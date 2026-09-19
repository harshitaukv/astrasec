"""MODULE 5 - Self-Healing & Security Intelligence Engine (Artificial Immune Memory).

Biological analogy -> implementation
    antigen memory / secondary response  ->  ImmuneMemory: every attack (prompt, type, severity, defence used, did it work)
                                              is stored; a *similar* attack later is recognised instantly by char-n-gram
                                              TF-IDF cosine similarity, before the classifier is even consulted.
    clonal selection (new antibodies)    ->  SelfHealer.learn_signatures(): phrases that recur in attacks the signatures
                                              missed become new regex signatures, admitted only after a zero-false-positive
                                              check against benign traffic.
    immune tolerance                     ->  analyst feedback ("false alarm") retires bad signatures/cases and raises the
                                              detection threshold; "missed attack" lowers it and adds the case to memory.
    adaptive strengthening               ->  escalate_policy(): if a defence keeps failing for an attack type
                                              (sanitize lets hostile content through) the policy is escalated to `block`.
    vaccination                          ->  retrain(): the classifier is refit on the corpus + confirmed attacks +
                                              confirmed false alarms, and deployed ONLY if it does not regress on held-out
                                              template families.
    "brain" (advice)                     ->  recommendations(): Llama 3.1 (via Ollama) writes prioritised advice from the
                                              system's own statistics; a rule-based fallback keeps it working offline.
                                              LLM-proposed regex rules are validated and held for human approval.

Every adaptation is written to the `adaptations` audit table.
"""
from __future__ import annotations

import csv
import json
import re
import shutil
import threading
import time
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import f1_score

from ..config import ATTACK_LABELS, DATA_DIR, LABELS, MODELS_DIR, SETTINGS
from ..signatures import Signature
from .defense import ESCALATE
from .threat import ThreatPredictor, fit_bundle

STOP = set("the a an of and to in on for with is are be you your me my it this that as at by or i we do can".split())


# ==================================================================================================== immune memory
class ImmuneMemory:
    def __init__(self, store) -> None:
        self.store = store
        self._lock = threading.RLock()
        self._vec: TfidfVectorizer | None = None
        self._matrix = None
        self._ids: list[int] = []
        self._dirty = True

    def _rebuild(self) -> None:
        # cases created only because the OUTPUT filter fired are untrusted (the model may have misbehaved on a benign prompt):
        # they are stored for review but take part in recall / learning only after an analyst confirms them.
        rows = self.store.query("SELECT id, normalized FROM memory WHERE active=1 AND label!='safe' AND source!='output_filter'")
        if not rows:
            self._vec, self._matrix, self._ids = None, None, []
        else:
            self._vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, lowercase=True)
            self._matrix = self._vec.fit_transform([r["normalized"] for r in rows])
            self._ids = [r["id"] for r in rows]
        self._dirty = False

    def recall(self, normalized: str, min_sim: float = 0.0) -> dict | None:
        """Most similar remembered attack, or None."""
        with self._lock:
            if self._dirty:
                self._rebuild()
            if self._vec is None or not normalized.strip():
                return None
            q = self._vec.transform([normalized])
            if q.nnz == 0:
                return None
            sims = (self._matrix @ q.T).toarray().ravel()
            j = int(np.argmax(sims))
            if sims[j] < min_sim:
                return None
            case = self.store.one("SELECT id,label,severity,action,hits,successes,failures,last_success,prompt FROM memory WHERE id=?", (self._ids[j],))
            if not case:
                return None
            case["similarity"] = round(float(sims[j]), 4)
            return case

    def store_case(self, prompt: str, normalized: str, label: str, severity: str, confidence: float, action: str,
                   success: bool | None, sig_hits: int, source: str = "traffic", dedupe_sim: float = 0.95) -> tuple[int, bool]:
        """Insert an attack case (or reinforce a near-duplicate). Returns (memory_id, is_new)."""
        now = time.time()
        near = self.recall(normalized, min_sim=dedupe_sim)
        if near and near["label"] == label:
            self.store.execute("UPDATE memory SET hits=hits+1, last_seen=?, action=?, last_success=?, successes=successes+?, failures=failures+? WHERE id=?",
                               (now, action, None if success is None else int(success), int(success is True), int(success is False), near["id"]))
            return near["id"], False
        mid = self.store.execute(
            "INSERT INTO memory(ts,last_seen,prompt,normalized,label,severity,confidence,action,hits,successes,failures,last_success,sig_hits,source,active) "
            "VALUES(?,?,?,?,?,?,?,?,1,?,?,?,?,?,1)",
            (now, now, prompt[:2000], normalized[:2000], label, severity, confidence, action, int(success is True), int(success is False),
             None if success is None else int(success), sig_hits, source))
        with self._lock:
            self._dirty = True
        return mid, True

    def record_outcome(self, mem_id: int, success: bool | None, action: str) -> None:
        if success is None:
            return
        self.store.execute("UPDATE memory SET last_success=?, action=?, successes=successes+?, failures=failures+? WHERE id=?",
                           (int(success), action, int(success), int(not success), mem_id))

    def deactivate(self, mem_id: int) -> None:
        self.store.execute("UPDATE memory SET active=0 WHERE id=?", (mem_id,))
        with self._lock:
            self._dirty = True

    def cases(self, limit: int = 100, label: str | None = None) -> list[dict]:
        sql = "SELECT id,ts,last_seen,prompt,label,severity,confidence,action,hits,successes,failures,last_success,sig_hits,source,active FROM memory WHERE active=1"
        params: list = []
        if label:
            sql += " AND label=?"
            params.append(label)
        return self.store.query(sql + " ORDER BY last_seen DESC LIMIT ?", params + [limit])

    def stats(self) -> dict:
        s = self.store
        by = {r["label"]: r["n"] for r in s.query("SELECT label, COUNT(*) n FROM memory WHERE active=1 GROUP BY label")}
        return {"cases": int(s.scalar("SELECT COUNT(*) FROM memory WHERE active=1")),
                "total_recurrences": int(s.scalar("SELECT COALESCE(SUM(hits),0) FROM memory WHERE active=1")),
                "by_label": by,
                "defence_success_rate": round(float(s.scalar("SELECT 1.0*SUM(successes)/NULLIF(SUM(successes)+SUM(failures),0) FROM memory WHERE active=1", default=1.0)), 3)}


# ==================================================================================================== self healing
class SelfHealer:
    def __init__(self, store, memory: ImmuneMemory, sig_engine, defense, predictor: ThreatPredictor, llm_client=None,
                 benign_reference: list[str] | None = None) -> None:
        self.store, self.memory, self.sig, self.defense, self.predictor, self.llm = store, memory, sig_engine, defense, predictor, llm_client
        self._benign_blob = "\n".join(t.lower() for t in (benign_reference or []))
        self._retrain_lock = threading.Lock()
        self.retrain_state: dict = {"status": "idle"}
        self._reference_metrics: dict | None = None
        th = store.kv_get("flag_threshold")
        if th is not None:
            SETTINGS.thresholds.flag = float(th)
        self.load_learned_signatures()

    # ------------------------------------------------------------------ signatures
    def load_learned_signatures(self) -> int:
        rows = self.store.query("SELECT * FROM signatures WHERE status='active'")
        sigs = [Signature(r["sid"], r["label"], r["pattern"], float(r["weight"]), r["source"]) for r in rows]
        self.sig.set_learned(sigs)
        return len(sigs)

    def _benign_hits(self, rx: re.Pattern) -> int:
        return len(rx.findall(self._benign_blob)) if self._benign_blob else 0

    def _next_sid(self, prefix: str) -> str:
        n = int(self.store.scalar("SELECT COUNT(*) FROM signatures WHERE sid LIKE ?", (prefix + "-%",))) + 1
        return f"{prefix}-{n:04d}"

    def learn_signatures(self, min_support: int = 2, per_label: int = 3) -> list[dict]:
        rows = self.store.query("SELECT label, normalized FROM memory WHERE active=1 AND sig_hits=0 AND label!='safe' AND source!='output_filter'")
        by_label: dict[str, list[str]] = defaultdict(list)
        for r in rows:
            by_label[r["label"]].append(r["normalized"])
        existing = {r["pattern"] for r in self.store.query("SELECT pattern FROM signatures")}
        learned: list[dict] = []
        for label, texts in by_label.items():
            if len(texts) < min_support:
                continue
            df: Counter = Counter()
            for t in texts:
                toks = re.findall(r"[a-z0-9']+", t.lower())
                grams = set()
                for n in (3, 4, 5):
                    for i in range(len(toks) - n + 1):
                        g = tuple(toks[i:i + n])
                        if sum(w not in STOP for w in g) >= 2 and not all(w.isdigit() for w in g):
                            grams.add(g)
                df.update(grams)
            cands = sorted(((g, c) for g, c in df.items() if c >= min_support), key=lambda x: (-x[1], -len(x[0]), x[0]))
            chosen: list[str] = []
            for g, c in cands[:150]:
                phrase = " ".join(g)
                if any(phrase in ch or ch in phrase for ch in chosen):
                    continue
                pat = r"\b" + r"\W+".join(re.escape(w) for w in g) + r"\b"
                if pat in existing:
                    continue
                rx = re.compile(pat, re.I)
                if self._benign_hits(rx) > 0:          # false-positive guard
                    continue
                sid = self._next_sid("LN")
                self.store.execute("INSERT INTO signatures(sid,label,pattern,weight,source,status,created,note) VALUES(?,?,?,?,?,?,?,?)",
                                   (sid, label, pat, 0.80, "learned", "active", time.time(), f"seen in {c} attack cases, 0 benign hits"))
                chosen.append(phrase)
                existing.add(pat)
                learned.append({"sid": sid, "label": label, "phrase": phrase, "support": c})
                self.store.log_adaptation("signature_learned", f"Learned {sid} for {label}: \"{phrase}\"", {"support": c, "pattern": pat})
                if len(chosen) >= per_label:
                    break
        if learned:
            self.load_learned_signatures()
        return learned

    def propose_rules_with_llm(self, limit: int = 8) -> dict:
        """Ask Llama 3.1 for candidate regex rules; validate them; hold for human approval (never auto-activated)."""
        if not (self.llm and self.llm.available()):
            return {"proposed": 0, "note": "Ollama / Llama 3.1 is not reachable, so no LLM rules were proposed."}
        rows = self.store.query("SELECT id,label,normalized FROM memory WHERE active=1 AND sig_hits=0 AND label!='safe' AND source!='output_filter' ORDER BY last_seen DESC LIMIT ?", (limit,))
        if not rows:
            return {"proposed": 0, "note": "No unsignatured attacks in memory."}
        listing = "\n".join(f"- [{r['label']}] {r['normalized'][:200]}" for r in rows)
        out = self.llm.json("You write precise Python regular expressions that detect LLM prompt attacks. Return JSON only.",
                            "These attack prompts evaded the current signatures:\n" + listing +
                            '\nReturn {"rules":[{"label":"prompt_injection|jailbreak|adversarial|model_extraction","pattern":"<python regex>","rationale":"<why>"}]} '
                            "with at most 3 rules. Patterns must be case-insensitive-safe, specific, and must not match ordinary customer questions.")
        proposed = []
        for rule in (out or {}).get("rules", [])[:3] if isinstance(out, dict) else []:
            ok, why = self._validate_rule(rule, rows)
            if not ok:
                continue
            sid = self._next_sid("LLM")
            self.store.execute("INSERT INTO signatures(sid,label,pattern,weight,source,status,created,note) VALUES(?,?,?,?,?,?,?,?)",
                               (sid, rule["label"], rule["pattern"], 0.78, "llm", "pending", time.time(), str(rule.get("rationale", ""))[:300]))
            proposed.append(sid)
            self.store.log_adaptation("rule_proposed", f"Llama proposed {sid} ({rule['label']}); awaiting approval", {"pattern": rule["pattern"]})
        return {"proposed": len(proposed), "sids": proposed}

    def _validate_rule(self, rule: dict, rows: list[dict]) -> tuple[bool, str]:
        try:
            label, pat = rule["label"], rule["pattern"]
            if label not in ATTACK_LABELS or not isinstance(pat, str) or not (6 <= len(pat) <= 240):
                return False, "shape"
            if re.search(r"\((?:[^()]*[+*])\)[+*{]", pat):
                return False, "nested quantifier (ReDoS risk)"
            rx = re.compile(pat, re.I)
            t0 = time.perf_counter()
            rx.search("a" * 4000 + " " + "ab " * 1500)
            if time.perf_counter() - t0 > 0.05:
                return False, "slow"
            if not any(rx.search(r["normalized"]) for r in rows if r["label"] == label):
                return False, "matches no source attack"
            if self._benign_hits(rx) > 0:
                return False, "matches benign traffic"
            return True, "ok"
        except (re.error, KeyError, TypeError):
            return False, "invalid"

    def set_signature_status(self, sid: str, status: str) -> bool:
        if status not in ("active", "retired", "pending"):
            return False
        n = self.store.execute("UPDATE signatures SET status=? WHERE sid=?", (status, sid))
        self.store.log_adaptation("signature_status", f"{sid} -> {status}", {})
        self.load_learned_signatures()
        return True

    def signatures(self) -> list[dict]:
        return self.store.query("SELECT sid,label,pattern,weight,source,status,created,fp_reports,note FROM signatures ORDER BY created DESC")

    # ------------------------------------------------------------------ feedback & threshold adaptation
    def feedback(self, event_id: int, verdict: str, attack_label: str | None = None) -> dict:
        if verdict not in ("false_positive", "missed_attack", "confirmed"):
            raise ValueError("verdict must be false_positive | missed_attack | confirmed")
        ev = self.store.get_event(event_id)
        if not ev:
            raise KeyError("event not found")
        self.store.execute("UPDATE events SET feedback=? WHERE id=?", (verdict, event_id))
        result: dict = {"event_id": event_id, "verdict": verdict, "changes": []}
        if verdict == "false_positive":
            if ev["memory_id"]:
                self.memory.deactivate(ev["memory_id"])
                result["changes"].append("removed the case from immune memory")
            for h in ev["trace"].get("steps", {}).get("step3_threat", {}).get("signature_hits", []):
                if h.get("source") in ("learned", "llm"):
                    self.store.execute("UPDATE signatures SET fp_reports=fp_reports+1 WHERE sid=?", (h["id"],))
                    if self.store.scalar("SELECT fp_reports FROM signatures WHERE sid=?", (h["id"],)) >= 2:
                        self.set_signature_status(h["id"], "retired")
                        result["changes"].append(f"retired learned signature {h['id']} after repeated false alarms")
            self._bump("fp")
        elif verdict == "missed_attack":
            label = attack_label if attack_label in ATTACK_LABELS else (ev["trace"].get("steps", {}).get("step3_threat", {}).get("top_attack") or "prompt_injection")
            from ..features import deobfuscate
            norm = deobfuscate(ev["prompt"]).normalized
            if ev["memory_id"]:
                self.store.execute("UPDATE memory SET source='analyst', label=?, confidence=0.99, active=1 WHERE id=?", (label, ev["memory_id"]))
                self.memory._dirty = True
                mid = ev["memory_id"]
            else:
                mid, new = self.memory.store_case(ev["prompt"], norm, label, "high", 0.99, "block", None, 0, source="analyst")
            self.store.execute("UPDATE events SET memory_id=? WHERE id=?", (mid, event_id))
            result["changes"].append(f"added to immune memory as {label}")
            self._bump("fn")
            learned = self.learn_signatures()
            if learned:
                result["changes"].append(f"learned {len(learned)} new signature(s)")
        else:
            if ev["memory_id"]:
                self.store.execute("UPDATE memory SET source='analyst' WHERE id=?", (ev["memory_id"],))
                self.memory._dirty = True
                result["changes"].append("case promoted to trusted immune memory")
        adapt = self.adapt_thresholds()
        if adapt:
            result["changes"].append(adapt)
        return result

    def _bump(self, key: str) -> None:
        self.store.kv_set(f"fb_{key}", int(self.store.kv_get(f"fb_{key}", 0)) + 1)

    def adapt_thresholds(self) -> str | None:
        th = SETTINGS.thresholds
        fp, fn = int(self.store.kv_get("fb_fp", 0)), int(self.store.kv_get("fb_fn", 0))
        old = th.flag
        msg = None
        if fp >= 3 and fp > fn:
            th.flag = round(min(th.flag_max, th.flag + 0.03), 3)
            self.store.kv_set("fb_fp", 0)
            msg = f"detection threshold raised {old:.2f} -> {th.flag:.2f} after {fp} false alarms"
        elif fn >= 3 and fn >= fp:
            th.flag = round(max(th.flag_min, th.flag - 0.03), 3)
            self.store.kv_set("fb_fn", 0)
            msg = f"detection threshold lowered {old:.2f} -> {th.flag:.2f} after {fn} missed attacks"
        if msg and th.flag != old:
            self.store.kv_set("flag_threshold", th.flag)
            self.store.log_adaptation("threshold", msg, {"old": old, "new": th.flag})
            return msg
        return None

    # ------------------------------------------------------------------ policy escalation
    def escalate_policy(self, min_samples: int = 6, max_fail_rate: float = 0.30) -> list[dict]:
        cursors: dict = self.store.kv_get("escalation_cursor", {})
        rows = self.store.query("SELECT id,label,severity,defense_success FROM events WHERE flagged=1 AND defense_success IS NOT NULL "
                                "AND action IN ('sanitize','rate_limit') ORDER BY id DESC LIMIT 500")
        groups: dict[str, list[dict]] = defaultdict(list)
        for r in rows:
            key = f"{r['label']}:{r['severity']}"
            if r["id"] > cursors.get(key, 0):
                groups[key].append(r)
        changes = []
        for key, evs in groups.items():
            fails = sum(1 for e in evs if e["defense_success"] == 0)
            cur = self.defense.policy.get(key)
            if len(evs) >= min_samples and fails / len(evs) > max_fail_rate and cur in ESCALATE:
                new = ESCALATE[cur]
                self.defense.set_policy(key, new)
                cursors[key] = max(e["id"] for e in evs)
                msg = f"policy {key}: {cur} -> {new} ({fails}/{len(evs)} defences failed)"
                self.store.log_adaptation("policy", msg, {"key": key, "old": cur, "new": new, "failures": fails, "samples": len(evs)})
                changes.append({"key": key, "old": cur, "new": new, "failures": fails, "samples": len(evs)})
        if changes:
            self.store.kv_set("escalation_cursor", cursors)
        return changes

    # ------------------------------------------------------------------ retraining ("vaccination")
    def _load_dataset(self) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        path = DATA_DIR / "dataset.csv"
        train, test = [], []
        if not path.exists():
            return train, test
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                (test if row["split"] == "test" else train).append((row["text"], row["label"]))
        return train, test

    def _eval(self, bundle, test: list[tuple[str, str]]) -> dict:
        pred = ThreatPredictor(bundle, self.sig).predict_many([t for t, _ in test], flag=SETTINGS.thresholds.flag)
        y_true = [y for _, y in test]
        y_pred = [p["label"] for p in pred]
        safe = [i for i, y in enumerate(y_true) if y == "safe"]
        fpr = sum(1 for i in safe if y_pred[i] != "safe") / max(len(safe), 1)
        att = [i for i, y in enumerate(y_true) if y != "safe"]
        det = sum(1 for i in att if y_pred[i] != "safe") / max(len(att), 1)
        return {"macro_f1": round(float(f1_score(y_true, y_pred, labels=LABELS, average="macro", zero_division=0)), 4),
                "false_positive_rate": round(fpr, 4), "detection_rate": round(det, 4)}

    def _extra_training(self) -> tuple[list[str], list[str], list[float]]:
        texts, labels, weights = [], [], []
        seen = set()
        for r in self.store.query("SELECT prompt,label,source,confidence FROM memory WHERE active=1 AND label!='safe'"):
            if r["source"] == "output_filter":
                continue
            if r["source"] == "analyst" or (r["confidence"] or 0) >= 0.8:
                if r["prompt"] not in seen:
                    seen.add(r["prompt"])
                    texts.append(r["prompt"]); labels.append(r["label"]); weights.append(2.0)
        for r in self.store.query("SELECT prompt FROM events WHERE feedback='false_positive'"):
            if r["prompt"] not in seen:
                seen.add(r["prompt"])
                texts.append(r["prompt"]); labels.append("safe"); weights.append(3.0)
        return texts, labels, weights

    def retrain(self, tolerance: float = 0.01) -> dict:
        if not self._retrain_lock.acquire(blocking=False):
            return {"status": "busy"}
        try:
            self.retrain_state = {"status": "running", "started": time.time()}
            train, test = self._load_dataset()
            if not train:
                out = {"status": "skipped", "reason": "data/dataset.csv not found - run `python -m training.train_all` first"}
                self.retrain_state = out
                return out
            et, el, ew = self._extra_training()
            kind = self.predictor.bundle.kind
            if self._reference_metrics is None:
                ref = fit_bundle([t for t, _ in train], [y for _, y in train], kind=kind, rf_trees=80)
                self._reference_metrics = self._eval(ref, test)
            texts = [t for t, _ in train] + et
            labels = [y for _, y in train] + el
            weights = np.array([1.0] * len(train) + ew)
            cand = fit_bundle(texts, labels, kind=kind, rf_trees=80, sample_weight=weights)
            cand_m = self._eval(cand, test)
            ref_m = self._reference_metrics
            ok = cand_m["macro_f1"] >= ref_m["macro_f1"] - tolerance and cand_m["false_positive_rate"] <= ref_m["false_positive_rate"] + tolerance
            out = {"status": "deployed" if ok else "rejected", "extra_samples": len(et), "reference": ref_m, "candidate": cand_m,
                   "finished": time.time()}
            if ok:
                all_t = [t for t, _ in train] + [t for t, _ in test] + et
                all_y = [y for _, y in train] + [y for _, y in test] + el
                all_w = np.array([1.0] * (len(train) + len(test)) + ew)
                final = fit_bundle(all_t, all_y, kind=kind, rf_trees=80, sample_weight=all_w)
                path = MODELS_DIR / "threat_model.joblib"
                if path.exists():
                    shutil.copy(path, str(path) + ".prev")
                final.save(path)
                self.predictor.bundle = final
                self.store.kv_set("last_retrain_memory_cases", int(self.store.scalar("SELECT COUNT(*) FROM memory WHERE active=1")))
                self.store.log_adaptation("retrain", f"Classifier retrained with {len(et)} learned samples: macro-F1 {cand_m['macro_f1']} (reference {ref_m['macro_f1']}) - deployed", out)
            else:
                self.store.log_adaptation("retrain", f"Retrained candidate rejected (macro-F1 {cand_m['macro_f1']} vs reference {ref_m['macro_f1']})", out)
            self.retrain_state = out
            return out
        except Exception as exc:  # pragma: no cover
            self.retrain_state = {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
            return self.retrain_state
        finally:
            self._retrain_lock.release()

    def retrain_async(self) -> dict:
        if self.retrain_state.get("status") == "running":
            return {"status": "busy"}
        threading.Thread(target=self.retrain, daemon=True).start()
        time.sleep(0.05)
        return {"status": "started"}

    # ------------------------------------------------------------------ recommendations
    def rule_based_recommendations(self, ctx: dict) -> dict:
        recs = []
        for f in ctx["risk_register"][:3]:
            recs.append({"title": f["title"][:110], "priority": "high" if f["severity"] in ("critical", "high") else "medium",
                         "why": f"Found by the {f['area']} audit ({f['severity']}).", "action": f["fix"]})
        atk = ctx["attacks_24h"]
        if atk:
            top = max(atk, key=atk.get)
            recs.append({"title": f"Most frequent attack type: {top.replace('_', ' ')} ({atk[top]} in 24 h)", "priority": "medium",
                         "why": "Concentrated attack patterns can be blocked more cheaply at the edge.",
                         "action": f"Review the {top.replace('_', ' ')} cases in Immune memory and consider tightening its policy row."})
        if ctx["defence_failures_24h"]:
            recs.append({"title": f"{ctx['defence_failures_24h']} defence action(s) failed to contain an attack", "priority": "high",
                         "why": "The output filter had to catch content that the input defence should have stopped.",
                         "action": "Let policy escalation run or set the affected policy rows to `block`; then retrain."})
        if ctx["emerging_24h"]:
            recs.append({"title": f"{ctx['emerging_24h']} unusual prompts were allowed but flagged as emerging threats", "priority": "medium",
                         "why": "They deviate from the learned baseline but matched no known attack.",
                         "action": "Label them in the Traffic view - confirmed attacks feed signature learning and retraining."})
        if ctx["memory_growth_since_retrain"] >= 25:
            recs.append({"title": "Immune memory has grown - retrain the classifier", "priority": "low",
                         "why": f"{ctx['memory_growth_since_retrain']} new attack cases have been stored since the last retrain.",
                         "action": "Run Retrain in the Immune memory page; it is deployed only if held-out accuracy does not regress."})
        if not recs:
            recs.append({"title": "No action needed", "priority": "low", "why": "Posture is healthy and no attacks were observed.", "action": "Keep monitoring."})
        return {"source": "rule-based fallback (Llama 3.1 not reachable)", "summary": f"Health score {ctx['health_score']} ({ctx['health_level']}).",
                "recommendations": recs[:6]}

    def recommendations(self, ctx: dict) -> dict:
        base = self.rule_based_recommendations(ctx)
        if not (self.llm and self.llm.available()):
            return base
        out = self.llm.json(
            "You are a senior AI-security engineer advising the owner of an LLM application protected by an artificial immune system. "
            "Be specific, concise and practical. Return JSON only.",
            "System statistics:\n" + json.dumps(ctx, default=str)[:6000] +
            '\nReturn {"summary":"<2 sentences>","recommendations":[{"title":"","priority":"high|medium|low","why":"","action":""}]} with 3-5 items.')
        if isinstance(out, dict) and isinstance(out.get("recommendations"), list) and out["recommendations"]:
            recs = [r for r in out["recommendations"] if isinstance(r, dict) and r.get("title") and r.get("action")][:6]
            if recs:
                return {"source": f"{self.llm.model} via Ollama", "summary": str(out.get("summary", ""))[:400], "recommendations": recs}
        return base
