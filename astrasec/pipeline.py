"""AstraSec orchestrator: one request travels through all five immune modules.

    prompt --> [1 Behaviour] --> [3 Threat prediction] --> [5 Immune-memory recall] --> fusion
           --> [2 Risk / health] --> [4 Adaptive defence] --> (protected LLM) --> output screening
           --> record --> [5 Self-healing: memory, signatures, policy, baseline]

The numbering follows the project's module list; the *execution* order differs because risk needs the threat verdict.
"""
from __future__ import annotations

import copy
import json
import threading
import time
from collections import Counter, defaultdict, deque
from pathlib import Path

from .config import ATTACK_LABELS, DATA_DIR, DB_PATH, LABEL_TITLES, LABELS, MODELS_DIR, SETTINGS
from .db import Store
from .engines.behavior import BehaviorLearningEngine, PromptBaseline
from .engines.defense import DefenseEngine, find_pii
from .engines.memory import ImmuneMemory, SelfHealer
from .engines.risk import RiskAnalyzer, level_for_health
from .engines.threat import ThreatBundle, ThreatPredictor
from .features import deobfuscate
from .llm import OllamaClient, get_chatbot, is_unsafe_response
from .signatures import SignatureEngine


def holt_forecast(series: list[float], horizon: int = 3, alpha: float = 0.5, beta: float = 0.3) -> list[float]:
    """Holt's linear exponential smoothing - a light-weight early-warning forecast of attack volume."""
    if len(series) < 2:
        return [float(series[-1]) if series else 0.0] * horizon
    level, trend = series[0], series[1] - series[0]
    for x in series[1:]:
        prev = level
        level = alpha * x + (1 - alpha) * (level + trend)
        trend = beta * (level - prev) + (1 - beta) * trend
    return [max(0.0, level + (h + 1) * trend) for h in range(horizon)]


class AstraSec:
    def __init__(self, models_dir: Path | str = MODELS_DIR, db_path: str = DB_PATH, llm_client: OllamaClient | None = None,
                 chatbot=None, bundle: ThreatBundle | None = None, baseline: PromptBaseline | None = None,
                 benign_reference: list[str] | None = None) -> None:
        models_dir = Path(models_dir)
        self.models_dir = models_dir
        self.store = Store(db_path)
        self.bundle = bundle or ThreatBundle.load(models_dir / "threat_model.joblib")
        live = models_dir / "behavior_live.joblib"
        if baseline is None:
            baseline = PromptBaseline.load(live if live.exists() and db_path != ":memory:" else models_dir / "behavior_model.joblib")
        self.sig = SignatureEngine()
        self.predictor = ThreatPredictor(self.bundle, self.sig)
        self.behavior = BehaviorLearningEngine(baseline, SETTINGS.thresholds.anomaly_flag, SETTINGS.behavior_refit_every)
        self.risk = RiskAnalyzer(self.store)
        self.defense = DefenseEngine(self.store, self.predictor, SETTINGS.rate)
        self.memory = ImmuneMemory(self.store)
        if benign_reference is None:
            ref = DATA_DIR / "benign_reference.json"
            benign_reference = json.loads(ref.read_text(encoding="utf-8")) if ref.exists() else []
        self.benign_reference = benign_reference
        self.llm_client = llm_client or OllamaClient()
        self.healer = SelfHealer(self.store, self.memory, self.sig, self.defense, self.predictor, self.llm_client, benign_reference)
        self.chatbot = chatbot or get_chatbot(self.llm_client)
        self._suspicion: dict[str, deque] = defaultdict(deque)
        self._n = 0
        self._lock = threading.Lock()
        self.started = time.time()

    # ------------------------------------------------------------------------------------------------ sandbox
    def sandbox(self) -> "AstraSec":
        """Isolated copy (in-memory DB, copied baseline, default thresholds) for red-team runs and tests."""
        saved = SETTINGS.thresholds.flag
        sb = AstraSec(self.models_dir, ":memory:", llm_client=self.llm_client, chatbot=self.chatbot, bundle=self.bundle,
                      baseline=copy.deepcopy(self.behavior.baseline), benign_reference=self.benign_reference)
        SETTINGS.thresholds.flag = saved
        return sb

    # ------------------------------------------------------------------------------------------------ fusion
    def _fuse(self, threat: dict, beh: dict, mem: dict | None, client: str, now: float) -> dict:
        th = SETTINGS.thresholds
        top_attack = max(ATTACK_LABELS, key=lambda l: threat["scores"][l])
        label, flagged, conf = threat["label"], threat["flagged"], threat["attack_confidence"]
        reasons: list[str] = []
        emerging = False
        if flagged:
            reasons.append("classifier + signatures")
        sus = self._suspicion[client]
        while sus and now - sus[0] > 300:
            sus.popleft()
        if not flagged and mem and mem["similarity"] >= th.memory_similarity:
            label, flagged = mem["label"], True
            conf = max(conf, round(0.6 + 0.4 * mem["similarity"], 4))
            reasons.append(f"immune-memory recall (similarity {mem['similarity']:.2f} to case #{mem['id']})")
        if not flagged and beh["anomaly_score"] >= th.anomaly_flag and conf >= 0.30:
            label, flagged = top_attack, True
            conf = max(conf, th.flag)
            reasons.append("behavioural anomaly + partial attack evidence")
        if not flagged and len(sus) >= 2 and conf >= th.flag * 0.7:
            label, flagged = top_attack, True
            conf = max(conf, th.flag)
            reasons.append("session escalation (repeated suspicious requests)")
        if not flagged and beh["anomaly_score"] >= min(0.95, th.anomaly_flag + 0.15) and conf < 0.30:
            emerging = True
            reasons.append("unusual but unclassified: emerging-threat candidate")
        sev, sev_score = ThreatPredictor.severity(label if flagged else "safe", conf, len(threat["signature_hits"]))
        if flagged and label == "safe":     # defensive: should not happen
            label = top_attack
        return {"label": label if flagged else "safe", "flagged": flagged, "confidence": round(conf, 4), "severity": sev,
                "severity_score": sev_score, "reasons": reasons, "emerging": emerging, "top_attack": top_attack}

    # ------------------------------------------------------------------------------------------------ main entry
    def protect(self, prompt: str, client_id: str = "anon", app_id: str = "demo-shop", forward: bool = True,
                ts_override: float | None = None) -> dict:
        t0 = time.perf_counter()
        now = ts_override or time.time()
        if not prompt or not prompt.strip():
            raise ValueError("prompt must not be empty")
        cfg = self.risk.config
        truncated = len(prompt) > cfg.max_input_chars
        if truncated:
            prompt = prompt[:cfg.max_input_chars]
        th = SETTINGS.thresholds
        deob = deobfuscate(prompt)

        # --- Module 1: behaviour ------------------------------------------------------------------
        beh = self.behavior.analyze(prompt, client_id)
        feats = beh.pop("features")
        # --- Module 3: threat prediction ------------------------------------------------------------
        threat = self.predictor.predict(prompt, flag=th.flag)
        # --- Module 5 (read side): immune-memory recall -----------------------------------------------
        mem = self.memory.recall(deob.normalized)
        fused = self._fuse(threat, beh, mem, client_id, now)
        label, flagged = fused["label"], fused["flagged"]
        memory_hit = bool(mem and mem["similarity"] >= th.memory_similarity)
        # --- Module 2: request risk -------------------------------------------------------------------
        t_for_risk = {**threat, "label": label, "flagged": flagged, "severity": fused["severity"], "severity_score": fused["severity_score"]}
        risk = self.risk.assess_request(deob, t_for_risk, beh["anomaly_score"], self.defense.guard.strikes(client_id))
        # --- Module 4: defence --------------------------------------------------------------------------
        pii = find_pii(prompt)
        action, why = self.defense.decide(label, fused["severity"], flagged, pii, mem if memory_hit else None)
        outcome = self.defense.apply(prompt, deob, label, flagged, action, why, client_id, th.flag)

        response, rf = None, None
        if forward and outcome.forward_text is not None:
            raw = self.chatbot.respond(outcome.forward_text, outcome.system_reminder)
            rf = self.defense.filter_response(raw, self.chatbot.system_prompt, self.chatbot.protected)
            response = rf["text"]
            self.behavior.api.record_response(len(raw))
        elif outcome.blocked:
            response = None
        leak_caught = bool(rf and rf["blocked"])

        # --- outcome accounting -------------------------------------------------------------------------
        if flagged:
            if outcome.blocked:
                success: bool | None = True
            elif forward:
                success = not leak_caught
            else:
                success = bool(outcome.validation["ok"]) if outcome.validation else True
        else:
            success = None
        missed_by_input = (not flagged) and leak_caught
        if missed_by_input:
            label, flagged = fused["top_attack"], True
            fused.update(label=label, flagged=True, reasons=fused["reasons"] + ["caught only by the output filter (input detection missed it)"])
            sev, sev_score = ThreatPredictor.severity(label, max(fused["confidence"], 0.6), 0)
            fused.update(severity=sev, severity_score=sev_score)
            success = True

        # --- Module 5 (write side): remember & adapt --------------------------------------------------------
        mem_id, new_case, learned = None, False, []
        final_action = outcome.action
        if flagged:
            mem_id, new_case = self.memory.store_case(prompt, deob.normalized, label, fused["severity"], fused["confidence"], final_action,
                                                     success, len(threat["signature_hits"]), source="output_filter" if missed_by_input else "traffic")
            if memory_hit and mem and mem["id"] != mem_id:
                self.memory.record_outcome(mem["id"], success, final_action)
            if new_case:
                n = int(self.store.kv_get("new_cases_since_learn", 0)) + 1
                if n >= SETTINGS.signature_learn_every:
                    learned = self.healer.learn_signatures()
                    n = 0
                self.store.kv_set("new_cases_since_learn", n)
            self._suspicion[client_id].append(now)
        elif beh["suspicious"]:
            self._suspicion[client_id].append(now)
        refit = False
        if not flagged and not beh["suspicious"] and not outcome.blocked:
            refit = self.behavior.learn(feats, True)
            if refit and self.store.path != ":memory:":
                self.behavior.baseline.save(self.models_dir / "behavior_live.joblib")
            if refit:
                self.store.log_adaptation("baseline", f"Behavioural baseline refit on {self.behavior.baseline.trained_on} samples",
                                          {"refits": self.behavior.baseline.refits})

        latency = round((time.perf_counter() - t0) * 1000, 2)
        step3 = {"label": label, "label_title": LABEL_TITLES[label], "flagged": flagged, "probability": fused["confidence"],
                 "severity": fused["severity"], "severity_score": fused["severity_score"], "scores": threat["scores"],
                 "ml_scores": threat["ml_scores"], "signature_hits": threat["signature_hits"], "explanation": threat["explanation"],
                 "obfuscation": threat["obfuscation"], "fused_by": fused["reasons"], "top_attack": fused["top_attack"],
                 "model": threat["model"], "threshold": th.flag}
        step4 = {"requested_action": outcome.requested, "action": final_action, "reason": outcome.reason, "blocked": outcome.blocked,
                 "sanitized_prompt": outcome.sanitized, "removed": outcome.removed, "validation": outcome.validation,
                 "masked": outcome.masked, "notes": outcome.notes, "escalated": outcome.escalated, "quarantined": outcome.quarantined,
                 "retry_after": outcome.retry_after, "response_filter": rf and {k: rf[k] for k in ("blocked", "findings", "masked")},
                 "defense_success": success}
        step5 = {"recalled": (mem and {"id": mem["id"], "similarity": mem["similarity"], "label": mem["label"], "prior_action": mem["action"],
                                       "prior_success": mem["last_success"], "seen": mem["hits"], "prompt": mem["prompt"][:160]}),
                 "recall_used": memory_hit, "stored": bool(flagged), "new_case": new_case, "memory_id": mem_id, "learned_signatures": learned,
                 "baseline_refit": refit}
        step1 = {**beh, "summary": ("suspicious behaviour" if beh["suspicious"] else "matches learned baseline")}

        with self._lock:
            self._n += 1
            n = self._n
        event_id = self.store.add_event(
            ts=now, client=client_id, app=app_id, prompt=prompt[:2000], label=label, flagged=int(flagged), attack_conf=fused["confidence"],
            severity=fused["severity"], severity_score=fused["severity_score"], anomaly=beh["anomaly_score"], risk=risk["risk_score"],
            action=final_action, allowed=int(not outcome.blocked), defense_success=None if success is None else int(success),
            memory_id=mem_id, memory_sim=(mem["similarity"] if mem else None), emerging=int(fused["emerging"]), leak_caught=int(leak_caught),
            health=None, latency_ms=latency, feedback=None, trace="{}")
        posture = self.risk.posture(self.defense.guard.quarantined_count())
        step2 = {**risk, "health_score": posture["health_score"], "health_level": posture["level"],
                 "components": {k: v["health"] for k, v in posture["components"].items()}}
        result = {
            "event_id": event_id,
            "decision": {"allowed": not outcome.blocked, "action": final_action, "label": label, "label_title": LABEL_TITLES[label],
                         "severity": fused["severity"], "flagged": flagged, "emerging": fused["emerging"],
                         "message": outcome.message, "truncated": truncated,
                         "caught_by": "output_filter" if missed_by_input else ("input" if flagged else None), "output_filtered": leak_caught},
            "response": response,
            "steps": {"step1_behavior": step1, "step2_health": step2, "step3_threat": step3, "step4_defense": step4, "step5_memory": step5},
            "latency_ms": latency,
        }
        self.store.execute("UPDATE events SET health=?, latency_ms=?, trace=? WHERE id=?",
                           (posture["health_score"], latency, json.dumps({"steps": result["steps"], "response": (response or "")[:600]}, default=str), event_id))
        if n % 20 == 0:
            self.healer.escalate_policy()
        return result

    # ------------------------------------------------------------------------------------------------ comparison
    def compare(self, prompt: str, client_id: str = "compare") -> dict:
        """Protected vs unprotected: what the same prompt does to a bare model."""
        protected = self.protect(prompt, client_id=client_id, forward=True)
        raw = self.chatbot.respond(prompt, None)
        unsafe = is_unsafe_response(raw) or self.defense.response_filter.screen(raw, self.chatbot.system_prompt, self.chatbot.protected)["blocked"]
        p_resp = protected["response"]
        return {"protected": protected, "unprotected": {"response": raw, "unsafe": bool(unsafe)},
                "protected_unsafe": bool(p_resp and is_unsafe_response(p_resp))}

    # ------------------------------------------------------------------------------------------------ analytics
    def stats(self, hours: int = 24) -> dict:
        now = time.time()
        since = now - hours * 3600
        rows = self.store.query("SELECT ts,label,flagged,action,severity,defense_success,emerging,client FROM events WHERE ts>=?", (since,))
        n_b = hours
        total, attacks = [0] * n_b, [0] * n_b
        for r in rows:
            i = min(n_b - 1, int((r["ts"] - since) // 3600))
            total[i] += 1
            attacks[i] += int(bool(r["flagged"]))
        by_label = Counter(r["label"] for r in rows if r["flagged"])
        by_action = Counter(r["action"] for r in rows)
        by_sev = Counter(r["severity"] for r in rows if r["flagged"])
        fc = holt_forecast([float(a) for a in attacks[-12:]], 3)
        recent = sum(attacks[-3:]) / 3.0
        trend = "rising" if fc[0] > recent * 1.25 + 0.5 else "falling" if fc[0] < recent * 0.6 - 0.2 else "stable"
        watch: dict[str, int] = Counter(r["client"] for r in rows if r["flagged"] and now - r["ts"] <= 1800)
        life = self.store.one("SELECT COUNT(*) n, SUM(flagged) f, SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) b, SUM(emerging) e, "
                              "AVG(latency_ms) lat FROM events")
        return {
            "hours": hours, "bucket_start": [since + i * 3600 for i in range(n_b)], "total": total, "attacks": attacks,
            "by_label": {l: by_label.get(l, 0) for l in ATTACK_LABELS}, "by_action": dict(by_action), "by_severity": dict(by_sev),
            "forecast": {"next_hours": [round(x, 2) for x in fc], "trend": trend, "method": "Holt linear exponential smoothing over the last 12 h"},
            "watchlist": [{"client": c, "attacks_30min": k} for c, k in watch.most_common(5) if k >= 2],
            "lifetime": {"requests": int(life["n"] or 0), "attacks": int(life["f"] or 0), "blocked": int(life["b"] or 0),
                         "emerging": int(life["e"] or 0), "avg_latency_ms": round(float(life["lat"] or 0), 1)},
        }

    def overview(self) -> dict:
        posture = self.risk.posture(self.defense.guard.quarantined_count())
        return {"posture": posture, "stats": self.stats(), "memory": self.memory.stats(),
                "baseline": self.behavior.stats(), "signatures": {**self.sig.counts, "pending": int(self.store.scalar("SELECT COUNT(*) FROM signatures WHERE status='pending'"))},
                "thresholds": {"flag": SETTINGS.thresholds.flag, "flag_min": SETTINGS.thresholds.flag_min, "flag_max": SETTINGS.thresholds.flag_max,
                               "memory_similarity": SETTINGS.thresholds.memory_similarity, "anomaly_flag": SETTINGS.thresholds.anomaly_flag},
                "quarantined": self.defense.guard.quarantined_clients(), "policy": self.defense.policy,
                "chatbot": self.chatbot.name, "llm": {"backend": "ollama" if self.llm_client.available() else "offline", "model": self.llm_client.model},
                "uptime_s": round(time.time() - self.started)}

    def recommendation_context(self) -> dict:
        posture = self.risk.posture(self.defense.guard.quarantined_count())
        since = time.time() - 86400
        rows = self.store.query("SELECT label,flagged,defense_success,emerging FROM events WHERE ts>=?", (since,))
        atk = Counter(r["label"] for r in rows if r["flagged"])
        last = int(self.store.kv_get("last_retrain_memory_cases", 0))
        cases = int(self.store.scalar("SELECT COUNT(*) FROM memory WHERE active=1"))
        return {"health_score": posture["health_score"], "health_level": posture["level"],
                "components": {k: v["health"] for k, v in posture["components"].items()}, "risk_register": posture["register"][:8],
                "requests_24h": len(rows), "attacks_24h": dict(atk), "defence_failures_24h": sum(1 for r in rows if r["defense_success"] == 0),
                "emerging_24h": sum(r["emerging"] or 0 for r in rows), "memory_cases": cases, "memory_growth_since_retrain": cases - last,
                "learned_signatures": self.sig.counts["learned"], "thresholds": {"flag": SETTINGS.thresholds.flag},
                "policy_changes": [a["summary"] for a in self.store.adaptations(6) if a["kind"] in ("policy", "threshold", "signature_learned")]}
