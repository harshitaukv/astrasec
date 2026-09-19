"""End-to-end red-team evaluation.

Runs the hand-written attack / benign set (astrasec/data/redteam.py - never used in training) through an isolated
AstraSec sandbox and measures what matters to an application owner:

  * detection rate / false-positive rate / type accuracy of the whole pipeline
  * ATTACK SUCCESS RATE (ASR): how often an attack makes the demo chatbot leak secrets, follow a jailbreak, run a
    privileged tool or dump model internals - unprotected vs behind AstraSec
  * benign utility: share of legitimate requests still answered
  * immune-memory effect: after analyst feedback on the misses, replaying mutated variants of the attacks
"""
from __future__ import annotations

import statistics
import time

from .config import ATTACK_LABELS
from .data.holdout import FRESH
from .data.redteam import RED_TEAM
from .llm import is_unsafe_response


def _run(app, items: list[tuple[str, str]], tag: str) -> dict:
    rows = []
    for i, (text, truth) in enumerate(items):
        client = f"{tag}-{i}"                      # one client per prompt: measure the detector, not the rate limiter
        r = app.protect(text, client_id=client, forward=True)
        raw = app.chatbot.respond(text, None)
        d = r["decision"]
        rows.append({"prompt": text[:160], "truth": truth, "pred": d["label"], "flagged": d["flagged"], "action": d["action"],
                     "allowed": d["allowed"], "input_flagged": d["caught_by"] == "input", "output_filtered": bool(d["output_filtered"]), "unprotected_unsafe": bool(is_unsafe_response(raw)),
                     "protected_unsafe": bool(r["response"] and is_unsafe_response(r["response"])),
                     "latency_ms": r["latency_ms"], "event_id": r["event_id"]})
    return summarise(rows)


def summarise(rows: list[dict]) -> dict:
    att = [r for r in rows if r["truth"] != "safe"]
    ben = [r for r in rows if r["truth"] == "safe"]
    detected = [r for r in att if r["flagged"]]
    per_class = {}
    for lab in ATTACK_LABELS:
        rs = [r for r in att if r["truth"] == lab]
        if rs:
            per_class[lab] = {"n": len(rs), "detected": sum(r["flagged"] for r in rs), "type_correct": sum(r["pred"] == lab for r in rs),
                              "asr_unprotected": round(sum(r["unprotected_unsafe"] for r in rs) / len(rs), 3),
                              "asr_protected": round(sum(r["protected_unsafe"] for r in rs) / len(rs), 3)}
    lat = sorted(r["latency_ms"] for r in rows)
    return {
        "n_attacks": len(att), "n_benign": len(ben),
        "detection_rate": round(len(detected) / max(len(att), 1), 4),
        "input_detection_rate": round(sum(r["input_flagged"] for r in att) / max(len(att), 1), 4),
        "type_accuracy": round(sum(r["pred"] == r["truth"] for r in att) / max(len(att), 1), 4),
        "false_positive_rate": round(sum(r["input_flagged"] for r in ben) / max(len(ben), 1), 4),
        "benign_impacted_rate": round(sum((not r["allowed"]) or r["output_filtered"] for r in ben) / max(len(ben), 1), 4),
        "benign_served": round(sum(r["allowed"] and not r["output_filtered"] for r in ben) / max(len(ben), 1), 4),
        "asr_unprotected": round(sum(r["unprotected_unsafe"] for r in att) / max(len(att), 1), 4),
        "asr_protected": round(sum(r["protected_unsafe"] for r in att) / max(len(att), 1), 4),
        "per_class": per_class,
        "latency_ms": {"p50": round(statistics.median(lat), 1), "p95": round(lat[int(0.95 * (len(lat) - 1))], 1)},
        "missed": [{k: r[k] for k in ("prompt", "truth", "action", "event_id")} for r in att if not r["flagged"]],
        "false_positives": [{k: r[k] for k in ("prompt", "pred", "action")} for r in ben if r["input_flagged"]],
        "benign_output_filtered": [r["prompt"] for r in ben if r["output_filtered"]],
        "rows": rows,
    }


def run_redteam(app) -> dict:
    """`app` may be the live AstraSec; a sandbox copy is used so production memory and thresholds are untouched."""
    t0 = time.time()
    sb = app.sandbox()
    cold = _run(sb, RED_TEAM, "cold")
    # analyst marks each miss as a missed attack -> immune memory + signature learning
    for r in cold["rows"]:
        if r["truth"] != "safe" and not r["input_flagged"]:       # every input-layer miss, incl. those only the output filter caught
            try:
                sb.healer.feedback(r["event_id"], "missed_attack", r["truth"])
            except Exception:
                pass
    mutated = [(f"Hi! {t} Thanks.", y) for t, y in RED_TEAM if y != "safe"] + [(t, y) for t, y in RED_TEAM if y == "safe"]
    warm = _run(sb, mutated, "warm")
    fresh = _run(app.sandbox(), FRESH, "fresh")
    return {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - t0, 1), "chatbot": sb.chatbot.name,
            "fresh_holdout": {**fresh, "note": "70 prompts written after the first red-team run and never used for training or tuning."},
            "note": "Sandboxed run: production memory, thresholds and baseline are not modified. The attack set was written independently of the training templates.",
            "cold_start": cold, "after_feedback": {**warm, "note": "Same attacks with a greeting/thanks wrapper, after analyst feedback on the cold-start misses (tests immune-memory recall of mutated variants)."}}
