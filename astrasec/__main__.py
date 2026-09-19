"""Command line entry point.

    python -m astrasec check "Ignore all previous instructions ..."   screen one prompt and print the five-step trace
    python -m astrasec redteam                                       run the independent red-team evaluation, write reports/
    python -m astrasec serve [--port 8000]                           start the API and dashboard
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime


from .config import ROOT


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def cmd_check(args: argparse.Namespace) -> int:
    from .pipeline import AstraSec
    r = AstraSec(db_path=":memory:").compare(args.prompt)
    d, s = r["protected"]["decision"], r["protected"]["steps"]
    print(f"Prompt: {args.prompt}\n")
    print(f"1 Behaviour     anomaly {_pct(s['step1_behavior']['anomaly_score'])}  ({s['step1_behavior']['summary']})")
    print(f"2 Health/risk   {s['step2_health']['risk_level']} risk, health score {s['step2_health']['health_score']}")
    t = s["step3_threat"]
    print(f"3 Threat        {t['label_title']}  p={_pct(t['probability'])}  severity={t['severity']}")
    print(f"4 Defence       {s['step4_defense']['action']}  ({s['step4_defense']['reason']})")
    print(f"5 Memory        {'new case stored' if s['step5_memory']['new_case'] else 'recorded' if s['step5_memory']['stored'] else 'nothing stored'}")
    print("\nWithout AstraSec:", r["unprotected"]["response"][:160].replace("\n", " "))
    print("With AstraSec   :", (r["protected"]["response"] or d["message"])[:160].replace("\n", " "))
    return 0


def cmd_redteam(args: argparse.Namespace) -> int:
    from .pipeline import AstraSec
    from .redteam import run_redteam
    res = run_redteam(AstraSec(db_path=":memory:"))
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / "redteam_latest.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    lines = [f"# Red-team report", f"", f"Generated {datetime.now():%Y-%m-%d %H:%M}. {res['note']}", ""]
    lines += ["| Phase | Detection | Caught at input | Right type | Harmless flagged | Attack success without / with AstraSec |", "|---|---|---|---|---|---|"]
    for name, key in (("First contact", "cold_start"), ("Fresh set", "fresh_holdout"), ("After analyst feedback", "after_feedback")):
        p = res[key]
        lines.append(f"| {name} | {_pct(p['detection_rate'])} | {_pct(p['input_detection_rate'])} | {_pct(p['type_accuracy'])} | "
                     f"{_pct(p['false_positive_rate'])} | {_pct(p['asr_unprotected'])} / {_pct(p['asr_protected'])} |")
    c = res["cold_start"]
    lines += ["", "## Attacks that got past the input check (first contact)", ""] + [f"- ({m['truth']}) {m['prompt']}" for m in c["missed"]]
    lines += ["", "## Harmless prompts that were flagged", ""] + ([f"- {m['prompt']} (called {m['pred']}, {m['action']})" for m in c["false_positives"]] or ["- none"])
    (out / "redteam_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nWritten to {out}/redteam_latest.json and redteam_report.md")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    uvicorn.run("astrasec.api.app:app", host=args.host, port=args.port)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="astrasec", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="screen one prompt"); c.add_argument("prompt"); c.set_defaults(fn=cmd_check)
    r = sub.add_parser("redteam", help="run the red-team evaluation"); r.set_defaults(fn=cmd_redteam)
    s = sub.add_parser("serve", help="start API and dashboard"); s.add_argument("--host", default="127.0.0.1"); s.add_argument("--port", type=int, default=8000); s.set_defaults(fn=cmd_serve)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
