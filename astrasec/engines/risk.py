"""MODULE 2 - AI Health & Risk Analyzer.

Two jobs:

1. **Per-request risk** - answers the three questions from the design document for every prompt: is it sensitive,
   could it expose confidential information, does it violate policy?  -> a 0..1 risk score and a level.
2. **AI Health Score** - a 0..100 posture score for the whole AI application, a weighted combination of four
   component risks:

       health = 100 * (1 - (w_p*R_prompt + w_a*R_api + w_c*R_config + w_d*R_deps))       weights: .35 / .20 / .25 / .20

   * R_prompt - recent traffic: severity-weighted attack rate, plus defences that failed.
   * R_api    - abusive cadence, extraction probing, quarantined clients, missing authentication / TLS.
   * R_config - static audit of the AI application's configuration against 16 hardening rules.
   * R_deps   - installed/pinned packages checked against an advisory snapshot (and, optionally, live OSV.dev).

   Every finding lands in a prioritised risk register with a concrete fix.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from ..config import DATA_DIR, ROOT, SETTINGS
from ..features import SENSITIVE_RE, Deobfuscation

SEV_WEIGHT = {"critical": 0.50, "high": 0.30, "medium": 0.15, "low": 0.05}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ------------------------------------------------------------------------------------------------ configuration audit
@dataclass
class AppConfig:
    """Security-relevant configuration of the protected AI application (editable from the dashboard)."""
    name: str = "AcmeShop Assistant"
    system_prompt_hardened: bool = True      # prompt tells the model to treat user text as data
    canary_token: bool = True                # canary planted in the system prompt to detect leaks
    secrets_in_prompt: bool = True           # API keys / codes pasted into the system prompt (bad)
    input_validation: bool = True
    output_filtering: bool = True
    pii_masking: bool = True
    rate_limiting: bool = True
    audit_logging: bool = True
    auth_required: bool = False
    tls_enabled: bool = False
    model_endpoint_public: bool = True
    tool_access: str = "read"                # none | read | write | admin
    human_approval_for_tools: bool = False
    max_input_chars: int = 8000
    temperature: float = 0.7
    model_supply_chain_verified: bool = False  # weights pulled from a verified source / hash pinned

    @staticmethod
    def from_dict(d: dict) -> "AppConfig":
        base = AppConfig()
        for k, v in (d or {}).items():
            if hasattr(base, k) and k != "name":
                setattr(base, k, type(getattr(base, k))(v) if not isinstance(getattr(base, k), str) else str(v))
            elif k == "name":
                base.name = str(v)
        return base


@dataclass(frozen=True)
class Rule:
    rid: str
    title: str
    severity: str
    check: object          # callable(AppConfig) -> bool  (True = passes)
    fix: str


RULES: list[Rule] = [
    Rule("CFG-01", "System prompt is not hardened against injection", "high", lambda c: c.system_prompt_hardened,
         "Add explicit instructions that user text is data, never instructions; keep them at the top of the prompt."),
    Rule("CFG-02", "Secrets are embedded in the system prompt", "critical", lambda c: not c.secrets_in_prompt,
         "Move keys, discount codes and passwords into a secrets manager; the model should never be able to recite them."),
    Rule("CFG-03", "No canary token to detect prompt leakage", "medium", lambda c: c.canary_token,
         "Plant a random canary string in the system prompt and block any response that contains it."),
    Rule("CFG-04", "Input validation is disabled", "high", lambda c: c.input_validation,
         "Validate length, encoding and structure of every prompt before it reaches the model."),
    Rule("CFG-05", "Output filtering is disabled", "high", lambda c: c.output_filtering,
         "Screen responses for secrets, PII, system-prompt overlap and numeric dumps before returning them."),
    Rule("CFG-06", "PII is not masked before it reaches the model", "medium", lambda c: c.pii_masking,
         "Mask e-mails, phone numbers and card numbers in prompts and logs."),
    Rule("CFG-07", "No rate limiting", "high", lambda c: c.rate_limiting,
         "Apply per-client token buckets; they also make model-extraction campaigns expensive."),
    Rule("CFG-08", "Audit logging is disabled", "medium", lambda c: c.audit_logging,
         "Log every prompt, decision and response hash so incidents can be reconstructed."),
    Rule("CFG-09", "Authentication is not required", "high", lambda c: c.auth_required,
         "Require an API key or OAuth token on every endpoint (set ASTRASEC_API_KEY)."),
    Rule("CFG-10", "Transport encryption (TLS) is off", "medium", lambda c: c.tls_enabled,
         "Terminate TLS at the gateway or reverse proxy."),
    Rule("CFG-11", "Model endpoint is publicly reachable", "medium", lambda c: not c.model_endpoint_public,
         "Expose only the AstraSec gateway; keep the raw model endpoint on a private network."),
    Rule("CFG-12", "Model has write/admin tool access", "critical", lambda c: c.tool_access in ("none", "read"),
         "Grant the least privilege the use-case needs; prefer read-only tools."),
    Rule("CFG-13", "Tool actions do not require human approval", "medium",
         lambda c: c.human_approval_for_tools or c.tool_access == "none",
         "Require confirmation for any tool call that changes state (refunds, e-mails, deletions)."),
    Rule("CFG-14", "Maximum input size is too large", "low", lambda c: 0 < c.max_input_chars <= 16000,
         "Cap prompts (e.g. 8,000 characters) to limit flooding and context-stuffing attacks."),
    Rule("CFG-15", "Sampling temperature is very high", "low", lambda c: c.temperature <= 1.0,
         "High temperature makes safety behaviour less predictable; keep it at or below 1.0."),
    Rule("CFG-16", "Model artefacts are not verified", "medium", lambda c: c.model_supply_chain_verified,
         "Pin checkpoints by hash and load only from trusted registries (avoids pickle/backdoor supply-chain risk)."),
]


def audit_config(cfg: AppConfig) -> dict:
    findings, total_w, failed_w = [], 0.0, 0.0
    for r in RULES:
        w = SEV_WEIGHT[r.severity]
        total_w += w
        ok = bool(r.check(cfg))
        if not ok:
            failed_w += w
            findings.append({"id": r.rid, "title": r.title, "severity": r.severity, "fix": r.fix, "area": "configuration"})
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return {"risk": round(failed_w / total_w, 4), "passed": len(RULES) - len(findings), "total": len(RULES), "findings": findings}


# ------------------------------------------------------------------------------------------------ dependency scan
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][0-9A-Za-z.\-+]*)?")


def _vtuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("+")[0])[:4]) or (0,)


def _load_advisories() -> list[dict]:
    p = DATA_DIR / "advisories.json"
    return json.loads(p.read_text(encoding="utf-8"))["advisories"] if p.exists() else []


def parse_requirements(text: str) -> list[dict]:
    pkgs = []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_RE.match(line)
        if m:
            pkgs.append({"name": m.group(1).lower().replace("_", "-"), "op": m.group(2) or "", "version": m.group(3) or ""})
    return pkgs


def scan_dependencies(requirements: str | list[dict]) -> dict:
    pkgs = parse_requirements(requirements) if isinstance(requirements, str) else requirements
    adv = _load_advisories()
    findings, unpinned = [], []
    for p in pkgs:
        if p["op"] not in ("==", "~=") and p["version"] == "":
            unpinned.append(p["name"])
        for a in adv:
            if a["package"] != p["name"]:
                continue
            if p["version"] and p["op"] in ("==", "~=", "<=") and _vtuple(p["version"]) < _vtuple(a["affected_below"]):
                findings.append({"id": a["id"], "title": f"{p['name']} {p['version']}: {a['issue']}", "severity": a["severity"],
                                 "fix": a["fix"], "area": "dependencies", "package": p["name"]})
            elif p["op"] in (">=", ">") and p["version"] and _vtuple(p["version"]) < _vtuple(a["affected_below"]):
                findings.append({"id": a["id"], "title": f"{p['name']}>={p['version']} still allows vulnerable versions: {a['issue']}",
                                 "severity": "low", "fix": f"Raise the lower bound to {a['affected_below']} or newer.", "area": "dependencies",
                                 "package": p["name"]})
    risk = min(1.0, sum(SEV_WEIGHT[f["severity"]] for f in findings) + 0.02 * len(unpinned))
    if unpinned:
        findings.append({"id": "DEP-PIN", "title": f"{len(unpinned)} unpinned dependencies ({', '.join(unpinned[:5])}{'...' if len(unpinned) > 5 else ''})",
                         "severity": "low", "fix": "Pin exact versions (or use a lock file) so builds are reproducible and auditable.",
                         "area": "dependencies"})
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return {"risk": round(risk, 4), "packages": len(pkgs), "findings": findings, "source": "bundled advisory snapshot"}


def osv_lookup(pkgs: list[dict], timeout: float = 6.0) -> list[dict]:
    """Optional live check against https://api.osv.dev (needs network).  Returns [] on any failure."""
    try:
        import requests
        queries = [{"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]} for p in pkgs if p["version"]]
        r = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": queries}, timeout=timeout)
        out = []
        for p, res in zip([p for p in pkgs if p["version"]], r.json().get("results", [])):
            for v in res.get("vulns", []):
                out.append({"package": p["name"], "version": p["version"], "id": v.get("id")})
        return out
    except Exception:
        return []


# ------------------------------------------------------------------------------------------------ analyzer
def level_for_risk(r: float) -> str:
    return "high" if r >= 0.70 else "medium" if r >= 0.40 else "low"


def level_for_health(h: float) -> str:
    return "healthy" if h >= 85 else "fair" if h >= 70 else "at risk" if h >= 50 else "critical"


class RiskAnalyzer:
    def __init__(self, store, requirements_path: Path | None = None) -> None:
        self.store = store
        self.req_path = requirements_path or (ROOT / "requirements.txt")
        stored = store.kv_get("app_config")
        self.config = AppConfig.from_dict(stored) if stored else AppConfig()
        self._deps_cache: dict | None = None

    # --- configuration / dependency management -------------------------------------------------
    def set_config(self, cfg: dict) -> AppConfig:
        self.config = AppConfig.from_dict({**asdict(self.config), **cfg})
        self.store.kv_set("app_config", asdict(self.config))
        self.store.log_adaptation("config", "Application configuration updated", {k: v for k, v in cfg.items()})
        return self.config

    def dependencies(self, refresh: bool = False, text: str | None = None) -> dict:
        if text is not None:
            return scan_dependencies(text)
        if self._deps_cache is None or refresh:
            txt = self.req_path.read_text(encoding="utf-8") if self.req_path.exists() else ""
            self._deps_cache = scan_dependencies(txt)
        return self._deps_cache

    # --- per-request risk ---------------------------------------------------------------------
    def assess_request(self, deob: Deobfuscation, threat: dict, anomaly: float, strikes: int = 0) -> dict:
        view = deob.text
        sensitive = bool(SENSITIVE_RE.search(view))
        label = threat["label"]
        violates = bool(threat["flagged"])
        exposes = sensitive and label in ("prompt_injection", "model_extraction", "adversarial") and violates
        factors = []
        risk = 0.0
        if violates:
            risk += threat["severity_score"]
            factors.append(f"classified as {label.replace('_', ' ')} ({threat['severity']} severity)")
        if sensitive:
            risk += 0.15 if violates else 0.05
            factors.append("touches sensitive assets (prompts, secrets, credentials)")
        if exposes:
            risk += 0.10
            factors.append("could expose confidential information")
        if threat["obfuscation"]:
            risk += 0.10
            factors.append("obfuscation used: " + ", ".join(threat["obfuscation"]))
        if anomaly >= SETTINGS.thresholds.anomaly_flag:
            risk += 0.10 * anomaly
            factors.append("behaviour deviates from the learned baseline")
        if strikes:
            risk += min(0.15, 0.05 * strikes)
            factors.append(f"client has {strikes} recent strike(s)")
        if not violates:
            risk = min(risk, 0.35)
        risk = round(min(1.0, risk), 3)
        return {"risk_score": risk, "risk_level": level_for_risk(risk) if violates or risk > 0.2 else "low",
                "sensitive_prompt": sensitive, "could_expose_confidential": exposes, "violates_policy": violates, "factors": factors}

    # --- application posture --------------------------------------------------------------------
    def posture(self, quarantined: int = 0) -> dict:
        w = SETTINGS.health
        now = time.time()
        rows = self.store.query("SELECT flagged, severity_score, defense_success, action, label, anomaly FROM events "
                                "WHERE ts>=? ORDER BY id DESC LIMIT 300", (now - 24 * 3600,))
        n = len(rows)
        findings: list[dict] = []
        if n:
            attacks = [r for r in rows if r["flagged"]]
            sev_rate = sum(r["severity_score"] or 0 for r in attacks) / n
            fails = sum(1 for r in attacks if r["defense_success"] == 0)
            # attacks that were contained are pressure, attacks that got through are damage: weight them 0.5 vs 1.0
            pressure = sum((r["severity_score"] or 0) * (1.0 if r["defense_success"] == 0 else 0.5) for r in attacks) / n
            r_prompt = min(1.0, 1.2 * pressure + 0.4 * fails / n)
            if attacks and sev_rate >= 0.25:
                findings.append({"id": "TRF-01", "title": f"{len(attacks)} of the last {n} requests were attacks", "severity": "high" if sev_rate > 0.4 else "medium",
                                 "fix": "Review the Traffic view; consider tightening the flag threshold and quarantining repeat offenders.", "area": "prompts"})
            if fails:
                findings.append({"id": "TRF-02", "title": f"{fails} defence action(s) let hostile content reach the model", "severity": "high",
                                 "fix": "Self-healing will escalate the policy; inspect the Immune memory page for the affected attack types.", "area": "prompts"})
            ext = sum(1 for r in rows if r["label"] == "model_extraction") / n
        else:
            r_prompt, ext = 0.0, 0.0
        cfg = self.config
        api_findings = []
        r_api = 0.0
        if not cfg.auth_required:
            r_api += 0.30
        if not cfg.tls_enabled:
            r_api += 0.15
        if not cfg.rate_limiting:
            r_api += 0.30
        r_api += min(0.3, ext * 1.5) + min(0.25, 0.08 * quarantined)
        if ext > 0.05:
            api_findings.append({"id": "API-01", "title": f"Model-extraction probing is {ext:.0%} of recent traffic", "severity": "medium",
                                 "fix": "Keep per-client token buckets tight and consider returning coarser outputs.", "area": "api"})
        if quarantined:
            api_findings.append({"id": "API-02", "title": f"{quarantined} client(s) currently quarantined", "severity": "medium",
                                 "fix": "Review their traffic; quarantine expires automatically.", "area": "api"})
        r_api = min(1.0, r_api)
        c = audit_config(cfg)
        d = self.dependencies()
        health = 100.0 * (1.0 - (w.prompt * r_prompt + w.api * r_api + w.config * c["risk"] + w.dependencies * d["risk"]))
        health = round(max(0.0, min(100.0, health)), 1)
        register = sorted(findings + api_findings + c["findings"] + d["findings"], key=lambda f: SEV_ORDER[f["severity"]])
        comps = {"prompts": r_prompt, "api": r_api, "config": c["risk"], "dependencies": d["risk"]}
        return {
            "health_score": health, "level": level_for_health(health), "window_requests": n,
            "components": {k: {"risk": round(v, 3), "health": round(100 * (1 - v), 1), "weight": getattr(w, {"prompts": "prompt"}.get(k, k))}
                           for k, v in comps.items()},
            "register": register, "config_audit": {"passed": c["passed"], "total": c["total"]},
            "dependency_scan": {"packages": d["packages"], "findings": len(d["findings"])},
        }
