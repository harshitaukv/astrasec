"""FastAPI service for AstraSec.

    uvicorn astrasec.api.app:app --port 8000        ->  dashboard at http://localhost:8000/   API docs at /docs

Set ASTRASEC_API_KEY to require an `X-API-Key` header on every /api route (except /api/health).
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..config import API_KEY, ATTACK_LABELS, MODELS_DIR, WEB_DIR
from ..engines.defense import ACTIONS
from ..engines.risk import scan_dependencies
from ..pipeline import AstraSec
from ..redteam import run_redteam
from ..simulate import run_simulation


class ProtectIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)
    client_id: str = Field("anon", max_length=80)
    app_id: str = Field("demo-shop", max_length=80)
    forward: bool = True


class CompareIn(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=20000)
    client_id: str = Field("compare", max_length=80)


class FeedbackIn(BaseModel):
    verdict: str = Field(..., pattern="^(false_positive|missed_attack|confirmed)$")
    attack_label: str | None = None


class PolicyIn(BaseModel):
    key: str
    action: str


class StatusIn(BaseModel):
    status: str = Field(..., pattern="^(active|retired|pending)$")


class RequirementsIn(BaseModel):
    requirements: str = Field(..., max_length=20000)


class SimIn(BaseModel):
    n: int = Field(240, ge=10, le=1500)
    hours: int = Field(24, ge=1, le=72)


def create_app(astra: AstraSec | None = None) -> FastAPI:
    holder: dict = {}

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        holder["astra"] = astra or AstraSec()
        yield
        holder["astra"].store.close()

    app = FastAPI(title="AstraSec", version=__version__, lifespan=lifespan,
                  description="Artificial Immune System for autonomous AI threat prediction, adaptive defence and self-healing.")

    def core() -> AstraSec:
        if "astra" not in holder:      # TestClient without lifespan
            holder["astra"] = astra or AstraSec()
        return holder["astra"]

    def auth(x_api_key: str | None = Header(default=None)) -> None:
        if API_KEY and not secrets.compare_digest(x_api_key or "", API_KEY):
            raise HTTPException(401, "invalid or missing X-API-Key")

    dep = [Depends(auth)]

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "auth": bool(API_KEY)}

    # ------------------------------------------------------------------ protection
    @app.post("/api/protect", dependencies=dep)
    def protect(body: ProtectIn) -> dict:
        return core().protect(body.prompt, body.client_id, body.app_id, body.forward)

    @app.post("/api/compare", dependencies=dep)
    def compare(body: CompareIn) -> dict:
        return core().compare(body.prompt, body.client_id)

    # ------------------------------------------------------------------ dashboards
    @app.get("/api/overview", dependencies=dep)
    def overview() -> dict:
        return core().overview()

    @app.get("/api/stats", dependencies=dep)
    def stats(hours: int = Query(24, ge=1, le=72)) -> dict:
        return core().stats(hours)

    @app.get("/api/events", dependencies=dep)
    def events(limit: int = Query(100, ge=1, le=500), label: str | None = None, flagged: bool | None = None) -> list[dict]:
        return core().store.recent_events(limit=limit, label=label, flagged=flagged)

    @app.get("/api/events/{event_id}", dependencies=dep)
    def event(event_id: int) -> dict:
        ev = core().store.get_event(event_id)
        if not ev:
            raise HTTPException(404, "event not found")
        return ev

    @app.post("/api/events/{event_id}/feedback", dependencies=dep)
    def feedback(event_id: int, body: FeedbackIn) -> dict:
        try:
            return core().healer.feedback(event_id, body.verdict, body.attack_label)
        except KeyError:
            raise HTTPException(404, "event not found")

    # ------------------------------------------------------------------ immune memory / self-healing
    @app.get("/api/memory", dependencies=dep)
    def memory(limit: int = Query(100, ge=1, le=500), label: str | None = None) -> dict:
        c = core()
        return {"stats": c.memory.stats(), "cases": c.memory.cases(limit, label)}

    @app.get("/api/signatures", dependencies=dep)
    def signatures() -> list[dict]:
        return core().healer.signatures()

    @app.post("/api/signatures/{sid}/status", dependencies=dep)
    def sig_status(sid: str, body: StatusIn) -> dict:
        if not core().healer.set_signature_status(sid, body.status):
            raise HTTPException(400, "bad status")
        return {"sid": sid, "status": body.status}

    @app.post("/api/signatures/propose", dependencies=dep)
    def propose() -> dict:
        return core().healer.propose_rules_with_llm()

    @app.get("/api/policy", dependencies=dep)
    def policy() -> dict:
        return {"policy": core().defense.policy, "actions": ACTIONS}

    @app.put("/api/policy", dependencies=dep)
    def set_policy(body: PolicyIn) -> dict:
        c = core()
        if body.action not in ACTIONS or ":" not in body.key or body.key.split(":")[0] not in ATTACK_LABELS:
            raise HTTPException(400, "key must look like 'jailbreak:high' and action must be one of " + ", ".join(ACTIONS))
        old = c.defense.policy.get(body.key)
        c.defense.set_policy(body.key, body.action)
        c.store.log_adaptation("policy", f"policy {body.key}: {old} -> {body.action} (manual)", {"key": body.key})
        return c.defense.policy

    @app.get("/api/adaptations", dependencies=dep)
    def adaptations(limit: int = Query(60, ge=1, le=300)) -> list[dict]:
        return core().store.adaptations(limit)

    @app.post("/api/retrain", dependencies=dep)
    def retrain() -> dict:
        return core().healer.retrain_async()

    @app.get("/api/retrain/status", dependencies=dep)
    def retrain_status() -> dict:
        return core().healer.retrain_state

    @app.post("/api/recommendations", dependencies=dep)
    def recommendations() -> dict:
        c = core()
        return c.healer.recommendations(c.recommendation_context())

    @app.post("/api/quarantine/release", dependencies=dep)
    def release(client: str = Query(..., max_length=80)) -> dict:
        core().defense.guard.release(client)
        return {"released": client}

    # ------------------------------------------------------------------ risk analyzer
    @app.get("/api/risk", dependencies=dep)
    def risk() -> dict:
        from dataclasses import asdict
        c = core()
        return {"posture": c.risk.posture(c.defense.guard.quarantined_count()), "config": asdict(c.risk.config)}

    @app.put("/api/risk/config", dependencies=dep)
    def risk_config(cfg: dict) -> dict:
        from dataclasses import asdict
        c = core()
        c.risk.set_config(cfg)
        return {"posture": c.risk.posture(c.defense.guard.quarantined_count()), "config": asdict(c.risk.config)}

    @app.post("/api/risk/dependencies", dependencies=dep)
    def risk_deps(body: RequirementsIn) -> dict:
        return scan_dependencies(body.requirements)

    # ------------------------------------------------------------------ evaluation & demo tooling
    @app.get("/api/model/metrics", dependencies=dep)
    def model_metrics() -> dict:
        p = MODELS_DIR / "metrics.json"
        if not p.exists():
            raise HTTPException(404, "models/metrics.json missing - run `python -m training.train_all`")
        return json.loads(p.read_text(encoding="utf-8"))

    @app.post("/api/redteam/run", dependencies=dep)
    def redteam_run() -> dict:
        c = core()
        res = run_redteam(c)
        c.store.kv_set("redteam_latest", res)
        return res

    @app.get("/api/redteam/latest", dependencies=dep)
    def redteam_latest() -> dict:
        res = core().store.kv_get("redteam_latest")
        if not res:
            raise HTTPException(404, "no red-team run yet")
        return res

    @app.post("/api/simulate", dependencies=dep)
    def simulate(body: SimIn) -> dict:
        return run_simulation(core(), n=body.n, hours=body.hours)

    @app.post("/api/admin/reset", dependencies=dep)
    def reset(confirm: bool = Query(False)) -> dict:
        if not confirm:
            raise HTTPException(400, "pass ?confirm=true")
        c = core()
        for t in ("events", "memory", "adaptations", "signatures", "policy", "kv"):
            c.store.execute(f"DELETE FROM {t}")
        c.defense.policy.clear()
        from ..engines.defense import DEFAULT_POLICY
        c.defense.policy.update(DEFAULT_POLICY)
        c.healer.load_learned_signatures()
        c.memory._dirty = True
        from ..config import SETTINGS
        SETTINGS.thresholds.flag = 0.50
        return {"reset": True}

    # ------------------------------------------------------------------ dashboard
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        def index() -> FileResponse:
            return FileResponse(WEB_DIR / "index.html")

    return app


app = create_app()
