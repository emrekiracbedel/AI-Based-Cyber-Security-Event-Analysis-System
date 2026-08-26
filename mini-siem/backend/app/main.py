"""
Mini-SIEM API: REST, WebSocket, ingest, Mongo-backed logs, Sigma + ML pipeline, LLM explain.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import (
    effective_llm_provider_for_request,
    llm_is_configured_for_request,
    resolve_llm_for_request,
    settings,
)
from app.dashboard_state import get_dashboard, simulation_loop
from app.db.mongo_store import get_mongo_status, list_recent_logs
from app.services.anomaly_detector import get_anomaly_detector
from app.services.llm_explain import explain_with_llm, template_explanation
from app.services.log_processor import LogSourceType
from app.services.sigma_engine import get_sigma_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_sigma_engine()
    get_anomaly_detector().load()
    dash = get_dashboard()
    sim_task: asyncio.Task | None = None
    if settings.enable_demo_simulation:
        sim_task = asyncio.create_task(simulation_loop())
    else:
        await asyncio.to_thread(dash.hydrate_from_mongo)
    yield
    if sim_task is not None:
        sim_task.cancel()
        try:
            await sim_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="Mini-SIEM", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5173",
        "http://localhost:5174",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health(request: Request) -> dict[str, Any]:
    mongo = get_mongo_status()
    sigma = get_sigma_engine()
    det = get_anomaly_detector()
    o_h = request.headers.get("X-MiniSiem-Llm-OpenAI")
    g_h = request.headers.get("X-MiniSiem-Llm-Gemini")
    eff = effective_llm_provider_for_request(o_h, g_h)
    return {
        "status": "ok",
        "mongo": mongo,
        "sigma_rules_loaded": len(sigma.rules),
        "ml_model_loaded": det.bundle is not None,
        "llm_configured": llm_is_configured_for_request(o_h, g_h),
        "llm_provider": eff,
        "gemini_model": settings.gemini_model if eff == "gemini" else None,
        "gemini_api_version": settings.gemini_api_version
        if eff == "gemini"
        else None,
        "demo_simulation": settings.enable_demo_simulation,
    }


@app.get("/api/snapshot")
def snapshot() -> dict[str, Any]:
    return get_dashboard().snapshot()


@app.get("/api/alerts/{alert_id}/explain")
async def explain_alert(alert_id: str, request: Request) -> dict[str, str]:
    alert = get_dashboard().get_alert_dict(alert_id)
    if not alert:
        return {
            "alert_id": alert_id,
            "explanation": "No alert found in the live buffer (it may have aged out).",
            "source": "none",
        }
    o_h = request.headers.get("X-MiniSiem-Llm-OpenAI")
    g_h = request.headers.get("X-MiniSiem-Llm-Gemini")
    result = await explain_with_llm(alert, openai_header=o_h, gemini_header=g_h)
    _, eff_key = resolve_llm_for_request(o_h, g_h)
    if result.text:
        return {
            "alert_id": alert_id,
            "explanation": result.text,
            "source": "llm",
        }

    if result.error == "no_api_key" or not eff_key:
        return {
            "alert_id": alert_id,
            "explanation": template_explanation(alert, show_key_setup_hint=True),
            "source": "template",
        }

    base = template_explanation(alert, show_key_setup_hint=False)
    err_line = result.error or "Unknown LLM error"
    return {
        "alert_id": alert_id,
        "explanation": (
            f"{base}\n\n---\n**LLM request failed** (API key is set but the model API did not return text). "
            f"**Detail:** {err_line}\n\n"
            "**Checklist:** Verify the key in **API keys**, or server env: "
            "`OPENAI_API_KEY` / `OPENAI_BASE_URL` / `LLM_MODEL`, or "
            "`GEMINI_API_KEY` / `LLM_PROVIDER=gemini` / `GEMINI_MODEL`. "
            "Check firewall/proxy for outbound HTTPS."
        ),
        "source": "llm_error",
    }


class IngestFlowBody(BaseModel):
    src_ip: str
    dst_ip: str
    weight: int = Field(default=1, ge=1, le=1_000_000)
    at_epoch_ms: int | None = None


@app.post("/api/ingest/flow")
def ingest_flow(body: IngestFlowBody) -> dict[str, str]:
    get_dashboard().ingest_flow(
        body.src_ip, body.dst_ip, at_epoch_ms=body.at_epoch_ms, weight=body.weight
    )
    return {"status": "accepted"}


class IngestLogBody(BaseModel):
    raw: str
    source_hint: str | None = None


@app.post("/api/ingest/log")
def ingest_log(body: IngestLogBody) -> dict[str, Any]:
    hint: LogSourceType | None = None
    if body.source_hint:
        try:
            hint = LogSourceType(body.source_hint)
        except ValueError as e:
            raise HTTPException(
                status_code=400,
                detail=f"invalid source_hint: {e}",
            ) from e
    normalized = get_dashboard().ingest_raw_log(body.raw, source_hint=hint)
    return {"status": "ok", "normalized": normalized}


@app.get("/api/logs/recent")
def logs_recent(limit: int = 50) -> dict[str, Any]:
    lim = max(1, min(limit, 500))
    return {"items": list_recent_logs(lim)}


@app.get("/api/rules")
def list_rules() -> dict[str, Any]:
    sigma = get_sigma_engine()
    return {
        "path": str(sigma.rules_path),
        "count": len(sigma.rules),
        "rules": [
            {"id": r.get("id"), "title": r.get("title"), "level": r.get("level")}
            for r in sigma.rules
        ],
    }


@app.get("/api/ml/status")
def ml_status() -> dict[str, Any]:
    det = get_anomaly_detector()
    return {
        "model_path": str(det.path),
        "loaded": det.bundle is not None,
    }


@app.post("/api/ml/reload")
def ml_reload() -> dict[str, Any]:
    ok = get_anomaly_detector().load()
    return {"loaded": ok}


@app.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket) -> None:
    await ws.accept()
    dash = get_dashboard()
    try:
        while True:
            payload = dash.snapshot()
            await ws.send_text(json.dumps(payload))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        return
