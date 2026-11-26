"""Health and liveness probe endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.common import envelope, error_response, rid_from_request
from app.core.db import ensure_alive
from app.core.metrics import METRICS
from app.export.formats import EXPORTERS

router = APIRouter(tags=["health"])


@router.get("/health/live")
def live(request: Request):
    return envelope({"status": "live"}, rid_from_request(request))


@router.get("/health/ready")
def ready(request: Request):
    db = request.app.state.db
    cfg = request.app.state.cfg
    db_ok = ensure_alive(db)
    if not db_ok:
        return error_response("NOT_READY", "database unavailable", rid_from_request(request), 503)
    return envelope(
        {
            "status": "ready",
            "database": cfg.dialect,
            "database_ok": True,
            "metrics": METRICS.snapshot(),
            "scanner": {"name": cfg.scanner_name, "version": cfg.scanner_version},
            "exporters": list(EXPORTERS),
        },
        rid_from_request(request),
    )


@router.get("/metrics.json")
def metrics(request: Request):
    return envelope(METRICS.snapshot(), rid_from_request(request))
