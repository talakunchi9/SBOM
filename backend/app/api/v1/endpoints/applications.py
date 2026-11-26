"""Applications and projects dashboard endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.common import envelope, error_response, org_from_request, rid_from_request
from app.core.db import finish
from app.projects.dashboard import list_projects
from app.repositories.store import utcnow

router = APIRouter(tags=["applications"])


@router.get("/api/v1/projects")
def projects_dashboard(request: Request):
    """Read-only Projects & Microservices view aggregated from scans."""
    q = (request.query_params.get("q") or "").strip()
    status = (request.query_params.get("status") or "").strip()
    scans = request.app.state.scans
    boms = request.app.state.boms
    data = list_projects(scans, boms, org_from_request(request), q=q, status=status)
    return envelope(data, rid_from_request(request))


@router.patch("/api/v1/applications/{target_name_or_id}/lifecycle-status")
async def update_app_lifecycle_status(target_name_or_id: str, request: Request):
    org = org_from_request(request)
    rid = rid_from_request(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    status = str(body.get("lifecycle_status") or body.get("status") or "").strip()
    if not status:
        return error_response("INVALID_INPUT", "lifecycle_status is required", rid, 400)
    s_lower = status.lower()
    if s_lower in ("decommission", "decommissioned", "inactive", "disabled"):
        norm_status = "Decommissioned"
    elif s_lower in ("active", "enabled"):
        norm_status = "Active"
    else:
        norm_status = "Decommissioned" if "decommission" in s_lower else "Active"

    db = request.app.state.db
    now = utcnow()
    with db.lock:
        db.execute(
            """UPDATE applications 
               SET lifecycle_status = ?, updated_at = ? 
               WHERE organization_id = ? AND (id = ? OR LOWER(name) = LOWER(?))""",
            (norm_status, now, org, target_name_or_id, target_name_or_id),
        )
        finish(db)
    return envelope({"target": target_name_or_id, "lifecycle_status": norm_status}, rid)
