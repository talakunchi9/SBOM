"""Software inventory and package tracking endpoints."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Request

from app.api.common import catalog_error_response, envelope, error_response, org_from_request, rid_from_request
from app.catalog import CatalogError

router = APIRouter(tags=["inventory"])


@router.get("/api/v1/inventory/components")
def list_inventory(request: Request, limit: int = 200, cursor: str = ""):
    boms = request.app.state.boms
    rid = rid_from_request(request)
    try:
        page = boms.list_inventory_components(org_from_request(request), limit=limit, cursor=cursor or None)
    except ValueError as exc:
        return error_response("INVALID_INPUT", str(exc), rid, 400)
    return envelope(page, rid)


@router.post("/api/v1/inventory/components")
async def create_inventory(request: Request):
    rid = rid_from_request(request)
    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", "malformed JSON body", rid, 400)
    items = body.get("components") if isinstance(body, dict) else None
    if not isinstance(items, list) or not items:
        return error_response("INVALID_INPUT", "components are required", rid, 400)
    org = org_from_request(request)
    reason = str(body.get("reason") or "Manual addition").strip()
    scan_service = request.app.state.scan_service
    boms = request.app.state.boms
    triage_repo = request.app.state.triage_repo
    try:
        normalized = [scan_service.bind_inventory_item(org, item) for item in items]
        saved = boms.add_inventory_components(org, normalized)
        for item in (saved or []):
            triage_repo.record_audit_log(
                org=org,
                application_id=item.get("application_id") or "",
                module_id=item.get("module_id") or "",
                component_name=item.get("name") or "",
                component_version=item.get("version") or "",
                action="ADD",
                new_value=item,
                reason=reason,
                changed_by="admin",
            )
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    except ValueError as exc:
        return error_response("INVALID_INPUT", str(exc), rid, 400)
    return envelope(saved, rid, 201)


@router.delete("/api/v1/inventory/components/{component_id}")
def delete_inventory(component_id: str, request: Request, reason: str = ""):
    org = org_from_request(request)
    rid = rid_from_request(request)
    boms = request.app.state.boms
    triage_repo = request.app.state.triage_repo
    deleted_row = boms.delete_inventory_component(org, component_id)
    if not deleted_row:
        return error_response("NOT_FOUND", "Component not found", rid, 404)

    audit_reason = (reason or request.headers.get("x-reason") or "Manual removal").strip()
    triage_repo.record_audit_log(
        org=org,
        application_id=deleted_row.get("application_id") or "",
        module_id=deleted_row.get("module_id") or "",
        component_name=deleted_row.get("name") or "",
        component_version=deleted_row.get("version") or "",
        action="REMOVE",
        old_value=deleted_row,
        reason=audit_reason,
        changed_by="admin",
    )

    return envelope({"deleted": True, "id": component_id, "reason": audit_reason}, rid)


@router.get("/api/v1/inventory/audit-log")
def get_inventory_audit_log(request: Request, component_name: str = "", limit: int = 50):
    triage_repo = request.app.state.triage_repo
    items = triage_repo.list_audit_log(org_from_request(request), component_name=component_name, limit=limit)
    return envelope({"items": items, "total": len(items)}, rid_from_request(request))


@router.get("/api/v1/packages/{package_name}/history")
def get_package_history(package_name: str, request: Request):
    rid = rid_from_request(request)
    pkg_name = package_name.strip()
    if not pkg_name:
        return error_response("INVALID_INPUT", "Package name is required", rid, 400)
    inv_service = request.app.state.inv_service
    try:
        history = inv_service.get_package_history(org_from_request(request), pkg_name)
    except ValueError as exc:
        return error_response("INVALID_INPUT", str(exc), rid, 400)
    return envelope(history, rid)


@router.get("/api/v1/packages/occurrences")
def get_package_occurrences(request: Request, name: str = "", purl: str = ""):
    rid = rid_from_request(request)
    inv_service = request.app.state.inv_service
    try:
        res = inv_service.get_package_occurrences(org_from_request(request), name=name, purl=purl)
    except ValueError as exc:
        return error_response("INVALID_INPUT", str(exc), rid, 400)
    return envelope(res, rid)
