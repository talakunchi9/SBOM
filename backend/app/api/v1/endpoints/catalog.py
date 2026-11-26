"""Catalog endpoints for projects and application modules."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.common import catalog_error_response, envelope, error_response, org_from_request, rid_from_request
from app.catalog import CatalogError

router = APIRouter(tags=["catalog"])


@router.get("/api/v1/catalog/projects")
def catalog_projects(request: Request, q: str = "", limit: int = 50, cursor: str = ""):
    """Searchable project names for dependent dropdowns. IDs are catalog UUIDs."""
    catalog = request.app.state.catalog
    rid = rid_from_request(request)
    try:
        page = catalog.list_projects(org_from_request(request), q=q, limit=limit, cursor=cursor or None)
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    return envelope(page, rid)


@router.post("/api/v1/catalog/projects")
async def create_catalog_project(request: Request):
    rid = rid_from_request(request)
    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", "malformed JSON body", rid, 400)
    if not isinstance(body, dict):
        return error_response("INVALID_INPUT", "project name is required", rid, 400)
    names = body.get("applications") or body.get("application_names") or []
    if isinstance(names, str):
        names = [names]
    app_names = []
    for item in names:
        if isinstance(item, dict):
            app_names.append(str(item.get("name") or ""))
        else:
            app_names.append(str(item or ""))
    catalog = request.app.state.catalog
    try:
        created = catalog.create_project(org_from_request(request), str(body.get("name") or ""), app_names)
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    return envelope(created, rid, 201)


@router.get("/api/v1/catalog/projects/{project_id}/applications-services")
def catalog_applications(project_id: str, request: Request, q: str = "", limit: int = 50, cursor: str = ""):
    """Applications/Services that belong to the selected project."""
    catalog = request.app.state.catalog
    rid = rid_from_request(request)
    try:
        page = catalog.list_applications(org_from_request(request), project_id, q=q, limit=limit, cursor=cursor or None)
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    return envelope(page, rid)


@router.post("/api/v1/catalog/projects/{project_id}/applications-services")
async def create_catalog_application(project_id: str, request: Request):
    rid = rid_from_request(request)
    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", "malformed JSON body", rid, 400)
    if not isinstance(body, dict):
        return error_response("INVALID_INPUT", "application/service name is required", rid, 400)
    catalog = request.app.state.catalog
    try:
        created = catalog.ensure_application(org_from_request(request), project_id, str(body.get("name") or ""))
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    return envelope(created, rid, 201)
