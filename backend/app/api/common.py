"""Common response envelope and request extraction helpers for API endpoints."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from app.catalog import CatalogError
from app.repositories.store import BomRepo, JobQueue, ScanRepo


def envelope(data: Any, request_id: str, status: int = 200) -> JSONResponse:
    body: dict[str, Any] = {"success": True, "request_id": request_id}
    if data is not None:
        body["data"] = data
    return JSONResponse(body, status_code=status)


def error_response(code: str, message: str, request_id: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"success": False, "error": {"code": code, "message": message}, "request_id": request_id},
        status_code=status,
    )


def org_from_request(request: Request) -> str:
    return (request.headers.get("x-organization-id") or "default").strip() or "default"


def rid_from_request(request: Request) -> str:
    return getattr(request.state, "request_id", "")


def catalog_error_response(exc: CatalogError, request_id: str) -> JSONResponse:
    return error_response(exc.code, exc.message, request_id, exc.status)


def with_sources(queue: JobQueue, rows: list[dict]) -> list[dict]:
    labels = queue.source_labels([row["id"] for row in rows])
    decorated = []
    for row in rows:
        item = dict(row)
        item.update(labels.get(row["id"]) or {})
        decorated.append(item)
    return decorated


def owned_scan(scans: ScanRepo, scan_id: str, org: str) -> dict | None:
    scan = scans.get_scan(scan_id)
    if scan is None or scan["organization_id"] != org:
        return None
    return scan


def snap_for_scan(scans: ScanRepo, boms: BomRepo, scan_id: str, org: str, request_id: str) -> tuple[dict | None, JSONResponse | None]:
    scan = owned_scan(scans, scan_id, org)
    if scan is None or not scan.get("snapshot_id"):
        return None, error_response("SCAN_NOT_FOUND", "not found", request_id, 404)
    snap = boms.get_snapshot(scan["snapshot_id"])
    if snap is None:
        return None, error_response("BOM_NOT_FOUND", "not found", request_id, 404)
    return snap, None


def valid_signature(header: str, body: bytes, secret: bytes) -> bool:
    if not secret or not header.startswith("sha256="):
        return False
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header, "sha256=" + digest)
