"""Bulk scan upload and management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, File, Form, Request, UploadFile

from app.api.common import envelope, error_response, org_from_request, rid_from_request
from app.sources.workspace import parse_bulk

router = APIRouter(tags=["bulk-scans"])


@router.post("/api/v1/scans/bulk")
async def bulk_upload(
    request: Request,
    file: UploadFile | None = File(default=None),
    project_name: str = Form(default=""),
):
    rid = rid_from_request(request)
    cfg = request.app.state.cfg
    if file is None or not file.filename:
        return error_response("INVALID_INPUT", "file field is required", rid, 400)
    lower = file.filename.lower()
    if not (lower.endswith(".csv") or lower.endswith(".xlsx") or lower.endswith(".xls")):
        return error_response("UNSUPPORTED_FILE", "expected .csv, .xlsx, or .xls", rid, 400)
    blob = await file.read()
    if len(blob) == 0:
        return error_response(
            "EMPTY_FILE",
            f"The spreadsheet file '{file.filename}' is empty (0 bytes). Empty files cannot be scanned.",
            rid,
            400,
        )
    if len(blob) > cfg.max_bulk_file_bytes:
        return error_response("INVALID_INPUT", "multipart parse failed", rid, 400)
    try:
        rows, errors = parse_bulk(file.filename, blob, cfg.max_bulk_file_bytes)
    except Exception as exc:
        msg = str(exc)
        code = "EMPTY_FILE" if "empty file" in msg.lower() else "INVALID_BULK_FILE"
        error_message = (
            f"The spreadsheet file '{file.filename}' contains no data rows or is empty. Empty files cannot be scanned."
            if "empty file" in msg.lower()
            else msg
        )
        return error_response(code, error_message, rid, 400)
    if len(rows) > cfg.max_bulk_rows:
        return error_response("TOO_MANY_ROWS", "file exceeds MAX_BULK_ROWS", rid, 400)

    bulk_service = request.app.state.bulk_service
    try:
        aggregate = bulk_service.submit_bulk(org_from_request(request), project_name, file.filename, rows, errors)
    except Exception as exc:
        return error_response("SUBMIT_FAILED", str(exc), rid, 500)
    return envelope(aggregate, rid, 202)


@router.get("/api/v1/bulk-scans/{bulk_id}")
def get_bulk(bulk_id: str, request: Request):
    rid = rid_from_request(request)
    bulk_service = request.app.state.bulk_service
    agg = bulk_service.get_bulk(bulk_id, org_from_request(request))
    if agg is None:
        return error_response("BULK_NOT_FOUND", "not found", rid, 404)
    return envelope(agg, rid)


@router.get("/api/v1/bulk-scans/{bulk_id}/results")
def bulk_results(bulk_id: str, request: Request):
    rid = rid_from_request(request)
    bulk_service = request.app.state.bulk_service
    agg = bulk_service.get_bulk(bulk_id, org_from_request(request))
    if agg is None:
        return error_response("BULK_NOT_FOUND", "not found", rid, 404)
    return envelope(agg["items"], rid)
