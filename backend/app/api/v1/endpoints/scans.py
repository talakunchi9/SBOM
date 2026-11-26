"""Security scans lifecycle and execution endpoints."""

from __future__ import annotations

import hashlib
from io import BytesIO
import logging
import uuid
from fastapi import APIRouter, File, Form, Request, UploadFile

from app.api.common import catalog_error_response, envelope, error_response, org_from_request, owned_scan, rid_from_request, with_sources
from app.catalog import CatalogError
from app.repositories.store import public_scan
from app.scans.orchestrator import CancelError, RescanError
from app.services.scan_service import safe_upload_name
from app.sources.workspace import is_supported_manifest, pack_folder, validate_repo_url

log = logging.getLogger("bom")
router = APIRouter(tags=["scans"])


@router.post("/api/v1/scans/preflight-check")
async def preflight_check(
    request: Request,
    application_name: str = Form(default=""),
    module_name: str = Form(default=""),
    project_name: str = Form(default=""),
    version: str = Form(default=""),
    file: UploadFile | None = File(default=None),
    files: list[UploadFile] | None = File(default=None),
    paths: list[str] | None = Form(default=None),
    repository_url: str = Form(default=""),
    branch: str = Form(default=""),
):
    org = org_from_request(request)
    rid = rid_from_request(request)
    scan_service = request.app.state.scan_service

    # Check if called with JSON
    content_type = request.headers.get("content-type") or ""
    if "application/json" in content_type:
        try:
            body = await request.json()
            application_name = body.get("application_name") or body.get("project_name") or application_name
            module_name = body.get("module_name") or body.get("application_name") or module_name
            version = body.get("version") or version
            repository_url = body.get("repository_url") or repository_url
            branch = body.get("branch") or branch
        except Exception:
            pass

    app_name = (application_name or project_name or "").strip()
    mod_name = (module_name or "").strip()
    ver = (version or "").strip()

    file_hash = ""
    try:
        if files:
            pairs = []
            for index, upload in enumerate(files):
                content = await upload.read()
                pairs.append((upload.filename or str(index), content))
            if pairs and not all(len(c) == 0 for _, c in pairs):
                packed, _ = pack_folder(pairs)
                file_hash = hashlib.sha256(packed).hexdigest()
        elif file:
            content = await file.read()
            if content:
                file_hash = hashlib.sha256(content).hexdigest()
    except Exception:
        pass

    res = scan_service.check_preflight_duplicate(
        org=org,
        app_name=app_name,
        mod_name=mod_name,
        ver=ver,
        file_hash=file_hash,
        repository_url=repository_url,
        branch=branch,
    )
    return envelope(res, rid)


@router.post("/api/v1/scans/local")
async def local_scan(
    request: Request,
    file: UploadFile | None = File(default=None),
    files: list[UploadFile] | None = File(default=None),
    paths: list[str] | None = Form(default=None),
    project_name: str = Form(default=""),
    application_name: str = Form(default=""),
    project_id: str = Form(default=""),
    application_id: str = Form(default=""),
    version: str = Form(default=""),
    description: str = Form(default=""),
    business_owner: str = Form(default=""),
    technical_owner: str = Form(default=""),
    development_type: str = Form(default="In-house"),
    vendor_name: str = Form(default=""),
    module_type: str = Form(default="Microservice"),
    generation_context: str = Form(default="Source"),
):
    rid = rid_from_request(request)
    cfg = request.app.state.cfg
    store = request.app.state.store
    orch = request.app.state.orch
    scan_service = request.app.state.scan_service

    length = request.headers.get("content-length")
    if length and int(length) > cfg.max_upload_bytes:
        return error_response("INVALID_INPUT", "multipart parse failed", rid, 400)
    try:
        if files:
            pairs = []
            path_list = paths or []
            if path_list and len(path_list) != len(files):
                return error_response("INVALID_INPUT", "folder path is not allowed", rid, 400)
            for index, upload in enumerate(files):
                name = path_list[index] if path_list else (upload.filename or "")
                content = await upload.read()
                if len(content) > cfg.max_upload_bytes:
                    return error_response("INVALID_INPUT", "multipart parse failed", rid, 400)
                pairs.append((name, content))
            if not pairs or all(len(c) == 0 for _, c in pairs):
                return error_response(
                    "EMPTY_FILE",
                    "The selected folder contains only empty files (0 bytes). Empty folders cannot be scanned.",
                    rid,
                    400,
                )
            try:
                packed, upload_name = pack_folder(pairs)
            except ValueError:
                return error_response("INVALID_INPUT", "folder path is not allowed", rid, 400)
            except LookupError:
                return error_response(
                    "UNSUPPORTED_FILE",
                    "folder must contain a supported manifest (npm, PyPI, Maven, Go, Cargo, NuGet, Composer, RubyGems, Pub, Hex, Swift, Conan, opam, CRAN, or Hackage)",
                    rid,
                    400,
                )
            blob = packed
        elif file is not None and file.filename:
            filename = file.filename
            lower = filename.lower()
            archive = lower.endswith(".zip") or lower.endswith(".tgz") or lower.endswith(".tar.gz")
            if not archive and not is_supported_manifest(filename):
                return error_response(
                    "UNSUPPORTED_FILE",
                    "file must be a .zip/.tar.gz archive, a supported manifest, or a project folder",
                    rid,
                    400,
                )
            blob = await file.read()
            if len(blob) == 0:
                return error_response(
                    "EMPTY_FILE",
                    f"The file '{filename}' is empty (0 bytes). Empty files cannot be scanned.",
                    rid,
                    400,
                )
            upload_name = filename
        else:
            return error_response("INVALID_INPUT", "file field is required", rid, 400)
    except Exception:
        log.exception("local upload failed")
        return error_response("INVALID_INPUT", "multipart parse failed", rid, 400)

    if not application_name and not application_id:
        return error_response("INVALID_INPUT", "application_name is required", rid, 400)

    org = org_from_request(request)
    try:
        bound = scan_service.bind_scan_target(
            org=org,
            project_id=project_id,
            application_id=application_id,
            project_name=project_name,
            application_name=application_name,
            business_owner=business_owner,
            technical_owner=technical_owner,
            development_type=development_type,
            vendor_name=vendor_name,
            module_type=module_type,
        )
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    if bound is not None:
        project_name, application_name = bound.project_name, bound.application_name

    key = f"uploads/{org}/{uuid.uuid4()}-{safe_upload_name(upload_name)}"
    store.put("uploads", key, BytesIO(blob))

    strategy = "VERSION_MANUAL"
    app_version = version
    if not app_version:
        strategy = "VERSION_UNKNOWN"
        app_version = "UNKNOWN"
    try:
        scan = orch.create_scan(
            {
                "organization_id": org,
                "project_id": project_name,
                "application_id": application_name,
                "application_name": application_name,
                "application_version": app_version,
                "description": description,
                "version_strategy": strategy,
                "bom_type": "SBOM",
                "source_type": "LOCAL",
                "trigger": "Manual",
                "generation_context": generation_context or "Source",
                "source_payload": {
                    "object_key": key,
                    "file_name": upload_name,
                    "upload_hash": hashlib.sha256(blob).hexdigest(),
                },
            }
        )
    except Exception as exc:
        return error_response("CREATE_SCAN_FAILED", str(exc), rid, 400)
    return envelope({"scan_id": scan["id"], "status": scan["status"], "stage": scan["stage"]}, rid, 202)


@router.post("/api/v1/scans/github")
async def github_scan(request: Request):
    rid = rid_from_request(request)
    orch = request.app.state.orch
    scan_service = request.app.state.scan_service

    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", "malformed JSON body", rid, 400)
    try:
        validate_repo_url(body.get("repository_url") or "")
    except ValueError as exc:
        return error_response("INVALID_REPOSITORY", str(exc), rid, 400)
    if not body.get("application_name") and not body.get("application_id"):
        return error_response("INVALID_INPUT", "application_name is required", rid, 400)
    org = org_from_request(request)
    try:
        bound = scan_service.bind_scan_target(
            org=org,
            project_id=body.get("project_id") or "",
            application_id=body.get("application_id") or "",
            project_name=body.get("project_name") or "",
            application_name=body.get("application_name") or "",
        )
    except CatalogError as exc:
        return catalog_error_response(exc, rid)
    project_name = bound.project_name if bound else (body.get("project_name") or "")
    application_name = bound.application_name if bound else body.get("application_name")
    version = body.get("version") or ""
    strategy = "VERSION_MANUAL"
    if not version:
        strategy = "VERSION_UNKNOWN"
        version = "UNKNOWN"
    auth = body.get("authentication") or {}
    try:
        scan = orch.create_scan(
            {
                "organization_id": org,
                "project_id": project_name,
                "application_id": application_name,
                "application_name": application_name,
                "application_version": version,
                "description": body.get("description") or "",
                "version_strategy": strategy,
                "bom_type": "SBOM",
                "source_type": "GITHUB",
                "source_payload": {
                    "repository_url": body.get("repository_url"),
                    "branch": body.get("branch") or "",
                    "commit_sha": body.get("commit_sha") or "",
                    "credential_id": auth.get("credential_id") or "",
                    "organization_id": org,
                },
            }
        )
    except Exception as exc:
        return error_response("CREATE_SCAN_FAILED", str(exc), rid, 400)
    return envelope({"scan_id": scan["id"], "status": scan["status"], "stage": scan.get("stage") or "QUEUED"}, rid, 202)


@router.get("/api/v1/scans")
def list_scans(request: Request):
    scans = request.app.state.scans
    queue = request.app.state.queue
    rid = rid_from_request(request)
    rows = with_sources(queue, scans.list_scans(org_from_request(request), 100))
    return envelope([public_scan(row) for row in rows], rid)


@router.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, request: Request):
    scans = request.app.state.scans
    queue = request.app.state.queue
    rid = rid_from_request(request)
    scan = owned_scan(scans, scan_id, org_from_request(request))
    if scan is None:
        return error_response("SCAN_NOT_FOUND", "the requested scan does not exist", rid, 404)
    return envelope(public_scan(with_sources(queue, [scan])[0]), rid)


@router.get("/api/v1/scans/{scan_id}/status")
def scan_status(scan_id: str, request: Request):
    scans = request.app.state.scans
    queue = request.app.state.queue
    rid = rid_from_request(request)
    scan = owned_scan(scans, scan_id, org_from_request(request))
    if scan is None:
        return error_response("SCAN_NOT_FOUND", "not found", rid, 404)
    labels = queue.source_labels([scan["id"]]).get(scan["id"]) or {}
    data = {"scan_id": scan["id"], "status": scan["status"], "stage": scan["stage"]}
    if scan.get("error_code"):
        data["error_code"] = scan["error_code"]
    if scan.get("error_message"):
        data["error_message"] = scan["error_message"]
    if scan.get("started_at"):
        data["started_at"] = scan["started_at"]
    if scan.get("completed_at"):
        data["completed_at"] = scan["completed_at"]
    if scan.get("source_type"):
        data["source_type"] = scan["source_type"]
    for key in ("file_name", "repository_url", "branch"):
        if labels.get(key):
            data[key] = labels[key]
    return envelope(data, rid)


@router.post("/api/v1/scans/{scan_id}/rescan")
def rescan(scan_id: str, request: Request):
    scans = request.app.state.scans
    orch = request.app.state.orch
    rid = rid_from_request(request)
    scan = owned_scan(scans, scan_id, org_from_request(request))
    if scan is None:
        return error_response("SCAN_NOT_FOUND", "the requested scan does not exist", rid, 404)
    try:
        updated = orch.rescan(scan)
    except RescanError as exc:
        status = 409 if exc.code == "SCAN_NOT_RESCANNABLE" else 400
        return error_response(exc.code, str(exc), rid, status)
    return envelope(
        {"scan_id": updated["id"], "status": updated["status"], "stage": updated["stage"]},
        rid,
        202,
    )


@router.post("/api/v1/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str, request: Request):
    scans = request.app.state.scans
    orch = request.app.state.orch
    rid = rid_from_request(request)
    scan = owned_scan(scans, scan_id, org_from_request(request))
    if scan is None:
        return error_response("SCAN_NOT_FOUND", "the requested scan does not exist", rid, 404)
    try:
        updated = orch.cancel(scan)
    except CancelError as exc:
        return error_response(exc.code, str(exc), rid, 409)
    return envelope(
        {"scan_id": updated["id"], "status": updated["status"], "stage": updated["stage"]},
        rid,
        202,
    )


@router.get("/api/v1/scans/{scan_id}/events")
def scan_events(scan_id: str, request: Request):
    scans = request.app.state.scans
    return envelope(scans.list_events(scan_id), rid_from_request(request))
