"""HTTP API. Responses use the same JSON envelope the UI already expects."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from typing import Any

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response

from app.catalog import CatalogError, CatalogRepo
from app.core.config import Config, load
from app.credentials.service import Audit, CredentialStore, Credentials
from app.core.db import connect, ensure_alive, migrate
from app.export.formats import EXPORTERS, export_snapshot, normalize_format
from app.core.metrics import METRICS
from app.scans.orchestrator import CancelError, Orchestrator, RescanError
from app.projects.dashboard import list_projects
from app.repositories.store import BomRepo, JobQueue, ScanRepo, iso, public_scan, utcnow
from app.sources.workspace import is_supported_manifest, pack_folder, parse_bulk, safe_upload_rel, validate_repo_url
from app.storage.object_store import open_store
from app.vulnerabilities.provider import VulnProvider

log = logging.getLogger("bom")


def _envelope(data: Any, request_id: str, status: int = 200) -> JSONResponse:
    body: dict[str, Any] = {"success": True, "request_id": request_id}
    if data is not None:
        body["data"] = data
    return JSONResponse(body, status_code=status)


def _error(code: str, message: str, request_id: str, status: int) -> JSONResponse:
    return JSONResponse(
        {"success": False, "error": {"code": code, "message": message}, "request_id": request_id},
        status_code=status,
    )


def _org(request: Request) -> str:
    return (request.headers.get("x-organization-id") or "default").strip() or "default"


def _catalog_error(exc: CatalogError, request_id: str) -> JSONResponse:
    return _error(exc.code, exc.message, request_id, exc.status)


def _with_sources(queue: JobQueue, rows: list[dict]) -> list[dict]:
    labels = queue.source_labels([row["id"] for row in rows])
    decorated = []
    for row in rows:
        item = dict(row)
        item.update(labels.get(row["id"]) or {})
        decorated.append(item)
    return decorated


def build(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or load()
    db = connect(cfg)
    migrate(db)
    store = open_store(cfg)
    secrets = CredentialStore(db, cfg.credential_kek)
    creds = Credentials(db, secrets)
    audit = Audit(db)
    scans = ScanRepo(db)
    boms = BomRepo(db)
    catalog = CatalogRepo(db)
    queue = JobQueue(db)
    vulns = VulnProvider(cfg.vuln_provider, cfg.vuln_timeout_seconds, cfg.mitre_api_url)
    orch = Orchestrator(cfg, scans, boms, queue, store, creds, audit, vulns)

    app = FastAPI(title="BOM Engine", docs_url="/docs", redoc_url="/redoc")
    app.state.cfg = cfg
    app.state.orch = orch
    app.state.scans = scans
    app.state.boms = boms
    app.state.catalog = catalog
    app.state.creds = creds
    app.state.audit = audit
    app.state.store = store
    app.state.db = db
    if cfg.api_allow_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cfg.api_allow_origins,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "X-Organization-Id", "X-User-Id", "X-Request-Id"],
            max_age=600,
        )

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        return response

    def rid(request: Request) -> str:
        return getattr(request.state, "request_id", "")

    @app.get("/health/live")
    def live(request: Request):
        return _envelope({"status": "live"}, rid(request))

    @app.get("/health/ready")
    def ready(request: Request):
        db_ok = ensure_alive(db)
        if not db_ok:
            return _error("NOT_READY", "database unavailable", rid(request), 503)
        return _envelope(
            {
                "status": "ready",
                "database": cfg.dialect,
                "database_ok": True,
                "metrics": METRICS.snapshot(),
                "scanner": {"name": cfg.scanner_name, "version": cfg.scanner_version},
                "exporters": list(EXPORTERS),
            },
            rid(request),
        )

    @app.get("/metrics.json")
    def metrics(request: Request):
        return _envelope(METRICS.snapshot(), rid(request))

    @app.post("/api/v1/scans/preflight-check")
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
        org = _org(request)
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

        from app.repositories.facts import _safe_get

        # LEVEL 1: If file_hash is present, check if this EXACT file content was already scanned
        if file_hash:
            file_query = """
                SELECT s.id, s.created_at, s.completed_at, a.name AS app_name, m.name AS module_name, s.application_version, s.scan_status,
                       COALESCE(s.project_id, '') AS legacy_project_id, COALESCE(s.application_name, '') AS legacy_app_name
                FROM scans s
                LEFT JOIN applications a ON s.catalog_project_id = a.id
                LEFT JOIN modules m ON s.catalog_application_id = m.id
                WHERE s.organization_id = ?
                  AND s.scan_status IN ('COMPLETED', 'completed', 'QUEUED', 'RUNNING', 'SCANNING')
                  AND (s.job_payload::text LIKE ? OR s.idempotency_key LIKE ?)
                ORDER BY s.created_at DESC LIMIT 1
            """
            row = db.execute(file_query, [org, f"%{file_hash}%", f"%{file_hash}%"]).fetchone()
            if row:
                completed = _safe_get(row, "completed_at", 2) or _safe_get(row, "created_at", 1)
                scan_app = _safe_get(row, "app_name", 3) or _safe_get(row, "legacy_project_id", 7) or app_name
                scan_mod = _safe_get(row, "module_name", 4) or _safe_get(row, "legacy_app_name", 8) or mod_name
                scan_ver = _safe_get(row, "application_version", 5) or ver
                return _envelope(
                    {
                        "is_duplicate": True,
                        "duplicate_type": "EXACT_FILE_EXISTS",
                        "message": "This exact file has already been scanned in the system.",
                        "application_name": scan_app,
                        "module_name": scan_mod,
                        "version": scan_ver,
                        "completed_at": str(completed) if completed else "",
                        "scan_id": _safe_get(row, "id", 0),
                        "scan_status": _safe_get(row, "scan_status", 6),
                    },
                    rid(request),
                )

        # LEVEL 2: Metadata Check (Application + Module + Version / Git repo)
        if app_name and ver:
            norm_ver = ver.lstrip("vV")
            meta_query = """
                SELECT s.id, s.created_at, s.completed_at, a.name AS app_name, m.name AS module_name, s.application_version, s.scan_status,
                       COALESCE(s.project_id, '') AS legacy_project_id, COALESCE(s.application_name, '') AS legacy_app_name
                FROM scans s
                LEFT JOIN applications a ON s.catalog_project_id = a.id
                LEFT JOIN modules m ON s.catalog_application_id = m.id
                WHERE s.organization_id = ?
                  AND (lower(a.name) = lower(?) OR lower(s.project_id) = lower(?))
                  AND (lower(m.name) = lower(?) OR lower(s.application_name) = lower(?) OR lower(s.application_id) = lower(?) OR ? = '')
                  AND (s.application_version = ? OR ltrim(lower(s.application_version), 'v') = lower(?))
                  AND s.scan_status IN ('COMPLETED', 'completed', 'QUEUED', 'RUNNING', 'SCANNING')
            """
            params = [org, app_name, app_name, mod_name, mod_name, mod_name, mod_name, ver, norm_ver]
            if repository_url:
                meta_query += " AND s.repository_url = ? AND (s.branch = ? OR ? = '')"
                params.extend([repository_url.strip(), branch.strip(), branch.strip()])
            meta_query += " ORDER BY s.created_at DESC LIMIT 1"

            row = db.execute(meta_query, params).fetchone()
            if row:
                completed = _safe_get(row, "completed_at", 2) or _safe_get(row, "created_at", 1)
                scan_app = _safe_get(row, "app_name", 3) or _safe_get(row, "legacy_project_id", 7) or app_name
                scan_mod = _safe_get(row, "module_name", 4) or _safe_get(row, "legacy_app_name", 8) or mod_name
                scan_ver = _safe_get(row, "application_version", 5) or ver
                return _envelope(
                    {
                        "is_duplicate": True,
                        "duplicate_type": "EXACT_SCAN_EXISTS",
                        "message": "A scan for this application, module, and version already exists.",
                        "application_name": scan_app,
                        "module_name": scan_mod,
                        "version": scan_ver,
                        "completed_at": str(completed) if completed else "",
                        "scan_id": _safe_get(row, "id", 0),
                        "scan_status": _safe_get(row, "scan_status", 6),
                    },
                    rid(request),
                )

        return _envelope({"is_duplicate": False}, rid(request))

    @app.post("/api/v1/scans/local")
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
        length = request.headers.get("content-length")
        if length and int(length) > cfg.max_upload_bytes:
            return _error("INVALID_INPUT", "multipart parse failed", rid(request), 400)
        try:
            if files:
                pairs = []
                path_list = paths or []
                if path_list and len(path_list) != len(files):
                    return _error("INVALID_INPUT", "folder path is not allowed", rid(request), 400)
                for index, upload in enumerate(files):
                    name = path_list[index] if path_list else (upload.filename or "")
                    content = await upload.read()
                    if len(content) > cfg.max_upload_bytes:
                        return _error("INVALID_INPUT", "multipart parse failed", rid(request), 400)
                    pairs.append((name, content))
                if not pairs or all(len(c) == 0 for _, c in pairs):
                    return _error(
                        "EMPTY_FILE",
                        "The selected folder contains only empty files (0 bytes). Empty folders cannot be scanned.",
                        rid(request),
                        400,
                    )
                try:
                    packed, upload_name = pack_folder(pairs)
                except ValueError:
                    return _error("INVALID_INPUT", "folder path is not allowed", rid(request), 400)
                except LookupError:
                    return _error(
                        "UNSUPPORTED_FILE",
                        "folder must contain a supported manifest (npm, PyPI, Maven, Go, Cargo, NuGet, Composer, RubyGems, Pub, Hex, Swift, Conan, opam, CRAN, or Hackage)",
                        rid(request),
                        400,
                    )
                blob = packed
            elif file is not None and file.filename:
                filename = file.filename
                lower = filename.lower()
                archive = lower.endswith(".zip") or lower.endswith(".tgz") or lower.endswith(".tar.gz")
                if not archive and not is_supported_manifest(filename):
                    return _error(
                        "UNSUPPORTED_FILE",
                        "file must be a .zip/.tar.gz archive, a supported manifest, or a project folder",
                        rid(request),
                        400,
                    )
                blob = await file.read()
                if len(blob) == 0:
                    return _error(
                        "EMPTY_FILE",
                        f"The file '{filename}' is empty (0 bytes). Empty files cannot be scanned.",
                        rid(request),
                        400,
                    )
                upload_name = filename
            else:
                return _error("INVALID_INPUT", "file field is required", rid(request), 400)
        except Exception:
            log.exception("local upload failed")
            return _error("INVALID_INPUT", "multipart parse failed", rid(request), 400)
        if not application_name and not application_id:
            return _error("INVALID_INPUT", "application_name is required", rid(request), 400)
        org = _org(request)
        try:
            bound = _bind_scan_target(
                catalog, org, project_id, application_id, project_name, application_name,
                business_owner=business_owner,
                technical_owner=technical_owner,
                development_type=development_type,
                vendor_name=vendor_name,
                module_type=module_type,
            )
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        if bound is not None:
            project_name, application_name = bound.project_name, bound.application_name
        key = f"uploads/{org}/{uuid.uuid4()}-{_safe_name(upload_name)}"
        from io import BytesIO

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
            return _error("CREATE_SCAN_FAILED", str(exc), rid(request), 400)
        return _envelope({"scan_id": scan["id"], "status": scan["status"], "stage": scan["stage"]}, rid(request), 202)

    @app.post("/api/v1/scans/github")
    async def github_scan(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error("INVALID_INPUT", "malformed JSON body", rid(request), 400)
        try:
            validate_repo_url(body.get("repository_url") or "")
        except ValueError as exc:
            return _error("INVALID_REPOSITORY", str(exc), rid(request), 400)
        if not body.get("application_name") and not body.get("application_id"):
            return _error("INVALID_INPUT", "application_name is required", rid(request), 400)
        org = _org(request)
        try:
            bound = _bind_scan_target(
                catalog,
                org,
                body.get("project_id") or "",
                body.get("application_id") or "",
                body.get("project_name") or "",
                body.get("application_name") or "",
            )
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
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
            return _error("CREATE_SCAN_FAILED", str(exc), rid(request), 400)
        return _envelope({"scan_id": scan["id"], "status": scan["status"], "stage": scan.get("stage") or "QUEUED"}, rid(request), 202)

    @app.get("/api/v1/scans")
    def list_scans(request: Request):
        rows = _with_sources(queue, scans.list_scans(_org(request), 100))
        return _envelope([public_scan(row) for row in rows], rid(request))

    @app.get("/api/v1/projects")
    def projects_dashboard(request: Request):
        """Read-only Projects & Microservices view aggregated from scans."""
        q = (request.query_params.get("q") or "").strip()
        status = (request.query_params.get("status") or "").strip()
        data = list_projects(scans, boms, _org(request), q=q, status=status)
        return _envelope(data, rid(request))

    @app.get("/api/v1/catalog/projects")
    def catalog_projects(request: Request, q: str = "", limit: int = 50, cursor: str = ""):
        """Searchable project names for dependent dropdowns. IDs are catalog UUIDs."""
        try:
            page = catalog.list_projects(_org(request), q=q, limit=limit, cursor=cursor or None)
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        return _envelope(page, rid(request))

    @app.post("/api/v1/catalog/projects")
    async def create_catalog_project(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error("INVALID_INPUT", "malformed JSON body", rid(request), 400)
        if not isinstance(body, dict):
            return _error("INVALID_INPUT", "project name is required", rid(request), 400)
        names = body.get("applications") or body.get("application_names") or []
        if isinstance(names, str):
            names = [names]
        app_names = []
        for item in names:
            if isinstance(item, dict):
                app_names.append(str(item.get("name") or ""))
            else:
                app_names.append(str(item or ""))
        try:
            created = catalog.create_project(_org(request), str(body.get("name") or ""), app_names)
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        return _envelope(created, rid(request), 201)

    @app.get("/api/v1/catalog/projects/{project_id}/applications-services")
    def catalog_applications(project_id: str, request: Request, q: str = "", limit: int = 50, cursor: str = ""):
        """Applications/Services that belong to the selected project."""
        try:
            page = catalog.list_applications(_org(request), project_id, q=q, limit=limit, cursor=cursor or None)
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        return _envelope(page, rid(request))

    @app.post("/api/v1/catalog/projects/{project_id}/applications-services")
    async def create_catalog_application(project_id: str, request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error("INVALID_INPUT", "malformed JSON body", rid(request), 400)
        if not isinstance(body, dict):
            return _error("INVALID_INPUT", "application/service name is required", rid(request), 400)
        try:
            created = catalog.ensure_application(_org(request), project_id, str(body.get("name") or ""))
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        return _envelope(created, rid(request), 201)

    @app.get("/api/v1/scans/{scan_id}")
    def get_scan(scan_id: str, request: Request):
        scan = _owned(scans, scan_id, _org(request))
        if scan is None:
            return _error("SCAN_NOT_FOUND", "the requested scan does not exist", rid(request), 404)
        return _envelope(public_scan(_with_sources(queue, [scan])[0]), rid(request))

    @app.get("/api/v1/scans/{scan_id}/status")
    def scan_status(scan_id: str, request: Request):
        scan = _owned(scans, scan_id, _org(request))
        if scan is None:
            return _error("SCAN_NOT_FOUND", "not found", rid(request), 404)
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
        return _envelope(data, rid(request))

    @app.post("/api/v1/scans/{scan_id}/rescan")
    def rescan(scan_id: str, request: Request):
        scan = _owned(scans, scan_id, _org(request))
        if scan is None:
            return _error("SCAN_NOT_FOUND", "the requested scan does not exist", rid(request), 404)
        try:
            updated = orch.rescan(scan)
        except RescanError as exc:
            status = 409 if exc.code == "SCAN_NOT_RESCANNABLE" else 400
            return _error(exc.code, str(exc), rid(request), status)
        return _envelope(
            {"scan_id": updated["id"], "status": updated["status"], "stage": updated["stage"]},
            rid(request),
            202,
        )

    @app.post("/api/v1/scans/{scan_id}/cancel")
    def cancel_scan(scan_id: str, request: Request):
        scan = _owned(scans, scan_id, _org(request))
        if scan is None:
            return _error("SCAN_NOT_FOUND", "the requested scan does not exist", rid(request), 404)
        try:
            updated = orch.cancel(scan)
        except CancelError as exc:
            return _error(exc.code, str(exc), rid(request), 409)
        return _envelope(
            {"scan_id": updated["id"], "status": updated["status"], "stage": updated["stage"]},
            rid(request),
            202,
        )

    @app.get("/api/v1/scans/{scan_id}/events")
    def scan_events(scan_id: str, request: Request):
        return _envelope(scans.list_events(scan_id), rid(request))

    @app.get("/api/v1/scans/{scan_id}/sbom")
    def scan_sbom(scan_id: str, request: Request):
        scan = _owned(scans, scan_id, _org(request))
        if scan is None:
            return _error("SCAN_NOT_FOUND", "not found", rid(request), 404)
        if not scan.get("snapshot_id"):
            return _error("SBOM_NOT_READY", "sbom not ready yet", rid(request), 404)
        snap = boms.get_snapshot(scan["snapshot_id"])
        if snap is None:
            return _error("BOM_NOT_FOUND", "not found", rid(request), 404)
        return _envelope(snap, rid(request))

    @app.get("/api/v1/scans/{scan_id}/components")
    def scan_components(scan_id: str, request: Request):
        snap, err = _snap_for_scan(scans, boms, scan_id, _org(request), rid(request))
        if err:
            return err
        return _envelope(snap["components"], rid(request))

    @app.get("/api/v1/scans/{scan_id}/dependencies")
    def scan_deps(scan_id: str, request: Request):
        snap, err = _snap_for_scan(scans, boms, scan_id, _org(request), rid(request))
        if err:
            return err
        return _envelope(snap["dependencies"], rid(request))

    @app.get("/api/v1/scans/{scan_id}/vulnerabilities")
    def scan_vulns(scan_id: str, request: Request):
        snap, err = _snap_for_scan(scans, boms, scan_id, _org(request), rid(request))
        if err:
            return err
        raw_matches = (snap.get("raw_metadata") or {}).get("vulnerability_matches")
        if not raw_matches or not isinstance(raw_matches, list):
            return _envelope(raw_matches, rid(request))

        org = _org(request)
        sbom_id = snap.get("id") or ""
        proj_name = snap.get("project_id") or ""

        with db.lock:
            findings_map = {}
            if sbom_id:
                try:
                    f_rows = db.execute(
                        """SELECT sc.id AS comp_id, UPPER(v.vulnerability_key) AS vuln_key,
                                  f.status, f.vex_status, f.owner
                           FROM findings f
                           JOIN vulnerabilities v ON v.id = f.vulnerability_id
                           JOIN sbom_components sc ON sc.id = f.sbom_component_id
                           WHERE f.sbom_id = ?""",
                        (sbom_id,),
                    ).fetchall()
                    for r in f_rows:
                        findings_map[(str(r["comp_id"]), str(r["vuln_key"]))] = dict(r)
                except Exception:
                    pass

            triage_map = {}
            try:
                t_rows = db.execute(
                    """SELECT UPPER(vulnerability_key) AS vuln_key, project_name, application_name,
                              status, vex_status, owner, justification
                       FROM vulnerability_triage
                       WHERE organization_id = ?
                         AND (project_name = ? OR project_name = '')
                       ORDER BY CASE WHEN project_name <> '' THEN 0 ELSE 1 END""",
                    (org, proj_name),
                ).fetchall()
                for r in t_rows:
                    vk = str(r["vuln_key"])
                    if vk not in triage_map:
                        triage_map[vk] = dict(r)
            except Exception:
                pass

        enriched = []
        for m in raw_matches:
            if isinstance(m, dict):
                c_id = str(m.get("component_id") or "")
                v_key = str(m.get("vulnerability_id") or "").strip().upper()
                f_entry = findings_map.get((c_id, v_key))
                t_entry = triage_map.get(v_key)

                item = dict(m)
                if f_entry and f_entry.get("status"):
                    item["status"] = f_entry["status"]
                    item["vex_status"] = f_entry.get("vex_status") or item.get("vex_status") or "affected"
                    if f_entry.get("owner"):
                        item["owner"] = f_entry["owner"]
                elif t_entry and t_entry.get("status"):
                    item["status"] = t_entry["status"]
                    item["vex_status"] = t_entry.get("vex_status") or item.get("vex_status") or "affected"
                    if t_entry.get("owner"):
                        item["owner"] = t_entry["owner"]

                if t_entry and t_entry.get("justification"):
                    item["justification"] = t_entry["justification"]
                if t_entry and t_entry.get("owner"):
                    item["owner"] = t_entry["owner"]

                enriched.append(item)
            else:
                enriched.append(m)

        return _envelope(enriched, rid(request))

    @app.get("/api/v1/vulnerabilities/triage")
    def list_vuln_triage(request: Request):
        org = _org(request)
        with db.lock:
            rows = db.execute(
                """SELECT vulnerability_key, project_name, application_name, status, vex_status, ticket_id, owner, justification, updated_at
                   FROM vulnerability_triage
                   WHERE organization_id = ?
                   ORDER BY updated_at DESC""",
                (org,),
            ).fetchall()
        data = [
            {
                "cve": row["vulnerability_key"],
                "project": row["project_name"],
                "application": row["application_name"],
                "status": row["status"],
                "vex_status": row["vex_status"],
                "ticket_id": row["ticket_id"],
                "owner": row["owner"],
                "justification": row["justification"],
                "updated_at": iso(row["updated_at"]) if row["updated_at"] else "",
            }
            for row in rows
        ]
        return _envelope(data, rid(request))

    @app.patch("/api/v1/vulnerabilities/{cve_id}/status")
    async def update_vuln_status(cve_id: str, request: Request):
        org = _org(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        status = str(body.get("status") or "").strip()
        if not status:
            return _error("INVALID_INPUT", "status is required", rid(request), 400)
        vex_status = str(body.get("vex_status") or body.get("vexStatus") or "").strip()
        project_name = str(body.get("project") or body.get("project_name") or "").strip()
        app_name = str(body.get("application") or body.get("application_name") or "").strip()
        ticket_id = str(body.get("ticket_id") or body.get("ticketId") or "").strip()
        owner = str(body.get("owner") or "").strip()
        justification = str(body.get("justification") or "").strip()
        clean_cve = cve_id.strip().upper()
        now = utcnow()

        with db.lock:
            existing = db.execute(
                """SELECT status FROM vulnerability_triage
                   WHERE organization_id = ? AND vulnerability_key = ?
                     AND (? = '' OR project_name = ?)
                   LIMIT 1""",
                (org, clean_cve, project_name, project_name),
            ).fetchone()
            current_status = str(existing["status"] if existing else "Open").strip()
            if current_status.lower() == "open" and status.lower() in ("closed", "fixed") and not justification:
                return _error(
                    "INVALID_STATUS_TRANSITION",
                    "Direct transition from Open to Closed is not allowed without validation justification. Move to In Progress or provide remediation justification.",
                    rid(request),
                    400,
                )

            db.execute(
                """INSERT INTO vulnerability_triage (
                     id, organization_id, vulnerability_key, project_name, application_name,
                     status, vex_status, ticket_id, owner, justification, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (organization_id, vulnerability_key, project_name, application_name)
                   DO UPDATE SET
                     status = EXCLUDED.status,
                     vex_status = CASE WHEN EXCLUDED.vex_status <> '' THEN EXCLUDED.vex_status ELSE vulnerability_triage.vex_status END,
                     ticket_id = CASE WHEN EXCLUDED.ticket_id <> '' THEN EXCLUDED.ticket_id ELSE vulnerability_triage.ticket_id END,
                     owner = CASE WHEN EXCLUDED.owner <> '' THEN EXCLUDED.owner ELSE vulnerability_triage.owner END,
                     justification = CASE WHEN EXCLUDED.justification <> '' THEN EXCLUDED.justification ELSE vulnerability_triage.justification END,
                     updated_at = EXCLUDED.updated_at""",
                (
                    str(uuid.uuid4()), org, clean_cve, project_name, app_name,
                    status, vex_status or "affected", ticket_id, owner, justification, now,
                ),
            )

            params = [status]
            vex_clause = ""
            if vex_status:
                vex_clause = ", vex_status = ?"
                params.append(vex_status)
            params.extend([now, clean_cve, org])

            proj_clause = ""
            if project_name:
                proj_clause = " AND s.project_id = ?"
                params.append(project_name)

            db.execute(
                f"""UPDATE findings
                   SET status = ? {vex_clause}, updated_at = ?
                   WHERE vulnerability_id IN (SELECT id FROM vulnerabilities WHERE UPPER(vulnerability_key) = ?)
                     AND sbom_id IN (SELECT s.id FROM sboms s WHERE s.organization_id = ? {proj_clause})""",
                tuple(params),
            )

            try:
                db.execute(
                    """INSERT INTO inventory_change_log (
                         id, organization_id, application_id, module_id, component_name, component_version,
                         action, old_value, new_value, reason, changed_by, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, 'VULN_STATUS_CHANGE', ?, ?, ?, 'admin', CURRENT_TIMESTAMP)""",
                    (
                        str(uuid.uuid4()), org, project_name or "", app_name or "",
                        clean_cve, status,
                        json.dumps({"status": current_status}),
                        json.dumps({"status": status, "vex_status": vex_status}),
                        justification or f"Status changed from {current_status} to {status}",
                    ),
                )
            except Exception as e:
                log.warning("Failed to record vulnerability audit log: %s", e)

        return _envelope({
            "cve": clean_cve,
            "status": status,
            "vex_status": vex_status,
            "project": project_name,
            "owner": owner,
            "justification": justification,
        }, rid(request))

    @app.patch("/api/v1/applications/{target_name_or_id}/lifecycle-status")
    async def update_app_lifecycle_status(target_name_or_id: str, request: Request):
        org = _org(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        status = str(body.get("lifecycle_status") or body.get("status") or "").strip()
        if not status:
            return _error("INVALID_INPUT", "lifecycle_status is required", rid(request), 400)
        s_lower = status.lower()
        if s_lower in ("decommission", "decommissioned", "inactive", "disabled"):
            norm_status = "Decommissioned"
        elif s_lower in ("active", "enabled"):
            norm_status = "Active"
        else:
            norm_status = "Decommissioned" if "decommission" in s_lower else "Active"

        now = utcnow()
        with db.lock:
            db.execute(
                """UPDATE applications 
                   SET lifecycle_status = ?, updated_at = ? 
                   WHERE organization_id = ? AND (id = ? OR LOWER(name) = LOWER(?))""",
                (norm_status, now, org, target_name_or_id, target_name_or_id),
            )
            try:
                db.execute(
                    """UPDATE projects 
                       SET lifecycle_status = ?, updated_at = ? 
                       WHERE organization_id = ? AND (id = ? OR LOWER(name) = LOWER(?))""",
                    (norm_status, now, org, target_name_or_id, target_name_or_id),
                )
            except Exception:
                pass
            from app.core.db import finish
            finish(db)
        return _envelope({"target": target_name_or_id, "lifecycle_status": norm_status}, rid(request))


    @app.get("/api/v1/scans/{scan_id}/export")
    def scan_export(scan_id: str, request: Request, format: str = "cyclonedx-json"):
        scan = _owned(scans, scan_id, _org(request))
        if scan is not None and scan.get("snapshot_id"):
            query = request.url.query
            return RedirectResponse(f"/api/v1/boms/{scan['snapshot_id']}/export?{query}", status_code=302)

        # Check if scan_id is a bulk scan
        bulk = _get_bulk(db, scan_id, _org(request))
        if bulk is not None:
            format_name = request.query_params.get("format", format)
            child_rows = db.execute(
                """SELECT s.sbom_id, s.project_id, s.application_name, s.application_version
                   FROM scans s
                   WHERE s.bulk_scan_id = ? AND s.sbom_id IS NOT NULL AND s.scan_status = 'COMPLETED'""",
                (scan_id,),
            ).fetchall()
            snapshots = [boms.get_snapshot(r[0]) for r in child_rows if r[0]]
            snapshots = [s for s in snapshots if s is not None]
            if not snapshots:
                return _error("NO_SNAPSHOTS", "no completed scans found in this bulk scan", rid(request), 404)

            composite = {
                "id": scan_id,
                "organization_id": _org(request),
                "project_id": bulk.get("project_id") or "Bulk Scan",
                "application_id": bulk.get("project_id") or "Bulk Scan",
                "application_version": f"{len(snapshots)} items",
                "scanner_name": "bom-engine",
                "scanner_version": "sbom-engine-1.0.0",
                "generated_at": bulk.get("completed_at") or bulk.get("created_at") or iso(utcnow()),
                "components": [],
                "dependencies": [],
            }
            seen_comps = set()
            for snap in snapshots:
                for comp in snap.get("components") or []:
                    key = (comp.get("name"), comp.get("version"), comp.get("purl"))
                    if key not in seen_comps:
                        seen_comps.add(key)
                        composite["components"].append(comp)
                for dep in snap.get("dependencies") or []:
                    composite["dependencies"].append(dep)
            try:
                payload, content_type = export_snapshot(format_name, composite)
            except KeyError:
                return _error("UNSUPPORTED_FORMAT", "unsupported format", rid(request), 400)

            # Use application name for user-friendly export filenames without UUIDs
            app_label = bulk.get("project_id") or "application"
            filename = _export_filename(app_label, format_name)
            headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
            return Response(payload, media_type=content_type, headers=headers)

        return _error("SCAN_NOT_FOUND", "not found", rid(request), 404)

    @app.get("/api/v1/boms/{bom_id}")
    def get_bom(bom_id: str, request: Request):
        snap = boms.get_snapshot(bom_id)
        if snap is None or snap.get("organization_id") != _org(request):
            return _error("BOM_NOT_FOUND", "not found", rid(request), 404)
        return _envelope(snap, rid(request))

    @app.get("/api/v1/boms/{bom_id}/export")
    def export_bom(bom_id: str, request: Request, format: str = "cyclonedx-json"):
        snap = boms.get_snapshot(bom_id)
        if snap is None or snap.get("organization_id") != _org(request):
            return _error("BOM_NOT_FOUND", "not found", rid(request), 404)
        try:
            payload, content_type = export_snapshot(format, snap)
        except KeyError:
            return _error("UNSUPPORTED_FORMAT", "unsupported format", rid(request), 400)

        # Use application name for user-friendly export filenames without UUIDs
        app_label = snap.get("project_id") or snap.get("application_id") or "application"
        filename = _export_filename(app_label, format)
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return Response(payload, media_type=content_type, headers=headers)

    @app.get("/api/v1/applications/{application_id}/boms")
    def app_boms(application_id: str, request: Request):
        org = _org(request)
        snaps = [snap for snap in boms.list_for_application(application_id, 50) if snap.get("organization_id") == org]
        return _envelope(snaps, rid(request))

    @app.get("/api/v1/inventory/components")
    def list_inventory(request: Request, limit: int = 200, cursor: str = ""):
        try:
            page = boms.list_inventory_components(_org(request), limit=limit, cursor=cursor or None)
        except ValueError as exc:
            return _error("INVALID_INPUT", str(exc), rid(request), 400)
        return _envelope(page, rid(request))

    @app.post("/api/v1/inventory/components")
    async def create_inventory(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error("INVALID_INPUT", "malformed JSON body", rid(request), 400)
        items = body.get("components") if isinstance(body, dict) else None
        if not isinstance(items, list) or not items:
            return _error("INVALID_INPUT", "components are required", rid(request), 400)
        org = _org(request)
        reason = str(body.get("reason") or "Manual addition").strip()
        try:
            normalized = [_bind_inventory_item(catalog, org, item) for item in items]
            saved = boms.add_inventory_components(org, normalized)
            for item in (saved or []):
                try:
                    db.execute(
                        """INSERT INTO inventory_change_log (
                             id, organization_id, application_id, module_id, component_name, component_version,
                             action, new_value, reason, changed_by, created_at
                           ) VALUES (?, ?, ?, ?, ?, ?, 'ADD', ?, ?, 'admin', CURRENT_TIMESTAMP)""",
                        (
                            str(uuid.uuid4()), org, item.get("application_id") or "", item.get("module_id") or "",
                            item.get("name") or "", item.get("version") or "",
                            json.dumps(item), reason,
                        ),
                    )
                except Exception:
                    pass
        except CatalogError as exc:
            return _catalog_error(exc, rid(request))
        except ValueError as exc:
            return _error("INVALID_INPUT", str(exc), rid(request), 400)
        return _envelope(saved, rid(request), 201)

    @app.delete("/api/v1/inventory/components/{component_id}")
    def delete_inventory(component_id: str, request: Request, reason: str = ""):
        org = _org(request)
        deleted_row = boms.delete_inventory_component(org, component_id)
        if not deleted_row:
            return _error("NOT_FOUND", "Component not found", rid(request), 404)

        audit_reason = (reason or request.headers.get("x-reason") or "Manual removal").strip()
        try:
            c_name = deleted_row.get("name") or ""
            c_ver = deleted_row.get("version") or ""
            c_app = deleted_row.get("application_id") or ""
            c_mod = deleted_row.get("module_id") or ""
            db.execute(
                """INSERT INTO inventory_change_log (
                     id, organization_id, application_id, module_id, component_name, component_version,
                     action, old_value, reason, changed_by, created_at
                   ) VALUES (?, ?, ?, ?, ?, ?, 'REMOVE', ?, ?, 'admin', CURRENT_TIMESTAMP)""",
                (
                    str(uuid.uuid4()), org, c_app, c_mod, c_name, c_ver,
                    json.dumps(deleted_row), audit_reason,
                ),
            )
        except Exception:
            pass

        return _envelope({"deleted": True, "id": component_id, "reason": audit_reason}, rid(request))

    @app.get("/api/v1/inventory/audit-log")
    def get_inventory_audit_log(request: Request, component_name: str = "", limit: int = 50):
        org = _org(request)
        comp_name = component_name.strip()
        if comp_name:
            rows = db.execute(
                """SELECT id, organization_id, application_id, module_id, component_name, component_version,
                          action, reason, changed_by, created_at
                   FROM inventory_change_log
                   WHERE organization_id = ? AND LOWER(component_name) = LOWER(?)
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (org, comp_name, limit),
            ).fetchall()
        else:
            rows = db.execute(
                """SELECT id, organization_id, application_id, module_id, component_name, component_version,
                          action, reason, changed_by, created_at
                   FROM inventory_change_log
                   WHERE organization_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (org, limit),
            ).fetchall()

        items = [
            {
                "id": r["id"],
                "organization_id": r["organization_id"],
                "application_id": r["application_id"],
                "module_id": r["module_id"],
                "component_name": r["component_name"],
                "component_version": r["component_version"],
                "action": r["action"],
                "reason": r["reason"],
                "changed_by": r["changed_by"],
                "created_at": iso(r["created_at"]) if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
            }
            for r in rows
        ]
        return _envelope({"items": items, "total": len(items)}, rid(request))

    @app.get("/api/v1/packages/{package_name}/history")
    def get_package_history(package_name: str, request: Request):
        pkg_name = package_name.strip()
        if not pkg_name:
            return _error("INVALID_INPUT", "Package name is required", rid(request), 400)
        org = _org(request)

        scan_records = db.execute(
            """SELECT sc.name, sc.version, sc.ecosystem, sc.dependency_scope, sc.is_direct_dependency,
                      sc.source_manifest, s.id AS sbom_id, s.scan_id, s.generated_at,
                      COALESCE(app.name, s.project_id) AS application_name,
                      COALESCE(mod.name, s.application_id) AS module_name,
                      s.repository_url, s.repository_branch, s.commit_sha
               FROM sbom_components sc
               JOIN sboms s ON s.id = sc.sbom_id
               LEFT JOIN applications app ON app.id = s.project_id
               LEFT JOIN modules mod ON mod.id = s.application_id
               WHERE s.organization_id = ? AND LOWER(sc.name) = LOWER(?)
               ORDER BY s.generated_at ASC""",
            (org, pkg_name),
        ).fetchall()

        audit_records = db.execute(
            """SELECT id, action, component_version, reason, changed_by, created_at, application_id, module_id
               FROM inventory_change_log
               WHERE organization_id = ? AND LOWER(component_name) = LOWER(?)
               ORDER BY created_at ASC""",
            (org, pkg_name),
        ).fetchall()

        timeline = []
        last_version_by_mod = {}

        for r in scan_records:
            mod_key = f"{r['application_name']}/{r['module_name']}"
            ver = r["version"]
            prev_ver = last_version_by_mod.get(mod_key)
            if prev_ver is None:
                change_type = "ADDED"
            elif prev_ver != ver:
                change_type = "UPGRADED"
            else:
                change_type = "CURRENT"
            last_version_by_mod[mod_key] = ver

            timeline.append({
                "type": "SCAN",
                "change_type": change_type,
                "version": ver,
                "previous_version": prev_ver if change_type == "UPGRADED" else None,
                "application": r["application_name"],
                "module": r["module_name"],
                "scan_id": r["scan_id"],
                "branch": r["repository_branch"],
                "commit_sha": r["commit_sha"],
                "source_manifest": r["source_manifest"],
                "scope": r["dependency_scope"],
                "timestamp": iso(r["generated_at"]) if hasattr(r["generated_at"], "isoformat") else str(r["generated_at"]),
                "reason": f"Detected in scan {r['scan_id']}",
            })

        for a in audit_records:
            timeline.append({
                "type": "AUDIT",
                "change_type": a["action"],
                "version": a["component_version"],
                "previous_version": None,
                "application": a["application_id"],
                "module": a["module_id"],
                "scan_id": None,
                "branch": "",
                "commit_sha": "",
                "source_manifest": "Manual Override",
                "scope": "manual",
                "timestamp": iso(a["created_at"]) if hasattr(a["created_at"], "isoformat") else str(a["created_at"]),
                "reason": a["reason"],
                "author": a["changed_by"],
            })

        timeline.sort(key=lambda x: str(x["timestamp"]), reverse=True)
        distinct_versions = sorted(list(set(t["version"] for t in timeline if t["version"])))

        return _envelope({
            "package_name": pkg_name,
            "distinct_versions": distinct_versions,
            "total_events": len(timeline),
            "timeline": timeline,
        }, rid(request))

    @app.get("/api/v1/packages/occurrences")
    def get_package_occurrences(request: Request, name: str = "", purl: str = ""):
        pkg_name = (name or "").strip()
        if not pkg_name and purl:
            from app.core.inventory_derived import derive_base_purl
            base = derive_base_purl(purl)
            if base and "/" in base:
                pkg_name = base.split("/")[-1].strip()
            else:
                pkg_name = purl.strip()
        if not pkg_name:
            return _error("INVALID_INPUT", "name or purl query parameter is required", rid(request), 400)
        from app.core.inventory_derived import calculate_package_usages
        usages = calculate_package_usages(db, package_name=pkg_name, organization_id=_org(request))
        apps_count = len(set(u["application_id"] for u in usages if u.get("application_id")))
        mods_count = len(set(u["module_id"] for u in usages if u.get("module_id")))
        return _envelope(
            {
                "package_name": pkg_name,
                "occurrence_count": len(usages),
                "applications_count": apps_count,
                "modules_count": mods_count,
                "usages": usages,
            },
            rid(request),
        )

    @app.post("/api/v1/scans/bulk")
    async def bulk_upload(request: Request, file: UploadFile | None = File(default=None), project_name: str = Form(default="")):
        if file is None or not file.filename:
            return _error("INVALID_INPUT", "file field is required", rid(request), 400)
        lower = file.filename.lower()
        if not (lower.endswith(".csv") or lower.endswith(".xlsx") or lower.endswith(".xls")):
            return _error("UNSUPPORTED_FILE", "expected .csv, .xlsx, or .xls", rid(request), 400)
        blob = await file.read()
        if len(blob) == 0:
            return _error(
                "EMPTY_FILE",
                f"The spreadsheet file '{file.filename}' is empty (0 bytes). Empty files cannot be scanned.",
                rid(request),
                400,
            )
        if len(blob) > cfg.max_bulk_file_bytes:
            return _error("INVALID_INPUT", "multipart parse failed", rid(request), 400)
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
            return _error(code, error_message, rid(request), 400)
        if len(rows) > cfg.max_bulk_rows:
            return _error("TOO_MANY_ROWS", "file exceeds MAX_BULK_ROWS", rid(request), 400)
        try:
            aggregate = _submit_bulk(db, orch, _org(request), project_name, file.filename, rows, errors)
        except Exception as exc:
            return _error("SUBMIT_FAILED", str(exc), rid(request), 500)
        return _envelope(aggregate, rid(request), 202)

    @app.get("/api/v1/bulk-scans/{bulk_id}")
    def get_bulk(bulk_id: str, request: Request):
        agg = _get_bulk(db, bulk_id, _org(request))
        if agg is None:
            return _error("BULK_NOT_FOUND", "not found", rid(request), 404)
        return _envelope(agg, rid(request))

    @app.get("/api/v1/bulk-scans/{bulk_id}/results")
    def bulk_results(bulk_id: str, request: Request):
        agg = _get_bulk(db, bulk_id, _org(request))
        if agg is None:
            return _error("BULK_NOT_FOUND", "not found", rid(request), 404)
        return _envelope(agg["items"], rid(request))

    @app.post("/api/v1/credentials/github")
    async def create_cred(request: Request):
        try:
            body = await request.json()
        except Exception:
            return _error("INVALID_INPUT", "malformed JSON body", rid(request), 400)
        org = _org(request)
        kind = body.get("type")
        try:
            if kind == "GITHUB_APP":
                if not body.get("app_id") or not body.get("private_key_pem"):
                    return _error("INVALID_INPUT", "app_id and private_key_pem are required", rid(request), 400)
                cred = creds.create_app(org, body.get("name") or "", body["app_id"], body["private_key_pem"], body.get("repository_scope"))
            elif kind == "GITHUB_FINE_GRAINED_PAT":
                if not body.get("token"):
                    return _error("INVALID_INPUT", "token is required", rid(request), 400)
                cred = creds.create_pat(org, body.get("name") or "", body["token"], body.get("repository_scope"))
            else:
                return _error("INVALID_INPUT", "unsupported credential type", rid(request), 400)
        except Exception:
            log.exception("credential store failed")
            return _error("CREDENTIAL_FAILED", "failed to store credential", rid(request), 500)
        audit.record("CREDENTIAL_CREATED", organization_id=org, credential_id=cred["id"], metadata={"type": cred["credential_type"]})
        return _envelope(cred, rid(request), 201)

    @app.get("/api/v1/credentials/github")
    def list_creds(request: Request):
        return _envelope(creds.list(_org(request)), rid(request))

    @app.delete("/api/v1/credentials/github/{cred_id}")
    def revoke_cred(cred_id: str, request: Request):
        org = _org(request)
        try:
            creds.revoke(cred_id, org)
        except LookupError:
            return _error("CREDENTIAL_NOT_FOUND", "not found", rid(request), 404)
        audit.record("CREDENTIAL_REVOKED", organization_id=org, credential_id=cred_id)
        return _envelope({"status": "revoked"}, rid(request))

    @app.post("/api/v1/github/webhooks")
    async def webhook(request: Request):
        body = await request.body()
        if len(body) > 5 * 1024 * 1024:
            return _error("INVALID_INPUT", "unreadable body", rid(request), 400)
        if not _valid_signature(request.headers.get("x-hub-signature-256") or "", body, cfg.github_webhook_secret.encode()):
            return _error("SIGNATURE_INVALID", "signature invalid", rid(request), 401)
        event = request.headers.get("x-github-event") or ""
        delivery = request.headers.get("x-github-delivery") or ""
        if not delivery:
            return _error("INVALID_INPUT", "missing delivery id", rid(request), 400)
        org = _org(request)
        delivery_key = "webhook:" + delivery
        if scans.find_by_key(delivery_key):
            return _envelope({"status": "duplicate"}, rid(request))
        if event not in ("push", "release"):
            from app.catalog.store import ensure_organization
            from app.repositories.store import iso, utcnow

            ensure_organization(db, org)
            db.execute(
                """INSERT INTO scans (
                   id, organization_id, project_id, application_id, application_name,
                   application_version, version_strategy, bom_type, source_type, scan_status,
                   scan_stage, idempotency_key, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT (idempotency_key) DO NOTHING""",
                (
                    str(uuid.uuid4()), org, "", "", "", "", "VERSION_UNKNOWN", "SBOM", "GITHUB",
                    "IGNORED", "IGNORED", delivery_key, iso(utcnow()),
                ),
            )
            return _envelope({"status": "ignored"}, rid(request))
        try:
            payload = json.loads(body)
        except Exception:
            return _error("INVALID_INPUT", "malformed payload", rid(request), 400)
        full_name = ((payload.get("repository") or {}).get("full_name") or "")
        url = "https://github.com/" + full_name
        try:
            validate_repo_url(url)
        except ValueError as exc:
            return _error("INVALID_REPOSITORY", str(exc), rid(request), 400)
        ref = payload.get("ref") or ""
        branch = (payload.get("repository") or {}).get("default_branch") or ""
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/") :]
        after = payload.get("after") or ""
        org = _org(request)
        try:
            scan = orch.create_scan(
                {
                    "organization_id": org,
                    "project_id": full_name,
                    "application_id": full_name,
                    "application_name": full_name,
                    "application_version": "webhook-" + after[:7],
                    "version_strategy": "VERSION_UNKNOWN",
                    "bom_type": "SBOM",
                    "source_type": "GITHUB",
                    "idempotency_key": delivery_key,
                    "source_payload": {
                        "repository_url": url,
                        "branch": branch,
                        "commit_sha": after,
                        "organization_id": org,
                    },
                }
            )
        except Exception as exc:
            return _error("SCAN_CREATE_FAILED", str(exc), rid(request), 500)
        return _envelope({"status": "queued", "scan_id": scan["id"]}, rid(request))

    return app


def _bind_scan_target(
    catalog: CatalogRepo,
    org: str,
    project_id,
    application_id,
    project_name,
    application_name,
    business_owner: str = "",
    technical_owner: str = "",
    development_type: str = "In-house",
    vendor_name: str = "",
    module_type: str = "Microservice",
):
    """Validate IDs when the UI sent them; otherwise keep name-based scans and seed the catalog."""
    project_id = str(project_id or "").strip()
    application_id = str(application_id or "").strip()
    project_name = str(project_name or "").strip()
    application_name = str(application_name or "").strip()
    if project_id or application_id:
        return catalog.bind(
            org,
            project_id=project_id,
            application_id=application_id,
            project_name=project_name,
            application_name=application_name,
            persist_missing=False,
        )
    if project_name and application_name:
        return catalog.ensure_named(
            org,
            project_name,
            application_name,
            business_owner=business_owner,
            technical_owner=technical_owner,
            development_type=development_type,
            vendor_name=vendor_name,
            module_type=module_type,
        )
    return None


def _bind_inventory_item(catalog: CatalogRepo, org: str, item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("each component must be an object")
    project_id = str(item.get("project_id") or item.get("projectId") or "").strip()
    application_id = str(item.get("application_id") or item.get("applicationId") or "").strip()
    proj_name = str(item.get("project") or item.get("project_name") or item.get("projectName") or "").strip()
    app_name = str(item.get("project_application") or item.get("projectApplication") or item.get("application") or item.get("application_name") or "").strip()
    if not project_id and not application_id and not proj_name and not app_name:
        return item
    bound = catalog.bind(
        org,
        project_id=project_id,
        application_id=application_id,
        project_name=proj_name or "Default-Application",
        application_name=app_name or "Default-Module",
        persist_missing=True,
    )
    patched = dict(item)
    patched["project"] = bound.project_name
    patched["project_name"] = bound.project_name
    patched["project_application"] = bound.application_name
    patched["project_id"] = bound.project_id
    patched["application_id"] = bound.application_id
    return patched


def _safe_name(name: str) -> str:
    base = name.replace("\\", "/").split("/")[-1]
    return base.replace("..", "")


def _export_filename(app_name: str, format_name: str) -> str:
    """Build a sanitized, user-friendly export filename using the application name (no UUIDs)."""
    import re

    raw = (app_name or "").strip()
    # Replace characters unsafe for filesystems while preserving readable casing (e.g. WorkforceEdge)
    clean_app = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-") or "application"
    normalized = normalize_format(format_name)
    if normalized == "spdx-json":
        return f"{clean_app}_spdx.json"
    if normalized == "cyclonedx-json":
        return f"{clean_app}_cyclonedx.json"
    if normalized == "csv":
        return f"{clean_app}_csv.csv"
    return f"{clean_app}_xlsx.xlsx"


def _owned(scans: ScanRepo, scan_id: str, org: str):
    scan = scans.get_scan(scan_id)
    if scan is None or scan["organization_id"] != org:
        return None
    return scan


def _snap_for_scan(scans, boms, scan_id, org, request_id):
    scan = _owned(scans, scan_id, org)
    if scan is None or not scan.get("snapshot_id"):
        return None, _error("SCAN_NOT_FOUND", "not found", request_id, 404)
    snap = boms.get_snapshot(scan["snapshot_id"])
    if snap is None:
        return None, _error("BOM_NOT_FOUND", "not found", request_id, 404)
    return snap, None


def _valid_signature(header: str, body: bytes, secret: bytes) -> bool:
    if not secret or not header.startswith("sha256="):
        return False
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header, "sha256=" + digest)


def _row_problems(errors: list) -> dict[int, list]:
    grouped: dict[int, list] = {}
    for err in errors:
        grouped.setdefault(err["row"], []).append(err)
    return grouped


def _submit_bulk(db, orch: Orchestrator, org: str, project: str, filename: str, rows: list, errors: list) -> dict:
    from app.catalog.store import ensure_organization
    from app.repositories.store import iso, utcnow

    bulk_id = str(uuid.uuid4())
    created = iso(utcnow())
    problems = _row_problems(errors)
    catalog = CatalogRepo(db)
    ensure_organization(db, org)
    METRICS.add("bulk_scans_total")
    items = []
    queued = 0
    seen_scans: set[str] = set()
    for row in rows:
        scan_id = ""
        error_code = ""
        error_message = ""
        row_problems = problems.get(row["row_number"]) or []
        if row_problems:
            status = "SKIPPED"
            error_code = row_problems[0]["code"]
            error_message = "; ".join(problem["message"] for problem in row_problems)
            scan_id = _insert_bulk_row(
                db, org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
            )
        else:
            try:
                project_name = row["project_name"] or project
                application_name = row["application_name"]
                if project_name and application_name:
                    catalog.ensure_named(org, project_name, application_name)
                scan = orch.create_scan(
                    {
                        "organization_id": org,
                        "project_id": project_name,
                        "application_id": application_name,
                        "application_name": application_name,
                        "application_version": row["version"] or "UNKNOWN",
                        "version_strategy": "VERSION_MANUAL",
                        "bom_type": "SBOM",
                        "source_type": "GITHUB",
                        "source_payload": {
                            "repository_url": row["repository_url"],
                            "branch": row["branch"],
                            "credential_id": row["authentication_reference"],
                            "organization_id": org,
                        },
                        "bulk_scan_id": bulk_id,
                        "bulk_row": row["row_number"],
                        "repository_url": row["repository_url"],
                        "branch": row["branch"],
                    }
                )
            except Exception as exc:
                status = "FAILED"
                error_code = "SCAN_CREATE_FAILED"
                error_message = str(exc)
                errors.append({"row": row["row_number"], "field": "repository_url", "code": error_code, "message": error_message})
                scan_id = _insert_bulk_row(
                    db, org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
                )
            else:
                outcome = scan.get("outcome")
                if outcome == "existing" or scan["id"] in seen_scans:
                    status = "SKIPPED"
                    error_code = "DUPLICATE_PROJECT"
                    branch = row["branch"] or "the default branch"
                    error_message = (
                        f"Duplicate project. Scan {scan['id']} already covers {row['repository_url']} ({branch}) "
                        "for this application. That scan was kept and this row was not queued."
                    )
                    errors.append(
                        {
                            "row": row["row_number"],
                            "field": "repository_url",
                            "code": "DUPLICATE_PROJECT",
                            "message": error_message,
                        }
                    )
                    scan_id = _insert_bulk_row(
                        db, org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
                    )
                else:
                    status = "QUEUED"
                    scan_id = scan["id"]
                    seen_scans.add(scan["id"])
                    queued += 1
        payload = {
            "id": scan_id,
            "bulk_scan_id": bulk_id,
            "row_number": row["row_number"],
            "project_name": row["project_name"],
            "application_name": row["application_name"],
            "version": row["version"],
            "repository_url": row["repository_url"],
            "status": status,
            "created_at": created,
        }
        if status == "QUEUED":
            payload["scan_id"] = scan_id
        if error_code:
            payload["error_code"] = error_code
        if error_message:
            payload["error_message"] = error_message
        if status in ("SKIPPED", "FAILED"):
            payload["started_at"] = created
            payload["completed_at"] = created
        items.append(payload)
    invalid_rows = len(rows) - queued
    status = "PROCESSING" if queued else "FAILED"
    db.execute(
        """UPDATE scans
           SET bulk_file_name=?, bulk_status=?, bulk_total_rows=?, bulk_invalid_rows=?, bulk_errors=?
           WHERE bulk_scan_id=?""",
        (filename, status, len(rows), invalid_rows, json.dumps(errors), bulk_id),
    )
    return {
        "id": bulk_id,
        "organization_id": org,
        "project_id": project,
        "status": status,
        "filename": filename,
        "total_rows": len(rows),
        "queued_rows": queued,
        "invalid_rows": invalid_rows,
        "created_at": created,
        "started_at": created,
        "completed_at": created if status in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED") else None,
        "validation_errors": errors or None,
        "items": items,
    }


def _insert_bulk_row(db, org, bulk_id, filename, total, row, status, error_code, error_message, created) -> str:
    item_id = str(uuid.uuid4())
    db.execute(
        """INSERT INTO scans (
           id, organization_id, project_id, application_id, application_name, application_version,
           version_strategy, bom_type, source_type, scan_status, scan_stage, error_code, error_message,
           idempotency_key, created_at, started_at, completed_at, bulk_scan_id, bulk_row_number, bulk_file_name, bulk_total_rows,
           repository_url, branch)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            item_id, org, row["project_name"], row["application_name"], row["application_name"],
            row["version"] or "UNKNOWN", "VERSION_MANUAL", "SBOM", "GITHUB", status, status,
            error_code or "", error_message or "", "bulk-item:" + item_id, created,
            created, created, bulk_id,
            row["row_number"], filename, total, row["repository_url"], row.get("branch") or "",
        ),
    )
    return item_id


def _get_bulk(db, bulk_id: str, org: str) -> dict | None:
    item_rows = db.execute(
        """SELECT id, bulk_scan_id, bulk_row_number, project_id, application_name, application_version,
                  repository_url, scan_status, error_code, error_message, started_at, completed_at,
                  bulk_file_name, bulk_total_rows, bulk_invalid_rows, bulk_errors, created_at, organization_id
           FROM scans
           WHERE bulk_scan_id = ? AND organization_id = ?
           ORDER BY bulk_row_number, created_at""",
        (bulk_id, org),
    ).fetchall()
    if not item_rows:
        return None
    head = item_rows[0]
    errors = json.loads(head["bulk_errors"]) if head["bulk_errors"] else []
    items = []
    for item in item_rows:
        payload = {
            "id": item["id"],
            "bulk_scan_id": item["bulk_scan_id"],
            "row_number": item["bulk_row_number"],
            "project_name": item["project_id"],
            "application_name": item["application_name"],
            "version": item["application_version"],
            "repository_url": item["repository_url"],
            "status": item["scan_status"],
            "created_at": iso(item["created_at"]),
        }
        if item["scan_status"] not in ("SKIPPED", "FAILED", "IGNORED"):
            payload["scan_id"] = item["id"]
        if item["error_code"]:
            payload["error_code"] = item["error_code"]
        if item["error_message"]:
            payload["error_message"] = item["error_message"]
        if item["started_at"]:
            payload["started_at"] = iso(item["started_at"])
        if item["completed_at"]:
            payload["completed_at"] = iso(item["completed_at"])
        items.append(payload)
    failed = sum(1 for item in items if item["status"] in ("FAILED", "SKIPPED", "DEAD_LETTER"))
    completed = sum(1 for item in items if item["status"] == "COMPLETED")
    running = sum(1 for item in items if item["status"] in ("RUNNING", "QUEUED", "PENDING"))
    if running:
        status = "PROCESSING"
    elif failed and completed:
        status = "COMPLETED_WITH_ERRORS"
    elif failed and not completed:
        status = "FAILED"
    elif head["bulk_invalid_rows"] and not completed:
        status = "FAILED"
    elif not completed:
        status = "PROCESSING"
    else:
        status = "COMPLETED"

    started_times = [item["started_at"] for item in items if item.get("started_at")]
    agg_started = min(started_times) if started_times else (iso(head["created_at"]) or iso(utcnow()))

    agg_completed = None
    if status in ("COMPLETED", "COMPLETED_WITH_ERRORS", "FAILED", "CANCELLED"):
        completed_times = [item["completed_at"] for item in items if item.get("completed_at")]
        agg_completed = max(completed_times) if completed_times else (iso(head["completed_at"]) or iso(utcnow()))

    agg = {
        "id": bulk_id,
        "organization_id": head["organization_id"],
        "project_id": head["project_id"],
        "status": status,
        "filename": head["bulk_file_name"],
        "total_rows": head["bulk_total_rows"],
        "invalid_rows": head["bulk_invalid_rows"],
        "created_at": iso(head["created_at"]),
        "started_at": agg_started,
        "completed_at": agg_completed,
        "items": items,
    }
    if errors:
        agg["validation_errors"] = errors
    return agg
