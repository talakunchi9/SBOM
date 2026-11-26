"""HTTP API. Responses use the same JSON envelope the UI already expects."""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.common import (
    catalog_error_response as _catalog_error,
    envelope as _envelope,
    error_response as _error,
    org_from_request as _org,
    owned_scan as _owned,
    rid_from_request as _rid,
    snap_for_scan as _snap_for_scan,
    valid_signature as _valid_signature,
    with_sources as _with_sources,
)
from app.api.v1.router import v1_router
from app.catalog import CatalogError, CatalogRepo
from app.core.config import Config, load
from app.credentials.service import Audit, CredentialStore, Credentials
from app.core.db import connect, migrate
from app.scans.orchestrator import Orchestrator
from app.repositories.store import BomRepo, JobQueue, ScanRepo
from app.repositories.triage_repo import TriageRepo
from app.services.bulk_scan_service import BulkScanService, row_problems as _row_problems
from app.services.inventory_service import InventoryService
from app.services.scan_service import (
    ScanService,
    export_filename as _export_filename,
    safe_upload_name as _safe_name,
)
from app.services.vulnerability_service import VulnerabilityService
from app.storage.object_store import open_store
from app.vulnerabilities.provider import VulnProvider

log = logging.getLogger("bom")


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
    triage_repo = TriageRepo(db)
    vulns = VulnProvider(cfg.vuln_provider, cfg.vuln_timeout_seconds, cfg.mitre_api_url)
    orch = Orchestrator(cfg, scans, boms, queue, store, creds, audit, vulns)

    scan_service = ScanService(db, catalog)
    bulk_service = BulkScanService(db, orch)
    inv_service = InventoryService(db)
    vuln_service = VulnerabilityService(triage_repo)

    app = FastAPI(title="BOM Engine", docs_url="/docs", redoc_url="/redoc")
    app.state.cfg = cfg
    app.state.orch = orch
    app.state.scans = scans
    app.state.boms = boms
    app.state.catalog = catalog
    app.state.queue = queue
    app.state.creds = creds
    app.state.audit = audit
    app.state.store = store
    app.state.db = db
    app.state.triage_repo = triage_repo
    app.state.scan_service = scan_service
    app.state.bulk_service = bulk_service
    app.state.inv_service = inv_service
    app.state.vuln_service = vuln_service

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

    # Mount the centralized API v1 router containing all endpoint domains
    app.include_router(v1_router)

    return app


# =========================================================================
# Backward-compatible helper functions preserved for external imports / tests
# =========================================================================

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
    svc = ScanService(catalog.db if hasattr(catalog, "db") else None, catalog)
    return svc.bind_scan_target(
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


def _bind_inventory_item(catalog: CatalogRepo, org: str, item: Any) -> dict[str, Any]:
    svc = ScanService(catalog.db if hasattr(catalog, "db") else None, catalog)
    return svc.bind_inventory_item(org, item)


def _submit_bulk(db, orch: Orchestrator, org: str, project: str, filename: str, rows: list, errors: list) -> dict:
    svc = BulkScanService(db, orch)
    return svc.submit_bulk(org, project, filename, rows, errors)


def _insert_bulk_row(db, org, bulk_id, filename, total, row, status, error_code, error_message, created) -> str:
    svc = BulkScanService(db, None)
    return svc.insert_bulk_row(org, bulk_id, filename, total, row, status, error_code, error_message, created)


def _get_bulk(db, bulk_id: str, org: str) -> dict | None:
    svc = BulkScanService(db, None)
    return svc.get_bulk(bulk_id, org)
