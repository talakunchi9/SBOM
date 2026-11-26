"""Scanning validation, target binding, and export filename formatting."""

from __future__ import annotations

import re
from typing import Any

from app.catalog import CatalogError, CatalogRepo
from app.core.db import Database
from app.export.formats import normalize_format
from app.repositories.facts import _safe_get


def export_filename(app_name: str, format_name: str) -> str:
    """Build a sanitized, user-friendly export filename using the application name (no UUIDs)."""
    raw = (app_name or "").strip()
    clean_app = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-") or "application"
    normalized = normalize_format(format_name)
    if normalized == "spdx-json":
        return f"{clean_app}_spdx.json"
    if normalized == "cyclonedx-json":
        return f"{clean_app}_cyclonedx.json"
    if normalized == "csv":
        return f"{clean_app}_csv.csv"
    return f"{clean_app}_xlsx.xlsx"


def safe_upload_name(name: str) -> str:
    base = name.replace("\\", "/").split("/")[-1]
    return base.replace("..", "")


class ScanService:
    def __init__(self, db: Database, catalog: CatalogRepo) -> None:
        self.db = db
        self.catalog = catalog

    def check_preflight_duplicate(
        self,
        org: str,
        app_name: str,
        mod_name: str,
        ver: str,
        file_hash: str = "",
        repository_url: str = "",
        branch: str = "",
    ) -> dict[str, Any]:
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
            row = self.db.execute(file_query, [org, f"%{file_hash}%", f"%{file_hash}%"]).fetchone()
            if row:
                completed = _safe_get(row, "completed_at", 2) or _safe_get(row, "created_at", 1)
                scan_app = _safe_get(row, "app_name", 3) or _safe_get(row, "legacy_project_id", 7) or app_name
                scan_mod = _safe_get(row, "module_name", 4) or _safe_get(row, "legacy_app_name", 8) or mod_name
                scan_ver = _safe_get(row, "application_version", 5) or ver
                return {
                    "is_duplicate": True,
                    "duplicate_type": "EXACT_FILE_EXISTS",
                    "message": "This exact file has already been scanned in the system.",
                    "application_name": scan_app,
                    "module_name": scan_mod,
                    "version": scan_ver,
                    "completed_at": str(completed) if completed else "",
                    "scan_id": _safe_get(row, "id", 0),
                    "scan_status": _safe_get(row, "scan_status", 6),
                }

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

            row = self.db.execute(meta_query, params).fetchone()
            if row:
                completed = _safe_get(row, "completed_at", 2) or _safe_get(row, "created_at", 1)
                scan_app = _safe_get(row, "app_name", 3) or _safe_get(row, "legacy_project_id", 7) or app_name
                scan_mod = _safe_get(row, "module_name", 4) or _safe_get(row, "legacy_app_name", 8) or mod_name
                scan_ver = _safe_get(row, "application_version", 5) or ver
                return {
                    "is_duplicate": True,
                    "duplicate_type": "EXACT_SCAN_EXISTS",
                    "message": "A scan for this application, module, and version already exists.",
                    "application_name": scan_app,
                    "module_name": scan_mod,
                    "version": scan_ver,
                    "completed_at": str(completed) if completed else "",
                    "scan_id": _safe_get(row, "id", 0),
                    "scan_status": _safe_get(row, "scan_status", 6),
                }

        return {"is_duplicate": False}

    def bind_scan_target(
        self,
        org: str,
        project_id: str = "",
        application_id: str = "",
        project_name: str = "",
        application_name: str = "",
        business_owner: str = "",
        technical_owner: str = "",
        development_type: str = "In-house",
        vendor_name: str = "",
        module_type: str = "Microservice",
    ) -> Any:
        project_id = str(project_id or "").strip()
        application_id = str(application_id or "").strip()
        project_name = str(project_name or "").strip()
        application_name = str(application_name or "").strip()
        if project_id or application_id:
            return self.catalog.bind(
                org,
                project_id=project_id,
                application_id=application_id,
                project_name=project_name,
                application_name=application_name,
                persist_missing=False,
            )
        if project_name and application_name:
            return self.catalog.ensure_named(
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

    def bind_inventory_item(self, org: str, item: Any) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise ValueError("each component must be an object")
        project_id = str(item.get("project_id") or item.get("projectId") or "").strip()
        application_id = str(item.get("application_id") or item.get("applicationId") or "").strip()
        proj_name = str(item.get("project") or item.get("project_name") or item.get("projectName") or "").strip()
        app_name = str(item.get("project_application") or item.get("projectApplication") or item.get("application") or item.get("application_name") or "").strip()
        if not project_id and not application_id and not proj_name and not app_name:
            return item
        bound = self.catalog.bind(
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
