"""Bulk scan queuing, row persistence, and status aggregation."""

from __future__ import annotations

import json
import uuid
from typing import Any

from app.catalog.store import CatalogRepo, ensure_organization
from app.core.db import Database
from app.core.metrics import METRICS
from app.repositories.store import iso, utcnow
from app.scans.orchestrator import Orchestrator


def row_problems(errors: list) -> dict[int, list]:
    grouped: dict[int, list] = {}
    for err in errors:
        grouped.setdefault(err["row"], []).append(err)
    return grouped


class BulkScanService:
    def __init__(self, db: Database, orch: Orchestrator | None = None) -> None:
        self.db = db
        self.orch = orch

    def insert_bulk_row(
        self,
        org: str,
        bulk_id: str,
        filename: str,
        total: int,
        row: dict,
        status: str,
        error_code: str,
        error_message: str,
        created: str,
    ) -> str:
        item_id = str(uuid.uuid4())
        self.db.execute(
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

    def submit_bulk(
        self,
        org: str,
        project: str,
        filename: str,
        rows: list,
        errors: list,
    ) -> dict[str, Any]:
        if self.orch is None:
            raise RuntimeError("Orchestrator required for submit_bulk")
        bulk_id = str(uuid.uuid4())
        created = iso(utcnow())
        problems = row_problems(errors)
        catalog = CatalogRepo(self.db)
        ensure_organization(self.db, org)
        METRICS.add("bulk_scans_total")
        items = []
        queued = 0
        seen_scans: set[str] = set()
        for row in rows:
            scan_id = ""
            error_code = ""
            error_message = ""
            row_probs = problems.get(row["row_number"]) or []
            if row_probs:
                status = "SKIPPED"
                error_code = row_probs[0]["code"]
                error_message = "; ".join(problem["message"] for problem in row_probs)
                scan_id = self.insert_bulk_row(
                    org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
                )
            else:
                try:
                    project_name = row["project_name"] or project
                    application_name = row["application_name"]
                    if project_name and application_name:
                        catalog.ensure_named(org, project_name, application_name)
                    scan = self.orch.create_scan(
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
                    scan_id = self.insert_bulk_row(
                        org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
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
                        scan_id = self.insert_bulk_row(
                            org, bulk_id, filename, len(rows), row, status, error_code, error_message, created,
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
        self.db.execute(
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

    def get_bulk(self, bulk_id: str, org: str) -> dict | None:
        item_rows = self.db.execute(
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
