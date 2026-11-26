"""Repository for vulnerability triage overrides and inventory/vulnerability audit logs."""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

from app.core.db import Database
from app.repositories.store import iso, utcnow

log = logging.getLogger("bom")


class TriageRepo:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get_existing_triage(self, org: str, cve: str, project_name: str = "") -> dict | None:
        with self.db.lock:
            row = self.db.execute(
                """SELECT status, vex_status, ticket_id, owner, justification, updated_at
                   FROM vulnerability_triage
                   WHERE organization_id = ? AND UPPER(vulnerability_key) = UPPER(?)
                     AND (? = '' OR project_name = ?)
                   LIMIT 1""",
                (org, cve, project_name, project_name),
            ).fetchone()
            return dict(row) if row else None

    def list_triage(self, org: str) -> list[dict]:
        with self.db.lock:
            rows = self.db.execute(
                """SELECT vulnerability_key, project_name, application_name, status, vex_status,
                          ticket_id, owner, justification, updated_at
                   FROM vulnerability_triage
                   WHERE organization_id = ?
                   ORDER BY updated_at DESC""",
                (org,),
            ).fetchall()
        return [
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

    def upsert_triage(
        self,
        org: str,
        clean_cve: str,
        project_name: str,
        app_name: str,
        status: str,
        vex_status: str,
        ticket_id: str,
        owner: str,
        justification: str,
        updated_at: Any = None,
    ) -> None:
        now = updated_at or utcnow()
        with self.db.lock:
            self.db.execute(
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

    def update_findings_for_triage(
        self,
        org: str,
        clean_cve: str,
        status: str,
        vex_status: str = "",
        project_name: str = "",
        updated_at: Any = None,
    ) -> None:
        now = updated_at or utcnow()
        params = [status]
        vex_clause = ""
        if vex_status:
            vex_clause = ", vex_status = ?"
            params.append(vex_status)
        params.extend([now, clean_cve, org])

        proj_clause = ""
        if project_name:
            proj_clause = " AND (s.project_id = ? OR LOWER(s.project_id) = LOWER(?) OR CAST(s.catalog_project_id AS text) = ?)"
            params.extend([project_name, project_name, project_name])

        query = f"""UPDATE findings
                    SET status = ? {vex_clause}, updated_at = ?
                    WHERE vulnerability_id IN (SELECT id FROM vulnerabilities WHERE UPPER(vulnerability_key) = ?)
                      AND sbom_id IN (SELECT s.id FROM sboms s WHERE s.organization_id = ? {proj_clause})"""

        with self.db.lock:
            self.db.execute(query, tuple(params))

    def get_findings_and_triage_maps(
        self,
        org: str,
        sbom_id: str,
        proj_name: str,
    ) -> tuple[dict[tuple[str, str], dict], dict[str, dict]]:
        findings_map: dict[tuple[str, str], dict] = {}
        triage_map: dict[str, dict] = {}

        with self.db.lock:
            if sbom_id:
                try:
                    f_rows = self.db.execute(
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

            try:
                t_rows = self.db.execute(
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

        return findings_map, triage_map

    def record_audit_log(
        self,
        org: str,
        application_id: str,
        module_id: str,
        component_name: str,
        component_version: str,
        action: str,
        old_value: dict | None = None,
        new_value: dict | None = None,
        reason: str = "",
        changed_by: str = "admin",
    ) -> None:
        try:
            resolved_app_id = application_id or ""
            resolved_mod_id = module_id or ""
            with self.db.lock:
                if resolved_app_id:
                    try:
                        row_app = self.db.execute(
                            "SELECT id FROM applications WHERE organization_id = ? AND (CAST(id AS text) = ? OR LOWER(name) = LOWER(?)) LIMIT 1",
                            (org, resolved_app_id, resolved_app_id),
                        ).fetchone()
                        if row_app:
                            resolved_app_id = str(row_app["id"])
                    except Exception:
                        pass
                if resolved_mod_id:
                    try:
                        row_mod = self.db.execute(
                            "SELECT id FROM modules WHERE organization_id = ? AND (CAST(id AS text) = ? OR LOWER(name) = LOWER(?)) LIMIT 1",
                            (org, resolved_mod_id, resolved_mod_id),
                        ).fetchone()
                        if row_mod:
                            resolved_mod_id = str(row_mod["id"])
                    except Exception:
                        pass

                self.db.execute(
                    """INSERT INTO inventory_change_log (
                         id, organization_id, application_id, module_id, component_name, component_version,
                         action, old_value, new_value, reason, changed_by, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                    (
                        str(uuid.uuid4()), org, resolved_app_id, resolved_mod_id,
                        component_name or "", component_version or "", action,
                        json.dumps(old_value) if old_value is not None else None,
                        json.dumps(new_value) if new_value is not None else None,
                        reason, changed_by,
                    ),
                )
        except Exception as e:
            log.warning("Failed to record audit log: %s", e)

    def list_audit_log(self, org: str, component_name: str = "", limit: int = 50) -> list[dict]:
        comp_name = component_name.strip()
        with self.db.lock:
            if comp_name:
                rows = self.db.execute(
                    """SELECT l.id, l.organization_id, l.application_id, l.module_id, l.component_name, l.component_version,
                              l.action, l.reason, l.changed_by, l.created_at,
                              app.name AS application_name,
                              m.name AS module_name
                       FROM inventory_change_log l
                       LEFT JOIN applications app ON (CAST(app.id AS text) = l.application_id OR LOWER(app.name) = LOWER(l.application_id))
                       LEFT JOIN modules m ON (CAST(m.id AS text) = l.module_id OR LOWER(m.name) = LOWER(l.module_id))
                       WHERE l.organization_id = ? AND LOWER(l.component_name) = LOWER(?)
                       ORDER BY l.created_at DESC
                       LIMIT ?""",
                    (org, comp_name, limit),
                ).fetchall()
            else:
                rows = self.db.execute(
                    """SELECT l.id, l.organization_id, l.application_id, l.module_id, l.component_name, l.component_version,
                              l.action, l.reason, l.changed_by, l.created_at,
                              app.name AS application_name,
                              m.name AS module_name
                       FROM inventory_change_log l
                       LEFT JOIN applications app ON (CAST(app.id AS text) = l.application_id OR LOWER(app.name) = LOWER(l.application_id))
                       LEFT JOIN modules m ON (CAST(m.id AS text) = l.module_id OR LOWER(m.name) = LOWER(l.module_id))
                       WHERE l.organization_id = ?
                       ORDER BY l.created_at DESC
                       LIMIT ?""",
                    (org, limit),
                ).fetchall()

        return [
            {
                "id": str(r["id"]),
                "organization_id": r["organization_id"],
                "application_id": r["application_id"],
                "application_name": r.get("application_name") or r["application_id"],
                "module_id": r["module_id"],
                "module_name": r.get("module_name") or r["module_id"],
                "component_name": r["component_name"],
                "component_version": r["component_version"],
                "action": r["action"],
                "reason": r["reason"],
                "changed_by": r["changed_by"],
                "created_at": iso(r["created_at"]) if hasattr(r["created_at"], "isoformat") else str(r["created_at"]),
            }
            for r in rows
        ]

