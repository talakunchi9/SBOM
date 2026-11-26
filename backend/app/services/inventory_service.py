"""Package usage occurrences and historical timeline services."""

from __future__ import annotations

from typing import Any

from app.core.db import Database
from app.core.inventory_derived import calculate_package_usages, derive_base_purl
from app.repositories.store import iso


class InventoryService:
    def __init__(self, db: Database) -> None:
        self.db = db

    def get_package_occurrences(self, org: str, name: str = "", purl: str = "") -> dict[str, Any]:
        pkg_name = (name or "").strip()
        if not pkg_name and purl:
            base = derive_base_purl(purl)
            if base and "/" in base:
                pkg_name = base.split("/")[-1].strip()
            else:
                pkg_name = purl.strip()
        if not pkg_name:
            raise ValueError("name or purl query parameter is required")

        usages = calculate_package_usages(self.db, package_name=pkg_name, organization_id=org)
        apps_count = len(set(u["application_id"] for u in usages if u.get("application_id")))
        mods_count = len(set(u["module_id"] for u in usages if u.get("module_id")))
        return {
            "package_name": pkg_name,
            "occurrence_count": len(usages),
            "applications_count": apps_count,
            "modules_count": mods_count,
            "usages": usages,
        }

    def get_package_history(self, org: str, package_name: str) -> dict[str, Any]:
        pkg_name = package_name.strip()
        if not pkg_name:
            raise ValueError("Package name is required")

        scan_records = self.db.execute(
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

        audit_records = self.db.execute(
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

        return {
            "package_name": pkg_name,
            "distinct_versions": distinct_versions,
            "total_events": len(timeline),
            "timeline": timeline,
        }
