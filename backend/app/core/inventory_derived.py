"""Derived inventory calculations and package classification helpers.

Implements baseline business logic for:
- Base PURL derivation (handling scoped npm and nested namespaces)
- Package classification (Internal / External / Vendor)
- Code origin derivation from Application development_type
- Application last scan date calculation
- Package usage, first/last detection, and active/removed status
- Change events (Added, Upgraded, Removed) between consecutive scans
"""

from __future__ import annotations

import re
from typing import Any


def derive_base_purl(purl: str | None) -> str | None:
    """Derive Base PURL by removing version, qualifiers, and subpath.
    
    Correctly handles:
    - Scoped npm packages: pkg:npm/@angular/core@14.2.0 -> pkg:npm/@angular/core
    - Percent-encoded scopes: pkg:npm/%40angular/core@14.2.0 -> pkg:npm/%40angular/core
    - Multi-level maven groupIds: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 -> pkg:maven/org.apache.logging.log4j/log4j-core
    - Nested golang repos: pkg:golang/github.com/gin-gonic/gin@v1.9.0 -> pkg:golang/github.com/gin-gonic/gin
    - Qualifiers: pkg:pypi/requests@2.28.1?extension=tar.gz -> pkg:pypi/requests
    - Subpaths: pkg:golang/github.com/gin-gonic/gin@v1.9.0#binding -> pkg:golang/github.com/gin-gonic/gin
    """
    if purl is None:
        return None
    if not isinstance(purl, str):
        return ""
    purl = purl.strip()
    if not purl.startswith("pkg:"):
        return purl

    # 1. Strip qualifiers (?...) and subpath (#...)
    base = purl.split("?")[0].split("#")[0]

    # 2. Split on the last slash to separate namespace prefix from package name and version
    last_slash = base.rfind("/")
    if last_slash == -1:
        # e.g. pkg:generic (invalid/edge case)
        return base

    prefix = base[:last_slash]
    name_and_version = base[last_slash + 1 :]

    # 3. Strip @version from the name segment
    if "@" in name_and_version:
        name = name_and_version.split("@", 1)[0]
    else:
        name = name_and_version

    return f"{prefix}/{name}"


def classify_package(
    name: str,
    purl_or_internal: str | list[str] | None = None,
    internal_prefixes: list[str] | None = None,
    vendor_prefixes: list[str] | None = None,
) -> str:
    """Classify a package as 'Internal', 'Vendor', 'External', or 'Unknown'.
    
    Flexible signature:
    - classify_package(name, purl, internal_prefixes, vendor_prefixes)
    - classify_package(name, internal_prefixes, vendor_prefixes)
    
    Classification rules:
    - Matches internal company namespace/prefix -> 'Internal'
    - Matches known enterprise vendor namespace -> 'Vendor'
    - Non-empty standard package -> 'External'
    - Missing name and purl -> 'Unknown'
    """
    purl = ""
    if isinstance(purl_or_internal, list):
        vendor_prefixes = internal_prefixes
        internal_prefixes = purl_or_internal
    elif isinstance(purl_or_internal, str):
        purl = purl_or_internal

    if not name and not purl:
        return "Unknown"

    clean_name = (name or "").strip().lower()
    clean_purl = (purl or "").strip().lower()

    # Check internal prefixes
    if internal_prefixes:
        for prefix in internal_prefixes:
            p_lower = prefix.strip().lower()
            if p_lower and (clean_name.startswith(p_lower) or clean_purl.startswith(p_lower)):
                return "Internal"

    # Check vendor prefixes
    if vendor_prefixes:
        for prefix in vendor_prefixes:
            v_lower = prefix.strip().lower()
            if v_lower and (clean_name.startswith(v_lower) or clean_purl.startswith(v_lower)):
                return "Vendor"

    return "External"


def derive_code_origin(application_development_type: str | None) -> str:
    """Derive module code origin from parent application development_type.
    
    Mapping rules:
    - 'In-house'   -> 'Internal'
    - 'Outsourced' -> 'Outsourced'
    - 'Vendor'     -> 'Vendor'
    """
    dev_type = (application_development_type or "").strip()
    if dev_type == "Outsourced":
        return "Outsourced"
    elif dev_type == "Vendor":
        return "Vendor"
    return "Internal"


def get_application_last_scan_date(db, application_id: str) -> str | None:
    """Calculate the Last Scan Date for an application across all tracked branches and modules.
    
    Returns the ISO-8601 string of completed_at for the most recent successful scan.
    """
    row = db.execute(
        """
        SELECT MAX(s.completed_at) as last_scan
        FROM scans s
        WHERE s.catalog_project_id = ?
          AND s.status = 'completed'
        """,
        (application_id,),
    ).fetchone()

    if row and row["last_scan"]:
        return str(row["last_scan"])
    return None


def calculate_package_usages(
    db,
    package_name: str,
    organization_id: str = "default",
) -> list[dict[str, Any]]:
    """Calculate usage across applications and modules for a given package.
    
    Returns:
    - application_id & application_name
    - module_id & module_name
    - repository & branch
    - package_location & file_path
    - direct / transitive dependency
    - scope
    - detection_method & confidence
    - version & purl
    - first_detected_at & last_detected_at
    - status ('Active' vs 'Removed')
    """
    clean_name = (package_name or "").strip()
    if not clean_name:
        return []

    query = """
    SELECT 
        a.id as application_id,
        a.name as application_name,
        COALESCE(m.id, '') as module_id,
        COALESCE(m.name, '') as module_name,
        COALESCE(s.repository_url, '') as repository_url,
        COALESCE(s.branch, '') as branch,
        COALESCE(c.source_manifest, '') as package_location,
        c.is_direct_dependency as direct_dependency,
        COALESCE(c.dependency_scope, 'runtime') as scope,
        COALESCE(c.detection_method, 'Lockfile') as detection_method,
        COALESCE(c.confidence, 1.0) as confidence,
        c.version,
        c.package_url as purl,
        MIN(s.created_at) as first_detected_at,
        MAX(s.created_at) as last_detected_at,
        (SELECT s2.id 
         FROM scans s2 
         WHERE s2.catalog_project_id = a.id 
           AND (s2.catalog_application_id = m.id OR (m.id IS NULL AND s2.catalog_application_id IS NULL))
         ORDER BY s2.created_at DESC LIMIT 1) as latest_scan_id,
        MAX(sb.scan_id) as component_latest_scan_id
    FROM sbom_components c
    JOIN sboms sb ON c.sbom_id = sb.id
    JOIN scans s ON sb.scan_id = s.id
    JOIN applications a ON s.catalog_project_id = a.id
    LEFT JOIN modules m ON s.catalog_application_id = m.id
    WHERE a.organization_id = ?
      AND (LOWER(c.name) = LOWER(?) OR c.package_url ILIKE ?)
    GROUP BY 
        a.id, a.name, m.id, m.name, s.repository_url, s.branch,
        c.source_manifest, c.is_direct_dependency, c.dependency_scope,
        c.detection_method, c.confidence, c.version, c.package_url
    ORDER BY a.name, m.name, c.version
    """
    rows = db.execute(
        query,
        (organization_id, clean_name, f"%{clean_name}%"),
    ).fetchall()

    results = []
    for r in rows:
        is_in_latest = r["latest_scan_id"] == r["component_latest_scan_id"]
        status = "Active" if is_in_latest else "Removed"
        results.append(
            {
                "application_id": r["application_id"],
                "application_name": r["application_name"],
                "module_id": r["module_id"],
                "module_name": r["module_name"],
                "repository_url": r["repository_url"],
                "branch": r["branch"],
                "package_location": r["package_location"],
                "direct_dependency": bool(r["direct_dependency"]),
                "scope": r["scope"],
                "detection_method": r["detection_method"],
                "confidence": float(r["confidence"]) if r["confidence"] is not None else 1.0,
                "version": r["version"],
                "purl": r["purl"],
                "first_detected_at": str(r["first_detected_at"]) if r["first_detected_at"] else None,
                "last_detected_at": str(r["last_detected_at"]) if r["last_detected_at"] else None,
                "status": status,
            }
        )
    return results


def calculate_scan_change_events(
    first_arg: Any,
    second_arg: Any = None,
    current_sbom_id: str | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Calculate Added, Upgraded, and Removed components between two SBOM snapshots.
    
    Can be called either as:
    1) calculate_scan_change_events(previous_components: list, current_components: list)
    2) calculate_scan_change_events(db, previous_sbom_id: str, current_sbom_id: str)
    """
    if isinstance(first_arg, (list, tuple)) and isinstance(second_arg, (list, tuple)):
        prev_components = first_arg
        curr_components = second_arg
    else:
        db = first_arg
        prev_id = second_arg
        curr_id = current_sbom_id
        prev_rows = db.execute(
            """SELECT name, version, package_url 
               FROM sbom_components WHERE sbom_id = ?""",
            (prev_id,),
        ).fetchall()
        curr_rows = db.execute(
            """SELECT name, version, package_url 
               FROM sbom_components WHERE sbom_id = ?""",
            (curr_id,),
        ).fetchall()
        prev_components = [dict(r) for r in prev_rows]
        curr_components = [dict(r) for r in curr_rows]

    prev_map = {
        (derive_base_purl(c.get("package_url") or c.get("purl")) or c.get("name", "")): c
        for c in prev_components
    }
    curr_map = {
        (derive_base_purl(c.get("package_url") or c.get("purl")) or c.get("name", "")): c
        for c in curr_components
    }

    added = []
    removed = []
    upgraded = []

    for key, c in curr_map.items():
        if not key:
            continue
        c_ver = c.get("version", "")
        c_name = c.get("name", "")
        c_purl = c.get("package_url") or c.get("purl")
        if key not in prev_map:
            added.append(
                {
                    "change_type": "Added",
                    "event": "Added",
                    "name": c_name,
                    "package_name": c_name,
                    "version": c_ver,
                    "purl": c_purl,
                }
            )
        else:
            p = prev_map[key]
            p_ver = p.get("version", "")
            if p_ver != c_ver:
                evt = "Upgraded" if c_ver > p_ver else "Downgraded"
                upgraded.append(
                    {
                        "change_type": evt,
                        "event": evt,
                        "name": c_name,
                        "package_name": c_name,
                        "previous_version": p_ver,
                        "new_version": c_ver,
                        "purl": c_purl,
                    }
                )

    for key, p in prev_map.items():
        if not key:
            continue
        p_ver = p.get("version", "")
        p_name = p.get("name", "")
        p_purl = p.get("package_url") or p.get("purl")
        if key not in curr_map:
            removed.append(
                {
                    "change_type": "Removed",
                    "event": "Removed",
                    "name": p_name,
                    "package_name": p_name,
                    "version": p_ver,
                    "purl": p_purl,
                }
            )

    return {"added": added, "upgraded": upgraded, "removed": removed}
