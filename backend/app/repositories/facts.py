"""Findings, NTIA checks, and dependency ids stored on the ten-table schema.

Snapshot reads still return the dictionaries the API already uses.
"""

from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
_CHECKS = (
    "ntia_supplier",
    "ntia_name",
    "ntia_version",
    "ntia_identifier",
    "ntia_relationship",
    "ntia_author",
    "ntia_timestamp",
)


def _safe_get(row: Any, key: str, index: int) -> Any:
    """Safely extract field from Row wrapper, dict, or tuple."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row.get(key)
    try:
        return row[key]
    except (TypeError, KeyError, IndexError):
        try:
            return row[index]
        except (IndexError, TypeError):
            return None


def resolve_catalog_ids(
    db,
    organization_id: str,
    project_name: str,
    application_name: str,
) -> tuple[str | None, str | None]:
    """Map the names or IDs stored on a scan to application and module ids."""
    project_name = (project_name or "").strip()
    application_name = (application_name or "").strip()
    if not (organization_id or "").strip() or not project_name:
        return None, None

    row = db.execute(
        """SELECT p.id AS project_id, m.id AS application_id
           FROM applications p
           LEFT JOIN modules m
             ON m.application_id = p.id
            AND m.organization_id = p.organization_id
            AND (m.name = ? OR lower(m.name) = lower(?) OR m.id = ?)
           WHERE p.organization_id = ? 
             AND (p.name = ? OR lower(p.name) = lower(?) OR p.id = ?)
           LIMIT 1""",
        (
            application_name,
            application_name,
            application_name,
            organization_id,
            project_name,
            project_name,
            project_name,
        ),
    ).fetchone()

    if row is None:
        return None, None
    return _safe_get(row, "project_id", 0), _safe_get(row, "application_id", 1)


def stored_metadata(raw: dict | None) -> dict:
    """Metadata saved on the SBOM. Matches live in findings."""
    data = dict(raw or {})
    data.pop("vulnerability_matches", None)
    return data


def stored_component_raw(raw: dict | None) -> dict:
    """Component JSON that is not stored in findings or NTIA columns."""
    data = dict(raw or {})
    data.pop("vulnerabilities", None)
    data.pop("compliance_status", None)
    data.pop("compliance_pass", None)
    return data


def persist_snapshot_facts(db, snap: dict[str, Any], components: list[dict[str, Any]]) -> None:
    """Write findings, NTIA flags, depth, and dependency ids for one SBOM."""
    sbom_id = snap["id"]
    project_id, application_id = resolve_catalog_ids(
        db,
        str(snap.get("organization_id") or ""),
        str(snap.get("project_id") or ""),
        str(snap.get("application_id") or ""),
    )
    db.execute(
        """UPDATE sboms
           SET catalog_project_id = ?, catalog_application_id = ?, facts_normalized = TRUE
           WHERE id = ?""",
        (project_id, application_id, sbom_id),
    )
    kept = {comp["id"] for comp in components}
    children: dict[str, list[str]] = {}
    for dep in snap.get("dependencies") or []:
        source = str(dep.get("from_component_id") or "")
        target = str(dep.get("to_component_id") or "")
        if source in kept and target in kept:
            children.setdefault(source, []).append(target)
    now = datetime.now(timezone.utc)
    comp_names = list({str(c.get("name") or "").lower() for c in components if c.get("name")})
    prior_map: dict[str, Any] = {}
    if comp_names:
        placeholders = ",".join("?" for _ in comp_names)
        try:
            p_rows = db.execute(
                f"""SELECT lower(sc.name) AS comp_name, MIN(sc.created_at) AS first_date
                    FROM sbom_components sc
                    WHERE lower(sc.name) IN ({placeholders}) AND sc.sbom_id <> ?
                    GROUP BY lower(sc.name)""",
                (*comp_names, sbom_id),
            ).fetchall()
            for r in p_rows:
                c_name = _safe_get(r, "comp_name", 0)
                if c_name:
                    prior_map[str(c_name).lower()] = _safe_get(r, "first_date", 1)
        except Exception:
            pass

    for comp in components:
        raw = comp.get("raw") if isinstance(comp.get("raw"), dict) else {}
        status = raw.get("compliance_status") if isinstance(raw.get("compliance_status"), dict) else {}
        flags = [status.get(code) if isinstance(status.get(code), bool) else None for code in _CHECKS]
        c_name = (comp.get("name") or "").lower()
        first_date = prior_map.get(c_name)
        if first_date is None and c_name not in prior_map:
            try:
                prior = db.execute(
                    """SELECT MIN(sc.created_at) AS first_date
                       FROM sbom_components sc
                       WHERE lower(sc.name) = lower(?) AND sc.sbom_id <> ?""",
                    (comp.get("name") or "", sbom_id),
                ).fetchone()
                first_date = _safe_get(prior, "first_date", 0) if prior else None
            except Exception:
                first_date = None
        first_det = first_date if first_date else now
        db.execute(
            """UPDATE sbom_components
               SET dependency_depth = COALESCE(?, dependency_depth),
                   depends_on = ?,
                   ntia_supplier = ?, ntia_name = ?, ntia_version = ?, ntia_identifier = ?,
                   ntia_relationship = ?, ntia_author = ?, ntia_timestamp = ?,
                   first_detected_at = COALESCE(first_detected_at, ?),
                   last_detected_at = ?
               WHERE id = ?""",
            (_depth(raw), children.get(comp["id"]) or [], *flags, first_det, now, comp["id"]),
        )
    _persist_findings(
        db,
        sbom_id,
        kept,
        snap.get("raw_metadata") or {},
        str(snap.get("organization_id") or "default"),
        str(snap.get("project_id") or ""),
    )


def overlay_snapshot_facts(db, snap: dict[str, Any]) -> None:
    """Fill match and compliance dictionaries from findings and NTIA columns."""
    org_id = str(snap.get("organization_id") or "default").strip() or "default"
    project_name = str(snap.get("project_id") or "").strip()
    findings = db.execute(
        """SELECT DISTINCT ON (f.sbom_component_id, v.vulnerability_key)
                  f.sbom_component_id, v.vulnerability_key, v.reference_urls, f.source, f.severity,
                  f.cvss_score, f.cvss_vector, f.description, f.fixed_version,
                  COALESCE(t.status, f.status, 'Open') AS status,
                  COALESCE(t.vex_status, f.vex_status, 'affected') AS vex_status,
                  COALESCE(t.justification, '') AS justification,
                  COALESCE(t.owner, '') AS owner
           FROM findings f
           JOIN vulnerabilities v ON v.id = f.vulnerability_id
           LEFT JOIN vulnerability_triage t
             ON UPPER(t.vulnerability_key) = UPPER(v.vulnerability_key)
            AND t.organization_id = ?
            AND (t.project_name = ? OR t.project_name = '')
           WHERE f.sbom_id = ?
           ORDER BY f.sbom_component_id, v.vulnerability_key,
                    CASE WHEN t.project_name <> '' THEN 0 ELSE 1 END""",
        (org_id, project_name, snap["id"]),
    ).fetchall()
    matches = []
    attached: dict[str, list[dict[str, Any]]] = {}
    for row in findings:
        score = float(_safe_get(row, "cvss_score", 5) or 0)
        raw_urls = _safe_get(row, "reference_urls", 2)
        urls = [url for url in (raw_urls or []) if url]
        record = {
            "component_id": _safe_get(row, "sbom_component_id", 0),
            "vulnerability_id": _safe_get(row, "vulnerability_key", 1),
            "source": _safe_get(row, "source", 3) or "",
            "severity": _safe_get(row, "severity", 4) or "UNKNOWN",
            "cvss_score": score,
            "cvss_vector": _safe_get(row, "cvss_vector", 6) or "",
            "description": _safe_get(row, "description", 7) or "",
            "fixed_version": _safe_get(row, "fixed_version", 8) or "",
            "status": _safe_get(row, "status", 9) or "Open",
            "vex_status": _safe_get(row, "vex_status", 10) or "affected",
            "justification": _safe_get(row, "justification", 11) or "",
            "owner": _safe_get(row, "owner", 12) or "",
        }
        if urls:
            record["references"] = urls
        matches.append(record)
        attached.setdefault(record["component_id"], []).append(
            {
                "id": record["vulnerability_id"],
                "severity": record["severity"],
                "cvss": score,
                "fixed_version": record["fixed_version"],
                "source": record["source"],
                "status": record["status"],
                "vex_status": record["vex_status"],
            }
        )
    metadata = dict(snap.get("raw_metadata") or {})
    metadata["vulnerability_matches"] = matches
    snap["raw_metadata"] = metadata
    flags = db.execute(
        """SELECT id, ntia_supplier, ntia_name, ntia_version, ntia_identifier,
                  ntia_relationship, ntia_author, ntia_timestamp, first_detected_at, last_detected_at
           FROM sbom_components WHERE sbom_id = ?""",
        (snap["id"],),
    ).fetchall()
    by_id = {_safe_get(row, "id", 0): row for row in flags}
    for comp in snap.get("components") or []:
        raw = dict(comp.get("raw") or {})
        if comp["id"] in attached:
            raw["vulnerabilities"] = attached[comp["id"]]
        row = by_id.get(comp["id"])
        if row is not None:
            first_det = _safe_get(row, "first_detected_at", 8)
            last_det = _safe_get(row, "last_detected_at", 9)
            if first_det:
                comp["first_detected_at"] = str(first_det)
                comp["first_scan_date"] = str(first_det)
            if last_det:
                comp["last_detected_at"] = str(last_det)
                comp["last_scan_date"] = str(last_det)
            status = {}
            for i, code in enumerate(_CHECKS, start=1):
                val = _safe_get(row, code, i)
                if val is not None:
                    status[code] = bool(val)
            if status:
                raw["compliance_status"] = status
                raw["compliance_pass"] = all(status.values())
        if raw:
            comp["raw"] = raw


def _persist_findings(
    db,
    sbom_id: str,
    kept: set[str],
    metadata: dict,
    org_id: str = "default",
    project_name: str = "",
) -> None:
    seen: set[tuple[str, str]] = set()
    for match in metadata.get("vulnerability_matches") or []:
        if not isinstance(match, dict):
            continue
        component_id = str(match.get("component_id") or "")
        key = str(match.get("vulnerability_id") or "").strip().upper()[:128]
        if not component_id or component_id not in kept or not key or (component_id, key) in seen:
            continue
        seen.add((component_id, key))
        vulnerability_id = _upsert_vulnerability(db, key, match)
        triage_row = db.execute(
            """SELECT status, vex_status FROM vulnerability_triage
               WHERE organization_id = ? AND UPPER(vulnerability_key) = ?
                 AND (project_name = ? OR project_name = '')
               ORDER BY CASE WHEN project_name <> '' THEN 0 ELSE 1 END LIMIT 1""",
            (org_id, key, project_name),
        ).fetchone()
        status_val = (_safe_get(triage_row, "status", 0) if triage_row else "") or match.get("status") or "Open"
        vex_val = (_safe_get(triage_row, "vex_status", 1) if triage_row else "") or match.get("vex_status") or "affected"
        db.execute(
            """INSERT INTO findings (
                 id, sbom_id, sbom_component_id, vulnerability_id, source, severity,
                 cvss_score, cvss_vector, description, fixed_version, status, vex_status)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (sbom_component_id, vulnerability_id) DO UPDATE SET
                 status = EXCLUDED.status,
                 vex_status = EXCLUDED.vex_status,
                 updated_at = CURRENT_TIMESTAMP""",
            (
                str(uuid.uuid4()),
                sbom_id,
                component_id,
                vulnerability_id,
                str(match.get("source") or "")[:40],
                _severity(match.get("severity")),
                _score(match.get("cvss_score")),
                str(match.get("cvss_vector") or "")[:200],
                str(match.get("description") or "")[:8000],
                str(match.get("fixed_version") or "")[:100],
                status_val,
                vex_val,
            ),
        )


def _upsert_vulnerability(db, key: str, match: dict) -> str:
    urls = [str(url).strip()[:2000] for url in (match.get("references") or []) if str(url or "").strip()]
    db.execute(
        """INSERT INTO vulnerabilities (
             id, vulnerability_key, source, severity, cvss_score, cvss_vector, description, reference_urls)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT (vulnerability_key) DO UPDATE
           SET source = CASE WHEN EXCLUDED.source <> '' THEN EXCLUDED.source ELSE vulnerabilities.source END,
               severity = CASE
                 WHEN EXCLUDED.severity <> 'UNKNOWN' THEN EXCLUDED.severity
                 ELSE vulnerabilities.severity END,
               cvss_score = CASE
                 WHEN EXCLUDED.cvss_score > 0 THEN EXCLUDED.cvss_score
                 ELSE vulnerabilities.cvss_score END,
               cvss_vector = CASE
                 WHEN EXCLUDED.cvss_vector <> '' THEN EXCLUDED.cvss_vector
                 ELSE vulnerabilities.cvss_vector END,
               description = CASE
                 WHEN EXCLUDED.description <> '' THEN EXCLUDED.description
                 ELSE vulnerabilities.description END,
               reference_urls = CASE
                 WHEN cardinality(EXCLUDED.reference_urls) > 0 THEN EXCLUDED.reference_urls
                 ELSE vulnerabilities.reference_urls END,
               updated_at = CURRENT_TIMESTAMP""",
        (
            str(uuid.uuid4()),
            key,
            str(match.get("source") or "")[:40],
            _severity(match.get("severity")),
            _score(match.get("cvss_score")),
            str(match.get("cvss_vector") or "")[:200],
            str(match.get("description") or "")[:8000],
            urls,
        ),
    )
    row = db.execute(
        "SELECT id FROM vulnerabilities WHERE vulnerability_key = ?",
        (key,),
    ).fetchone()
    if row is None:
        raise RuntimeError("vulnerability could not be saved")
    return _safe_get(row, "id", 0)


def _severity(value: Any) -> str:
    upper = str(value or "").strip().upper()
    if upper in _SEVERITIES:
        return upper
    return "UNKNOWN"


def _score(value: Any) -> float:
    try:
        score = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    if score < 0:
        return 0.0
    if score > 10:
        return 10.0
    return round(score, 1)


def _depth(raw: Any) -> int | None:
    if not isinstance(raw, dict) or "depth" not in raw or isinstance(raw.get("depth"), bool):
        return None
    try:
        depth = int(raw["depth"])
    except (TypeError, ValueError):
        return None
    if depth < 0:
        return None
    return depth
