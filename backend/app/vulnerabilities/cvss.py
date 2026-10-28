"""CVSS Base Score calculation and vector parsing for CVSS v3.1, v3.0, and fallbacks."""

from __future__ import annotations

import math
import re
from typing import Any

CVSS3_VECTOR_RE = re.compile(r"CVSS:3\.[01]/[A-Za-z0-9:/._-]+", re.IGNORECASE)
CVSS4_VECTOR_RE = re.compile(r"CVSS:4\.0/[A-Za-z0-9:/._-]+", re.IGNORECASE)


def calculate_cvss3_score(vector: str) -> float:
    """Calculate the exact FIRST CVSS v3.1 / v3.0 Base Score from a vector string.

    Returns float rounded to 1 decimal place using the standard CVSS 3.1 roundup function.
    Returns 0.0 if the vector cannot be parsed or required metrics are missing.
    """
    if not vector:
        return 0.0

    parts: dict[str, str] = {}
    for segment in vector.split("/"):
        if ":" in segment:
            k, v = segment.split(":", 1)
            parts[k.strip().upper()] = v.strip().upper()

    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    if not required.issubset(parts.keys()):
        return 0.0

    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}
    scope_changed = parts["S"] == "C"

    if scope_changed:
        pr_map = {"N": 0.85, "L": 0.68, "H": 0.50}
    else:
        pr_map = {"N": 0.85, "L": 0.62, "H": 0.27}

    c_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    i_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    a_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    try:
        av = av_map[parts["AV"]]
        ac = ac_map[parts["AC"]]
        pr = pr_map[parts["PR"]]
        ui = ui_map[parts["UI"]]
        c = c_map[parts["C"]]
        i = i_map[parts["I"]]
        a = a_map[parts["A"]]
    except KeyError:
        return 0.0

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw_score = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw_score = min(impact + exploitability, 10.0)

    # Standard FIRST CVSS v3.1 Roundup specification:
    int_input = round(raw_score * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def score_from_severity(severity: str) -> float:
    """Return a standard baseline CVSS score for a given severity rating."""
    sev = (severity or "").strip().upper()
    if sev == "CRITICAL":
        return 9.5
    if sev == "HIGH":
        return 7.5
    if sev in ("MEDIUM", "MODERATE"):
        return 5.5
    if sev == "LOW":
        return 2.5
    return 0.0


def severity_from_score(score: float) -> str:
    """Return standard CVSS v3.1 qualitative rating from a base score."""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "UNKNOWN"


def extract_cvss_from_osv(vuln_doc: dict[str, Any]) -> tuple[float, str, str]:
    """Extract (score, vector, severity) from an OSV vulnerability record.

    Inspects:
    1. vuln_doc['severity'] (list of {type: 'CVSS_V3'|'CVSS_V4', score: 'CVSS:3.1/...'})
    2. vuln_doc['database_specific']['severity']
    3. vuln_doc['database_specific']['cvss']
    """
    vector = ""
    score = 0.0
    severity = ""

    # Check severity array in OSV doc
    sev_list = vuln_doc.get("severity") or []
    if isinstance(sev_list, list):
        # Look for CVSS_V3 first
        for item in sev_list:
            if not isinstance(item, dict):
                continue
            stype = str(item.get("type") or "").upper()
            raw_score = str(item.get("score") or "").strip()
            if "CVSS_V3" in stype or raw_score.startswith(("CVSS:3.1", "CVSS:3.0")):
                vector = raw_score
                score = calculate_cvss3_score(vector)
                if score > 0:
                    severity = severity_from_score(score)
                    break
        # If no CVSS_V3, check CVSS_V4 or others
        if not vector:
            for item in sev_list:
                if not isinstance(item, dict):
                    continue
                raw_score = str(item.get("score") or "").strip()
                if raw_score.startswith("CVSS:"):
                    vector = raw_score
                    # Try to parse if it contains CVSS 3 metrics or estimate
                    if "AV:" in vector and "AC:" in vector:
                        score = calculate_cvss3_score(vector)
                    break

    # Check database_specific
    db_spec = vuln_doc.get("database_specific") or {}
    if isinstance(db_spec, dict):
        raw_sev = str(db_spec.get("severity") or "").strip().upper()
        if raw_sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
            if raw_sev == "MODERATE":
                raw_sev = "MEDIUM"
            if not severity:
                severity = raw_sev

        # Sometimes database_specific has cvss dict or score
        cvss_info = db_spec.get("cvss")
        if isinstance(cvss_info, dict):
            if not score and cvss_info.get("score"):
                try:
                    score = float(cvss_info["score"])
                except (ValueError, TypeError):
                    pass
            if not vector and cvss_info.get("vectorString"):
                vector = str(cvss_info["vectorString"])
        elif isinstance(cvss_info, (int, float)) and not score:
            score = float(cvss_info)

    # If score is still 0 but we have severity, provide baseline
    if score <= 0 and severity and severity != "UNKNOWN":
        score = score_from_severity(severity)

    # If severity is still empty but score > 0, calculate severity
    if not severity and score > 0:
        severity = severity_from_score(score)

    return score, vector, severity or "UNKNOWN"
