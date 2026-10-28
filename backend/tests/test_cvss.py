"""Tests for CVSS Base Score calculation and OSV/MITRE vulnerability enrichment."""

from app.vulnerabilities.cvss import (
    calculate_cvss3_score,
    extract_cvss_from_osv,
    score_from_severity,
    severity_from_score,
)
from app.vulnerabilities.provider import _first_cvss, _parse_mitre


def test_cvss3_score_calculation():
    # Requests CVE-2018-18074
    assert calculate_cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    # PyYAML CVE-2020-14343
    assert calculate_cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    # Django CVE-2020-13596 (scope changed)
    assert calculate_cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    # Django CVE-2020-13254 (high attack complexity)
    assert calculate_cvss3_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N") == 5.9
    # Django CVE-2021-33203 (high privileges required)
    assert calculate_cvss3_score("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N") == 4.9
    # Invalid / empty vectors
    assert calculate_cvss3_score("") == 0.0
    assert calculate_cvss3_score("invalid-vector") == 0.0


def test_severity_from_score():
    assert severity_from_score(9.8) == "CRITICAL"
    assert severity_from_score(7.5) == "HIGH"
    assert severity_from_score(5.9) == "MEDIUM"
    assert severity_from_score(3.1) == "LOW"
    assert severity_from_score(0.0) == "UNKNOWN"


def test_score_from_severity():
    assert score_from_severity("CRITICAL") == 9.5
    assert score_from_severity("HIGH") == 7.5
    assert score_from_severity("MEDIUM") == 5.5
    assert score_from_severity("MODERATE") == 5.5
    assert score_from_severity("LOW") == 2.5
    assert score_from_severity("UNKNOWN") == 0.0


def test_extract_cvss_from_osv():
    # Advisory with CVSS_V3 severity list
    doc1 = {
        "id": "GHSA-x84v-xcm2-53pg",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
        "database_specific": {"severity": "HIGH"},
    }
    score1, vec1, sev1 = extract_cvss_from_osv(doc1)
    assert score1 == 7.5
    assert vec1 == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert sev1 == "HIGH"

    # Advisory with database_specific only
    doc2 = {
        "id": "GHSA-test-123",
        "database_specific": {"severity": "MODERATE"},
    }
    score2, vec2, sev2 = extract_cvss_from_osv(doc2)
    assert score2 == 5.5
    assert sev2 == "MEDIUM"


def test_parse_mitre_with_and_without_metrics():
    # MITRE record without metrics
    doc_no_metrics = {
        "cveMetadata": {"cveId": "CVE-2018-18074", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Requests package vulnerability."}],
                "references": [{"url": "https://example.com"}],
            }
        },
    }
    parsed = _parse_mitre(doc_no_metrics)
    assert parsed is not None
    assert parsed["id"] == "CVE-2018-18074"
    assert parsed["cvss_score"] == 0.0

    # MITRE record with metrics
    doc_with_metrics = {
        "cveMetadata": {"cveId": "CVE-2024-21626", "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "runc vulnerability."}],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "baseScore": 8.6,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
                        }
                    }
                ],
            }
        },
    }
    parsed2 = _parse_mitre(doc_with_metrics)
    assert parsed2 is not None
    assert parsed2["cvss_score"] == 8.6
    assert parsed2["severity"] == "HIGH"
