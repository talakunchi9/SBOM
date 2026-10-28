"""OSV package lookup plus MITRE CVE records."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

import httpx

from app.core.metrics import METRICS
from app.vulnerabilities.cvss import (
    calculate_cvss3_score,
    extract_cvss_from_osv,
    score_from_severity,
    severity_from_score,
)

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
ADV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
OSV_ECO = {
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "go": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "rubygems": "RubyGems",
    "pub": "Pub",
    "hex": "Hex",
    "swift": "SwiftURL",
    "conan": "ConanCenter",
    "opam": "opam",
    "cran": "CRAN",
    "hackage": "Hackage",
}
MAX_ADVISORIES = 2000
MAX_CVE = 250


class VulnProvider:
    def __init__(self, kind: str, timeout: float, mitre_base: str) -> None:
        self.kind = kind.lower()
        self.timeout = timeout
        self.mitre_base = mitre_base.rstrip("/")
        self._cache: dict[str, dict] = {}
        self._osv_cache: dict[str, tuple[float, str, str]] = {}

    def name(self) -> str:
        return "mitre" if self.kind == "mitre" else "osv"

    def correlate(self, snap: dict) -> None:
        if self.kind == "osv":
            self._correlate_osv(snap)
        else:
            self._correlate_mitre(snap)

    def _targets(self, snap: dict) -> list[tuple[int, dict]]:
        out = []
        for index, comp in enumerate(snap.get("components") or []):
            eco = OSV_ECO.get(str(comp.get("ecosystem") or "").lower())
            if not eco or not comp.get("name"):
                continue
            version = query_version(str(comp.get("version") or ""))
            query = {"package": {"name": comp["name"], "ecosystem": eco}}
            if version:
                query["version"] = version
            out.append((index, query))
        return out

    def _query_batch(self, queries: list[dict]) -> list[dict]:
        results = []
        with httpx.Client(timeout=self.timeout) as client:
            for start in range(0, len(queries), 500):
                chunk = queries[start : start + 500]
                response = client.post("https://api.osv.dev/v1/querybatch", json={"queries": chunk})
                response.raise_for_status()
                results.extend(response.json().get("results") or [])
        return results

    def _correlate_osv(self, snap: dict) -> None:
        targets = self._targets(snap)
        if not targets:
            return
        results = self._query_batch([item for _, item in targets])
        matches = []
        raw_items = []
        for offset, result in enumerate(results):
            if offset >= len(targets):
                break
            index, _query = targets[offset]
            comp = snap["components"][index]
            for vuln in _result_vulns(result, _query):
                raw_items.append((comp, vuln))

        advisory_ids = [v.get("id") for _, v in raw_items if v.get("id")]
        details = self._advisories(advisory_ids[:MAX_ADVISORIES])

        for comp, vuln in raw_items:
            vid = vuln.get("id") or ""
            detail = details.get(vid) or vuln
            score, vector, severity = extract_cvss_from_osv(detail)
            fixed = _fixed_for(detail, comp.get("name") or "")
            summary = detail.get("summary") or detail.get("details") or ""
            record = {
                "component_id": comp["id"],
                "vulnerability_id": vid,
                "source": "osv",
                "severity": severity,
                "cvss_score": score,
                "cvss_vector": vector,
                "description": summary,
                "fixed_version": fixed,
            }
            matches.append(record)
            _attach(comp, record, "osv")
            METRICS.add("vulnerabilities_discover")
        snap.setdefault("raw_metadata", {})
        snap["raw_metadata"]["vulnerability_matches"] = matches
        snap["raw_metadata"]["vulnerability_provider"] = "osv"

    def _correlate_mitre(self, snap: dict) -> None:
        targets = self._targets(snap)
        if not targets:
            return
        results = self._query_batch([item for _, item in targets])
        candidates = []
        pending = []
        seen = set()
        for offset, result in enumerate(results):
            if offset >= len(targets):
                break
            index, _query = targets[offset]
            comp_id = snap["components"][index]["id"]
            for vuln in _result_vulns(result, _query):
                ids = [vuln.get("id") or "", *(vuln.get("aliases") or [])]
                cves, advisory = _split_ids(ids)
                for cve in cves:
                    _add_candidate(
                        candidates,
                        seen,
                        comp_id,
                        {
                            "index": index,
                            "cve": cve,
                            "severity": "",
                            "cvss_score": 0.0,
                            "cvss_vector": "",
                            "summary": "",
                            "fixed": "",
                        },
                    )
                if advisory:
                    pending.append((index, advisory))
        details = self._advisories([item[1] for item in pending][:MAX_ADVISORIES])
        for index, advisory_id in pending:
            detail = details.get(advisory_id)
            if not detail:
                continue
            comp = snap["components"][index]
            score, vector, severity = extract_cvss_from_osv(detail)
            fixed = _fixed_for(detail, comp.get("name") or "")
            summary = detail.get("summary") or ""
            for raw_id in [detail.get("id") or "", *(detail.get("aliases") or [])]:
                cve = str(raw_id).strip().upper()
                if not CVE_RE.match(cve):
                    continue
                _add_candidate(
                    candidates,
                    seen,
                    comp["id"],
                    {
                        "index": index,
                        "cve": cve,
                        "severity": severity,
                        "cvss_score": score,
                        "cvss_vector": vector,
                        "summary": summary,
                        "fixed": fixed,
                    },
                )
        if not candidates:
            return
        fetched = self._mitre_records([item["cve"] for item in candidates])

        # Fetch OSV records for candidates where MITRE and advisory didn't provide CVSS
        cves_needing_osv = [
            cand["cve"]
            for cand in candidates
            if (not fetched.get(cand["cve"]) or float(fetched[cand["cve"]].get("cvss_score") or 0.0) <= 0.0)
            and float(cand.get("cvss_score") or 0.0) <= 0.0
        ]
        osv_cves = self._osv_records(cves_needing_osv) if cves_needing_osv else {}

        matches = []
        for cand in candidates:
            finding = fetched.get(cand["cve"])
            source = "mitre" if finding else "osv"
            if not finding:
                finding = {
                    "id": cand["cve"],
                    "severity": cand.get("severity") or "UNKNOWN",
                    "cvss_score": cand.get("cvss_score") or 0.0,
                    "cvss_vector": cand.get("cvss_vector") or "",
                    "description": cand.get("summary") or "",
                    "fixed": cand.get("fixed") or "",
                    "references": [],
                }
            else:
                if not finding.get("severity") or finding["severity"] == "UNKNOWN":
                    finding["severity"] = cand.get("severity") or finding.get("severity") or "UNKNOWN"
                if not finding.get("fixed"):
                    finding["fixed"] = cand.get("fixed") or ""
                if not finding.get("description"):
                    finding["description"] = cand.get("summary") or ""
                if (not finding.get("cvss_score") or finding["cvss_score"] <= 0) and cand.get("cvss_score"):
                    finding["cvss_score"] = cand["cvss_score"]
                if not finding.get("cvss_vector") and cand.get("cvss_vector"):
                    finding["cvss_vector"] = cand["cvss_vector"]

            # If still missing CVSS score, enrich from OSV lookup
            if (not finding.get("cvss_score") or finding["cvss_score"] <= 0) and cand["cve"] in osv_cves:
                osv_score, osv_vector, osv_sev = osv_cves[cand["cve"]]
                if osv_score > 0:
                    finding["cvss_score"] = osv_score
                if osv_vector and not finding.get("cvss_vector"):
                    finding["cvss_vector"] = osv_vector
                if (not finding.get("severity") or finding["severity"] == "UNKNOWN") and osv_sev:
                    finding["severity"] = osv_sev

            score_val = float(finding.get("cvss_score") or 0.0)
            if score_val > 0 and (not finding.get("severity") or finding["severity"] == "UNKNOWN"):
                finding["severity"] = severity_from_score(score_val)
            elif score_val <= 0 and finding.get("severity") and finding["severity"] != "UNKNOWN":
                finding["cvss_score"] = score_from_severity(finding["severity"])

            if not finding.get("severity"):
                finding["severity"] = "UNKNOWN"
            comp = snap["components"][cand["index"]]
            record = {
                "component_id": comp["id"],
                "vulnerability_id": finding["id"],
                "source": source,
                "severity": finding["severity"],
                "cvss_score": finding.get("cvss_score") or 0.0,
                "cvss_vector": finding.get("cvss_vector") or "",
                "description": finding.get("description") or "",
                "fixed_version": finding.get("fixed") or "",
            }
            if finding.get("references"):
                record["references"] = finding["references"]
            matches.append(record)
            _attach(comp, record, source)
            METRICS.add("vulnerabilities_discover")
        snap.setdefault("raw_metadata", {})
        snap["raw_metadata"]["vulnerability_matches"] = matches
        snap["raw_metadata"]["vulnerability_provider"] = "mitre"

    def _advisories(self, ids: list[str]) -> dict[str, dict]:
        unique = []
        seen = set()
        for item in ids:
            if item in seen or not ADV_RE.match(item):
                continue
            seen.add(item)
            unique.append(item)
            if len(unique) >= MAX_ADVISORIES:
                break
        out: dict[str, dict] = {}
        if not unique:
            return out

        def fetch(adv_id: str) -> tuple[str, dict | None]:
            url = "https://api.osv.dev/v1/vulns/" + quote(adv_id, safe="")
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.get(url, headers={"Accept": "application/json"})
                if response.status_code // 100 != 2:
                    return adv_id, None
                return adv_id, response.json()
            except httpx.HTTPError:
                return adv_id, None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch, adv_id) for adv_id in unique]
            for future in as_completed(futures):
                adv_id, body = future.result()
                if body:
                    out[adv_id] = body
        return out

    def _osv_records(self, cve_ids: list[str]) -> dict[str, tuple[float, str, str]]:
        unique = []
        seen = set()
        for cve in cve_ids:
            if cve in seen or not CVE_RE.match(cve):
                continue
            seen.add(cve)
            unique.append(cve)
            if len(unique) >= MAX_CVE:
                break
        out: dict[str, tuple[float, str, str]] = {}
        if not unique:
            return out

        def fetch(cve: str) -> tuple[str, tuple[float, str, str] | None]:
            if cve in self._osv_cache:
                return cve, self._osv_cache[cve]
            url = "https://api.osv.dev/v1/vulns/" + quote(cve, safe="")
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.get(url, headers={"Accept": "application/json"})
                if response.status_code // 100 != 2:
                    return cve, None
                res = extract_cvss_from_osv(response.json())
                self._osv_cache[cve] = res
                return cve, res
            except (httpx.HTTPError, ValueError):
                return cve, None

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch, cve) for cve in unique]
            for future in as_completed(futures):
                cve, res = future.result()
                if res:
                    out[cve] = res
        return out

    def _mitre_records(self, cve_ids: list[str]) -> dict[str, dict]:
        unique = []
        seen = set()
        for cve in cve_ids:
            if cve in seen or not CVE_RE.match(cve):
                continue
            seen.add(cve)
            unique.append(cve)
            if len(unique) >= MAX_CVE:
                break
        out: dict[str, dict] = {}

        def fetch(cve: str) -> tuple[str, dict | None]:
            if cve in self._cache:
                return cve, self._cache[cve]
            url = self.mitre_base + "/cve/" + quote(cve, safe="")
            try:
                with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                    response = client.get(url, headers={"Accept": "application/json", "User-Agent": "bom-engine"})
                if response.status_code == 404 or response.status_code // 100 != 2:
                    return cve, None
                finding = _parse_mitre(response.json())
            except (httpx.HTTPError, ValueError):
                return cve, None
            if finding:
                self._cache[cve] = finding
            return cve, finding

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(fetch, cve) for cve in unique]
            for future in as_completed(futures):
                cve, finding = future.result()
                if finding:
                    out[cve] = finding
        return out


_VERSION = re.compile(r"v?\d+(?:\.\d+){0,6}(?:[-+][0-9A-Za-z.-]+)?")


def _result_vulns(result: dict, query: dict) -> list:
    vulns = result.get("vulns") or []
    if query.get("version"):
        return vulns
    return vulns[:25]


def query_version(raw: str) -> str:
    """Turn a manifest constraint into one version the OSV query can match.

    A lone manifest often stores a range (`^1.2.5`) or a single number (`1`).
    OSV then supplies CVE ids, and the MITRE API supplies the record.
    """
    text = (raw or "").strip()
    if not text or text in {"*", "latest", "x"}:
        return ""
    lower = text.lower()
    if lower.startswith(("git+", "git:", "git@", "file:", "http:", "https:", "github:", "workspace:", "link:", "portal:")):
        return ""
    if "://" in text:
        return ""
    if "||" in text:
        text = text.split("||", 1)[0].strip()
    if " - " in text:
        text = text.split(" - ", 1)[0].strip()
    if text[:1] in "[(":
        text = text[1:].split(",", 1)[0].rstrip("])")
    for prefix in ("~>", ">=", "<=", "==", "!=", "~=", ">", "<", "^", "~", "="):
        if text.startswith(prefix):
            text = text[len(prefix) :].strip()
            break
    text = text.replace(".x", ".0").replace(".*", ".0").strip()
    match = _VERSION.search(text)
    if not match:
        return ""
    return match.group(0)


def _add_candidate(out: list, seen: set, component_id: str, cand: dict) -> None:
    key = component_id + "|" + cand["cve"]
    if key in seen:
        for existing in out:
            if existing["index"] == cand["index"] and existing["cve"] == cand["cve"]:
                if (not existing.get("severity") or existing["severity"] == "UNKNOWN") and cand.get("severity"):
                    existing["severity"] = cand["severity"]
                if (not existing.get("cvss_score") or existing["cvss_score"] <= 0) and cand.get("cvss_score"):
                    existing["cvss_score"] = cand["cvss_score"]
                if not existing.get("cvss_vector") and cand.get("cvss_vector"):
                    existing["cvss_vector"] = cand["cvss_vector"]
                if not existing.get("summary") and cand.get("summary"):
                    existing["summary"] = cand["summary"]
                if not existing.get("fixed") and cand.get("fixed"):
                    existing["fixed"] = cand["fixed"]
                break
        return
    seen.add(key)
    out.append(cand)


def _split_ids(ids: list[str]) -> tuple[list[str], str]:
    cves = []
    advisory = ""
    for raw in ids:
        text = (raw or "").strip()
        upper = text.upper()
        if CVE_RE.match(upper):
            cves.append(upper)
        elif not advisory and ADV_RE.match(text):
            advisory = text
    return cves, advisory


def _advisory_severity(adv: dict) -> str:
    raw = ((adv.get("database_specific") or {}).get("severity") or "")
    mapping = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get(str(raw).strip().upper(), "")


def _fixed_for(adv: dict, name: str) -> str:
    fallback = ""
    for affected in adv.get("affected") or []:
        fixed = ""
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    val = str(event["fixed"]).strip()
                    if val and val not in {"*", "None", "unknown"}:
                        fixed = val
        if not fixed:
            continue
        pkg = ((affected.get("package") or {}).get("name") or "")
        if pkg.lower() == name.lower():
            return fixed
        if not fallback:
            fallback = fixed
    return fallback


def _parse_mitre(doc: dict) -> dict | None:
    meta = doc.get("cveMetadata") or {}
    if str(meta.get("state") or "").upper() != "PUBLISHED":
        return None
    finding = {
        "id": meta.get("cveId") or "",
        "severity": "",
        "cvss_score": 0.0,
        "cvss_vector": "",
        "description": "",
        "fixed": "",
        "references": [],
    }
    containers = doc.get("containers") or {}
    blocks = list(containers.get("adp") or []) + [containers.get("cna") or {}]
    for block in blocks:
        if not finding["description"]:
            finding["description"] = _english(block.get("descriptions") or [])
        if not finding["cvss_vector"] or finding["cvss_score"] <= 0:
            metric = _first_cvss(block.get("metrics") or [])
            if metric:
                vector = str(metric.get("vectorString") or "").strip()
                score = 0.0
                if metric.get("baseScore") is not None:
                    try:
                        score = float(metric["baseScore"])
                    except (ValueError, TypeError):
                        pass
                if not score and vector:
                    score = calculate_cvss3_score(vector)
                if score > 0:
                    finding["cvss_score"] = score
                if vector:
                    finding["cvss_vector"] = vector
                sev = _severity(metric.get("baseSeverity") or "")
                if sev != "UNKNOWN":
                    finding["severity"] = sev
        if not finding["fixed"]:
            finding["fixed"] = _fixed_version(block)
        for ref in block.get("references") or []:
            if ref.get("url"):
                finding["references"].append(ref["url"])
    if finding["cvss_score"] > 0 and (not finding["severity"] or finding["severity"] == "UNKNOWN"):
        finding["severity"] = severity_from_score(finding["cvss_score"])
    elif finding["cvss_score"] <= 0 and finding["cvss_vector"]:
        finding["cvss_score"] = calculate_cvss3_score(finding["cvss_vector"])
    if not finding["severity"]:
        finding["severity"] = "UNKNOWN"
    return finding


def _english(items: list) -> str:
    for item in items:
        if str(item.get("lang") or "").lower() == "en" and item.get("value"):
            return item["value"]
    return items[0].get("value") if items else ""


def _first_cvss(metrics: list) -> dict | None:
    for metric in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            block = metric.get(key)
            if isinstance(block, dict) and (block.get("vectorString") or block.get("baseScore")):
                return block
    return None


def _fixed_version(block: dict) -> str:
    for affected in block.get("affected") or []:
        for version in affected.get("versions") or []:
            lt = str(version.get("lessThan") or "").strip()
            if lt and lt not in {"*", "None", "unknown"}:
                return lt
            lte = str(version.get("lessThanOrEqual") or "").strip()
            if lte and lte not in {"*", "None", "unknown"}:
                return lte
            text = str(version.get("version") or "").strip()
            if text.lower().startswith("prior to "):
                val = text[len("prior to ") :].strip()
                if val and val not in {"*", "None", "unknown"}:
                    return val
    return ""


def _severity(value: str) -> str:
    upper = value.strip().upper()
    if upper in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return upper
    return "UNKNOWN"


def _attach(comp: dict, record: dict, source: str) -> None:
    comp.setdefault("raw", {})
    comp["raw"].setdefault("vulnerabilities", []).append(
        {
            "id": record["vulnerability_id"],
            "severity": record.get("severity") or "UNKNOWN",
            "cvss": float(record.get("cvss_score") or 0.0),
            "cvss_vector": record.get("cvss_vector") or "",
            "fixed_version": record.get("fixed_version") or "",
            "source": source,
        }
    )
