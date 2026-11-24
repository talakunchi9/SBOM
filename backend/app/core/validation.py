"""Validation guards for SBOM documents, Package URLs (PURLs), and inventory entities.

Implements:
- Gate 1: SBOM Format Check (SG-04) - CycloneDX (1.3 to 1.6) and SPDX (2.x)
- Gate 2: Required Fields Check (SG-06) - Component name and version
- Gate 3: Package URL (PURL) Syntax Check (SG-07) - conforming to purl-spec with scoped npm support
"""

from __future__ import annotations

import json
import re
from typing import Any, Tuple

# Official purl-spec pattern with support for scoped npm (@scope/name) and percent-encoded (%40scope/name)
PURL_REGEX = re.compile(
    r"^pkg:(?P<type>[a-zA-Z][a-zA-Z0-9_.+-]*)"
    r"(?:/(?P<namespace>(?:@[a-zA-Z0-9_.-]+)|(?:%40[a-zA-Z0-9_.-]+)|(?:[^@?#/]+(?:/[^@?#/]+)*)))?"
    r"/(?P<name>[^@?#/]+)"
    r"(?:@(?P<version>[^?#]+))?"
    r"(?:\?(?P<qualifiers>[^#]+))?"
    r"(?:#(?P<subpath>.*))?$"
)


class SbomFormatError(Exception):
    def __init__(self, message: str, code: str = "INVALID_SBOM_FORMAT", status: int = 400):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status = status


def is_valid_purl(purl: str | None) -> bool:
    """Validate Package URL string against official purl-spec regex.
    
    Accepts:
    - pkg:npm/lodash@4.17.21
    - pkg:npm/@angular/core@14.2.0 (raw @ in scope)
    - pkg:npm/%40angular/core@14.2.0 (percent-encoded @ in scope)
    - pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    - pkg:golang/github.com/gin-gonic/gin@v1.9.0
    - pkg:pypi/requests@2.28.1
    - pkg:cargo/serde@1.0.188
    - pkg:nuget/Newtonsoft.Json@13.0.1
    """
    if not purl or not isinstance(purl, str):
        return False
    match = PURL_REGEX.match(purl.strip())
    if not match:
        return False
    parts = match.groupdict()
    return bool(parts.get("type") and parts.get("name"))


def detect_and_validate_sbom_format(content: bytes | dict | str) -> Tuple[str, str]:
    """Inspect raw upload bytes or parsed dictionary and validate SBOM schema headers.
    
    Returns:
        (format_name, version) e.g. ("CycloneDX", "1.5") or ("SPDX", "SPDX-2.3")
    Raises:
        SbomFormatError if document is not a recognized SBOM format.
    """
    if isinstance(content, dict):
        data = content
    elif isinstance(content, (bytes, bytearray, str)):
        raw_text = content.decode("utf-8", "replace") if isinstance(content, (bytes, bytearray)) else content
        stripped = raw_text.strip()
        if stripped.startswith("<") or "<?xml" in stripped[:100]:
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(raw_text)
                local_root = root.tag.split("}")[-1] if "}" in root.tag else root.tag
                if local_root.lower() == "bom":
                    spec_ver = root.attrib.get("version", "1.5")
                    if "cyclonedx.org/schema/bom/" in root.tag:
                        xmlns_url = root.tag.split("}")[0].lstrip("{")
                        spec_ver = xmlns_url.split("/")[-1]
                    return "CycloneDX", str(spec_ver)
            except Exception:
                pass
        try:
            data = json.loads(raw_text)
        except Exception as exc:
            raise SbomFormatError(f"File is not valid JSON or CycloneDX XML: {str(exc)}", "INVALID_FORMAT", 400)
    else:
        raise SbomFormatError("Payload must be bytes, string, or dictionary", "INVALID_PAYLOAD", 400)

    if not isinstance(data, dict):
        raise SbomFormatError("Root of SBOM JSON must be an object", "INVALID_STRUCTURE", 400)

    # 1. CycloneDX Detection
    if data.get("bomFormat") == "CycloneDX" or (
        data.get("components") and (data.get("specVersion") or data.get("metadata"))
    ):
        spec_ver = str(data.get("specVersion", "1.5"))
        if spec_ver not in ("1.2", "1.3", "1.4", "1.5", "1.6"):
            raise SbomFormatError(
                f"Unsupported CycloneDX specification version: '{spec_ver}'. Supported: 1.3-1.6",
                "UNSUPPORTED_VERSION",
                400,
            )
        return "CycloneDX", spec_ver

    # 2. SPDX Detection
    if data.get("spdxVersion") or ("packages" in data and data.get("SPDXID")):
        spdx_ver = str(data.get("spdxVersion", "SPDX-2.3"))
        if not spdx_ver.startswith("SPDX-2"):
            raise SbomFormatError(
                f"Unsupported SPDX version: '{spdx_ver}'. Only SPDX 2.x JSON is supported.",
                "UNSUPPORTED_VERSION",
                400,
            )
        return "SPDX", spdx_ver

    raise SbomFormatError(
        "Unrecognized SBOM format. Uploaded file must be a valid CycloneDX or SPDX JSON document.",
        "INVALID_SBOM_FORMAT",
        400,
    )


def validate_component_record(comp: dict[str, Any], index: int = 0, strict: bool = False) -> list[dict[str, Any]]:
    """Validate component required fields (name and version).
    
    In strict mode (file upload), missing version is rejected.
    In permissive mode (code scan), missing version should be marked 'Version unknown'.
    """
    errors: list[dict[str, Any]] = []
    name = (comp.get("name") or "").strip()
    version = str(comp.get("version") or comp.get("versionInfo") or "").strip()

    if not name:
        errors.append({"row": index, "field": "name", "error": "Component name is mandatory and cannot be blank."})

    if not version or version.upper() in ("NONE", "NOASSERTION", "UNKNOWN", "—"):
        if strict:
            errors.append({"row": index, "field": "version", "error": "Component version is mandatory in strict mode."})

    purl = comp.get("purl") or comp.get("package_url")
    if purl and not is_valid_purl(purl):
        errors.append({"row": index, "field": "purl", "error": f"Invalid package URL: {purl}"})

    return errors
