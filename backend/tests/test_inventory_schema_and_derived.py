"""Tests for the 39 inventory field requirements, database schema, and derived calculations."""

import base64
import os
import psycopg
import pytest

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql://sbom:123456789@127.0.0.1:5432/sbom_test")
os.environ["CREDENTIAL_KEK"] = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
os.environ["DATABASE_URL"] = TEST_DB
os.environ["OBJECT_STORAGE_URL"] = "local://./data/test-objects"
os.environ["API_ALLOW_ORIGINS"] = "http://127.0.0.1:5173"
os.environ["VULN_PROVIDER"] = "osv"

from app.api import build  # noqa: E402
from app.core.inventory_derived import (  # noqa: E402
    derive_base_purl,
    classify_package,
    derive_code_origin,
    get_application_last_scan_date,
    calculate_package_usages,
    calculate_scan_change_events,
)
from app.core.validation import (  # noqa: E402
    is_valid_purl,
    detect_and_validate_sbom_format,
    validate_component_record,
    SbomFormatError,
)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Ensure clean schema and migrations up to 009 are applied."""
    conn = psycopg.connect(TEST_DB, autocommit=True)
    conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
    conn.execute("CREATE SCHEMA public")
    conn.execute("GRANT ALL ON SCHEMA public TO PUBLIC")
    conn.close()

    # Trigger migrations through app builder
    build()


def test_01_readable_id_generation_and_tenant_isolation():
    """Test APP-0001 sequence generation per organization."""
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        conn.execute("INSERT INTO organizations (id, name) VALUES ('org-a', 'Org A'), ('org-b', 'Org B') ON CONFLICT DO NOTHING")
        
        # Org A apps
        r1 = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'App 1', 'In-house') RETURNING readable_id"
        ).fetchone()[0]
        r2 = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'App 2', 'In-house') RETURNING readable_id"
        ).fetchone()[0]
        
        # Org B apps should start from APP-0001 as well (tenant isolated)
        r3 = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-b', 'App 1', 'In-house') RETURNING readable_id"
        ).fetchone()[0]
        
        assert r1 == "APP-0001"
        assert r2 == "APP-0002"
        assert r3 == "APP-0001"


def test_02_modules_references_applications():
    """Test module creates a child record under applications."""
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        app_id = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'PayFlow', 'In-house') RETURNING id"
        ).fetchone()[0]
        
        mod_id = conn.execute(
            """INSERT INTO modules (organization_id, application_id, name, path, programming_language, package_manager, module_type)
               VALUES ('org-a', %s, 'auth-service', '/services/auth', 'Python', 'pip', 'Microservice') RETURNING id""",
            (app_id,)
        ).fetchone()[0]
        
        assert mod_id is not None
        row = conn.execute("SELECT application_id, module_type, path FROM modules WHERE id = %s", (mod_id,)).fetchone()
        assert row[0] == app_id
        assert row[1] == "Microservice"
        assert row[2] == "/services/auth"


def test_03_application_constraints():
    """Test check constraints on applications (development_type, lifecycle_status)."""
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        conn.execute("INSERT INTO organizations (id, name) VALUES ('org-a', 'Org A') ON CONFLICT DO NOTHING")
        # Invalid development_type
        with pytest.raises(psycopg.Error):
            conn.execute(
                "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'Bad App', 'InvalidType')"
            )
        # OSS fork is no longer a valid development_type
        with pytest.raises(psycopg.Error):
            conn.execute(
                "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'Bad Fork App', 'OSS fork')"
            )
            
        # Invalid lifecycle_status
        with pytest.raises(psycopg.Error):
            conn.execute(
                "INSERT INTO applications (organization_id, name, development_type, lifecycle_status) VALUES ('org-a', 'Bad App 2', 'In-house', 'InvalidStatus')"
            )
            
        # Valid vendor application with vendor_name
        v_app = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type, vendor_name) VALUES ('org-a', 'Vendor App', 'Vendor', 'Acme Corp') RETURNING id, vendor_name"
        ).fetchone()
        assert v_app[1] == "Acme Corp"


def test_04_module_constraints():
    """Test check constraints on modules (module_type)."""
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        app_id = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'App For Module Test', 'In-house') RETURNING id"
        ).fetchone()[0]
        
        with pytest.raises(psycopg.Error):
            conn.execute(
                "INSERT INTO modules (application_id, name, module_type) VALUES (%s, 'bad-mod', 'NotAValidModuleType')",
                (app_id,)
            )


def test_05_scans_and_components_constraints():
    """Test scan trigger/generation_context and component classification/confidence constraints."""
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        app_id = conn.execute(
            "INSERT INTO applications (organization_id, name, development_type) VALUES ('org-a', 'Scan Test App', 'In-house') RETURNING id"
        ).fetchone()[0]
        
        # Valid scan
        scan_id = conn.execute(
            """INSERT INTO scans (organization_id, idempotency_key, catalog_project_id, source_type, trigger, generation_context, scan_status)
               VALUES ('org-a', 'idem-key-1', %s, 'zip', 'CI/CD', 'Source', 'completed') RETURNING id""",
            (app_id,)
        ).fetchone()[0]
        assert scan_id is not None
        
        # Invalid trigger
        with pytest.raises(psycopg.Error):
            conn.execute(
                "INSERT INTO scans (organization_id, catalog_project_id, trigger) VALUES ('org-a', %s, 'BadTrigger')",
                (app_id,)
            )

        # Create an SBOM snapshot for component testing
        sbom_id = conn.execute(
            """INSERT INTO sboms (organization_id, catalog_project_id, scan_id, bom_type, bom_format_version, scanner_name, scanner_version)
               VALUES ('org-a', %s, %s, 'cyclonedx', '1.5', 'syft', '1.0.0') RETURNING id""",
            (app_id, scan_id)
        ).fetchone()[0]

        # Valid component
        comp_id = conn.execute(
            """INSERT INTO sbom_components (sbom_id, name, version, detection_method, confidence, classification)
               VALUES (%s, 'express', '4.18.2', 'lockfile', 100, 'External') RETURNING id""",
            (sbom_id,)
        ).fetchone()[0]
        assert comp_id is not None

        # Invalid confidence (> 100)
        with pytest.raises(psycopg.Error):
            conn.execute(
                """INSERT INTO sbom_components (sbom_id, name, version, confidence)
                   VALUES (%s, 'bad-comp', '1.0', 101)""",
                (sbom_id,)
            )


def test_06_base_purl_derivation():
    """Test derive_base_purl with various ecosystems and PURL forms."""
    assert derive_base_purl("pkg:npm/left-pad@1.3.0") == "pkg:npm/left-pad"
    assert derive_base_purl("pkg:npm/%40angular/core@14.2.0") == "pkg:npm/%40angular/core"
    assert derive_base_purl("pkg:npm/@angular/core@14.2.0") == "pkg:npm/@angular/core"
    assert derive_base_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1") == "pkg:maven/org.apache.logging.log4j/log4j-core"
    assert derive_base_purl("pkg:golang/github.com/gin-gonic/gin@v1.9.0") == "pkg:golang/github.com/gin-gonic/gin"
    assert derive_base_purl("pkg:pypi/requests@2.28.1") == "pkg:pypi/requests"
    assert derive_base_purl("invalid-purl") == "invalid-purl"
    assert derive_base_purl(None) is None


def test_07_package_classification():
    """Test classify_package logic."""
    internal_prefixes = ["@myorg/", "com.mycompany."]
    vendor_packages = ["oracle-driver", "sap-connector"]

    assert classify_package("@myorg/shared-auth", internal_prefixes=internal_prefixes, vendor_prefixes=vendor_packages) == "Internal"
    assert classify_package("com.mycompany.service.core", internal_prefixes=internal_prefixes, vendor_prefixes=vendor_packages) == "Internal"
    assert classify_package("oracle-driver", internal_prefixes=internal_prefixes, vendor_prefixes=vendor_packages) == "Vendor"
    assert classify_package("express", internal_prefixes=internal_prefixes, vendor_prefixes=vendor_packages) == "External"
    assert classify_package("", internal_prefixes=internal_prefixes, vendor_prefixes=vendor_packages) == "Unknown"


def test_08_code_origin_derivation():
    """Test derive_code_origin maps application development_type correctly."""
    assert derive_code_origin("In-house") == "Internal"
    assert derive_code_origin("Outsourced") == "Outsourced"
    assert derive_code_origin("Vendor") == "Vendor"
    assert derive_code_origin("Unknown") == "Internal"


def test_09_purl_validation():
    """Test is_valid_purl regex."""
    assert is_valid_purl("pkg:npm/left-pad@1.3.0") is True
    assert is_valid_purl("pkg:npm/@angular/core@14.2.0") is True
    assert is_valid_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1") is True
    assert is_valid_purl("pkg:pypi/django@4.2") is True
    assert is_valid_purl("not-a-purl") is False
    assert is_valid_purl("") is False


def test_10_sbom_format_detection():
    """Test detect_and_validate_sbom_format discriminator."""
    cdx_payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "react", "version": "18.2.0"}]
    }
    fmt, ver = detect_and_validate_sbom_format(cdx_payload)
    assert fmt == "CycloneDX"
    assert ver == "1.5"

    spdx_payload = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SPDX-Test",
        "packages": [{"name": "lodash", "versionInfo": "4.17.21"}]
    }
    fmt, ver = detect_and_validate_sbom_format(spdx_payload)
    assert fmt == "SPDX"
    assert ver == "SPDX-2.3"

    with pytest.raises(SbomFormatError):
        detect_and_validate_sbom_format({"hello": "world"})


def test_11_component_validation():
    """Test validate_component_record checks."""
    valid_record = {
        "name": "log4j-core",
        "version": "2.17.1",
        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
    }
    errs = validate_component_record(valid_record)
    assert len(errs) == 0

    invalid_record = {
        "name": "",
        "version": "1.0.0",
        "purl": "not-a-purl"
    }
    errs = validate_component_record(invalid_record, strict=True)
    assert len(errs) == 2


def test_12_change_events_calculation():
    """Test calculate_scan_change_events computes added, upgraded, downgraded, removed."""
    base_components = [
        {"name": "lib-a", "version": "1.0.0", "purl": "pkg:npm/lib-a@1.0.0"},
        {"name": "lib-b", "version": "1.0.0", "purl": "pkg:npm/lib-b@1.0.0"},
        {"name": "lib-c", "version": "2.0.0", "purl": "pkg:npm/lib-c@2.0.0"},
    ]
    new_components = [
        {"name": "lib-a", "version": "1.1.0", "purl": "pkg:npm/lib-a@1.1.0"},  # Upgraded
        {"name": "lib-b", "version": "1.0.0", "purl": "pkg:npm/lib-b@1.0.0"},  # Unchanged
        {"name": "lib-d", "version": "1.0.0", "purl": "pkg:npm/lib-d@1.0.0"},  # Added
        # lib-c is Removed
    ]
    changes = calculate_scan_change_events(base_components, new_components)
    assert len(changes["added"]) == 1
    assert changes["added"][0]["name"] == "lib-d"
    assert len(changes["upgraded"]) == 1
    assert changes["upgraded"][0]["name"] == "lib-a"
    assert changes["upgraded"][0]["event"] == "Upgraded"
    assert len(changes["removed"]) == 1
    assert changes["removed"][0]["name"] == "lib-c"
