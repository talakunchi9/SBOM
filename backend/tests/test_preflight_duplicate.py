"""Tests for the preflight duplicate check endpoint."""

import base64
import os
import psycopg
import pytest
from fastapi.testclient import TestClient

TEST_DB = os.environ.get("TEST_DATABASE_URL", "postgresql://sbom:123456789@127.0.0.1:5432/sbom_test")
os.environ["CREDENTIAL_KEK"] = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
os.environ["DATABASE_URL"] = TEST_DB
os.environ["OBJECT_STORAGE_URL"] = "local://./data/test-objects"
os.environ["API_ALLOW_ORIGINS"] = "http://127.0.0.1:5173"
os.environ["VULN_PROVIDER"] = "osv"

from app.api import build  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Ensure clean schema and migrations up to 009 are applied."""
    conn = psycopg.connect(TEST_DB, autocommit=True)
    conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
    conn.execute("CREATE SCHEMA public")
    conn.execute("GRANT ALL ON SCHEMA public TO PUBLIC")
    conn.close()
    build()


def test_preflight_no_duplicate_when_empty():
    client = TestClient(build())
    headers = {"X-Organization-Id": "default"}
    
    res = client.post(
        "/api/v1/scans/preflight-check",
        headers=headers,
        data={
            "application_name": "PayFlow",
            "module_name": "auth-service",
            "version": "v1.0.0",
        },
    )
    assert res.status_code == 200
    body = res.json()["data"]
    assert body["is_duplicate"] is False


def test_preflight_detects_existing_scan():
    client = TestClient(build())
    headers = {"X-Organization-Id": "default"}
    
    # 1. First, create a local scan
    manifest_bytes = b'{"name": "test-pkg", "version": "1.0.0"}'
    res_scan = client.post(
        "/api/v1/scans/local",
        headers=headers,
        data={
            "project_name": "PayFlow",
            "application_name": "auth-service",
            "version": "v1.0.0",
            "business_owner": "Finance Team",
            "technical_owner": "Alice",
            "development_type": "In-house",
            "module_type": "Microservice",
        },
        files={"file": ("package.json", manifest_bytes, "application/json")},
    )
    assert res_scan.status_code == 202
    scan_id = res_scan.json()["data"]["scan_id"]

    # Mark the scan completed in DB
    with psycopg.connect(TEST_DB, autocommit=True) as conn:
        conn.execute(
            "UPDATE scans SET scan_status = 'COMPLETED', completed_at = NOW() WHERE id = %s",
            (scan_id,),
        )

    # 2. Now run preflight check with identical details
    res_check = client.post(
        "/api/v1/scans/preflight-check",
        headers=headers,
        data={
            "application_name": "PayFlow",
            "module_name": "auth-service",
            "version": "v1.0.0",
        },
    )
    assert res_check.status_code == 200
    data = res_check.json()["data"]
    assert data["is_duplicate"] is True
    assert data["application_name"] == "PayFlow"
    assert data["module_name"] == "auth-service"
    assert data["version"] == "v1.0.0"
    assert data["scan_id"] == scan_id

    # 3. Preflight with different version without file should NOT be a duplicate
    res_diff_ver = client.post(
        "/api/v1/scans/preflight-check",
        headers=headers,
        data={
            "application_name": "PayFlow",
            "module_name": "auth-service",
            "version": "v1.0.1",
        },
    )
    assert res_diff_ver.status_code == 200
    assert res_diff_ver.json()["data"]["is_duplicate"] is False

    # 4. Uploading the exact same manifest file (even with different version) MUST detect duplicate file
    res_file_dup = client.post(
        "/api/v1/scans/preflight-check",
        headers=headers,
        data={
            "application_name": "OtherApp",
            "module_name": "other-service",
            "version": "v2.0.0",
        },
        files={"file": ("package.json", manifest_bytes, "application/json")},
    )
    assert res_file_dup.status_code == 200
    file_dup_data = res_file_dup.json()["data"]
    assert file_dup_data["is_duplicate"] is True
    assert file_dup_data["duplicate_type"] == "EXACT_FILE_EXISTS"
    assert file_dup_data["application_name"] == "PayFlow"
    assert file_dup_data["module_name"] == "auth-service"
    assert file_dup_data["version"] == "v1.0.0"
    assert file_dup_data["scan_id"] == scan_id
