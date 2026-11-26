"""GitHub incoming webhooks endpoints."""

from __future__ import annotations

import json
import uuid
from fastapi import APIRouter, Request

from app.api.common import envelope, error_response, org_from_request, rid_from_request, valid_signature
from app.sources.workspace import validate_repo_url

router = APIRouter(tags=["webhooks"])


@router.post("/api/v1/github/webhooks")
async def webhook(request: Request):
    cfg = request.app.state.cfg
    scans = request.app.state.scans
    db = request.app.state.db
    orch = request.app.state.orch
    rid = rid_from_request(request)

    body = await request.body()
    if len(body) > 5 * 1024 * 1024:
        return error_response("INVALID_INPUT", "unreadable body", rid, 400)
    if not valid_signature(request.headers.get("x-hub-signature-256") or "", body, cfg.github_webhook_secret.encode()):
        return error_response("SIGNATURE_INVALID", "signature invalid", rid, 401)
    event = request.headers.get("x-github-event") or ""
    delivery = request.headers.get("x-github-delivery") or ""
    if not delivery:
        return error_response("INVALID_INPUT", "missing delivery id", rid, 400)
    org = org_from_request(request)
    delivery_key = "webhook:" + delivery
    if scans.find_by_key(delivery_key):
        return envelope({"status": "duplicate"}, rid)
    if event not in ("push", "release"):
        from app.catalog.store import ensure_organization
        from app.repositories.store import iso, utcnow

        ensure_organization(db, org)
        db.execute(
            """INSERT INTO scans (
               id, organization_id, project_id, application_id, application_name,
               application_version, version_strategy, bom_type, source_type, scan_status,
               scan_stage, idempotency_key, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT (idempotency_key) DO NOTHING""",
            (
                str(uuid.uuid4()), org, "", "", "", "", "VERSION_UNKNOWN", "SBOM", "GITHUB",
                "IGNORED", "IGNORED", delivery_key, iso(utcnow()),
            ),
        )
        return envelope({"status": "ignored"}, rid)
    try:
        payload = json.loads(body)
    except Exception:
        return error_response("INVALID_INPUT", "malformed payload", rid, 400)
    full_name = ((payload.get("repository") or {}).get("full_name") or "")
    url = "https://github.com/" + full_name
    try:
        validate_repo_url(url)
    except ValueError as exc:
        return error_response("INVALID_REPOSITORY", str(exc), rid, 400)
    ref = payload.get("ref") or ""
    branch = (payload.get("repository") or {}).get("default_branch") or ""
    if ref.startswith("refs/heads/"):
        branch = ref[len("refs/heads/") :]
    after = payload.get("after") or ""
    try:
        scan = orch.create_scan(
            {
                "organization_id": org,
                "project_id": full_name,
                "application_id": full_name,
                "application_name": full_name,
                "application_version": "webhook-" + after[:7],
                "version_strategy": "VERSION_UNKNOWN",
                "bom_type": "SBOM",
                "source_type": "GITHUB",
                "idempotency_key": delivery_key,
                "source_payload": {
                    "repository_url": url,
                    "branch": branch,
                    "commit_sha": after,
                    "organization_id": org,
                },
            }
        )
    except Exception as exc:
        return error_response("SCAN_CREATE_FAILED", str(exc), rid, 500)
    return envelope({"status": "queued", "scan_id": scan["id"]}, rid)

