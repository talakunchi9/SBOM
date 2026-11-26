"""GitHub credentials management endpoints."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Request

from app.api.common import envelope, error_response, org_from_request, rid_from_request

log = logging.getLogger("bom")
router = APIRouter(tags=["credentials"])


@router.post("/api/v1/credentials/github")
async def create_cred(request: Request):
    rid = rid_from_request(request)
    try:
        body = await request.json()
    except Exception:
        return error_response("INVALID_INPUT", "malformed JSON body", rid, 400)
    org = org_from_request(request)
    kind = body.get("type")
    creds = request.app.state.creds
    audit = request.app.state.audit
    try:
        if kind == "GITHUB_APP":
            if not body.get("app_id") or not body.get("private_key_pem"):
                return error_response("INVALID_INPUT", "app_id and private_key_pem are required", rid, 400)
            cred = creds.create_app(org, body.get("name") or "", body["app_id"], body["private_key_pem"], body.get("repository_scope"))
        elif kind == "GITHUB_FINE_GRAINED_PAT":
            if not body.get("token"):
                return error_response("INVALID_INPUT", "token is required", rid, 400)
            cred = creds.create_pat(org, body.get("name") or "", body["token"], body.get("repository_scope"))
        else:
            return error_response("INVALID_INPUT", "unsupported credential type", rid, 400)
    except Exception:
        log.exception("credential store failed")
        return error_response("CREDENTIAL_FAILED", "failed to store credential", rid, 500)
    audit.record("CREDENTIAL_CREATED", organization_id=org, credential_id=cred["id"], metadata={"type": cred["credential_type"]})
    return envelope(cred, rid, 201)


@router.get("/api/v1/credentials/github")
def list_creds(request: Request):
    creds = request.app.state.creds
    return envelope(creds.list(org_from_request(request)), rid_from_request(request))


@router.delete("/api/v1/credentials/github/{cred_id}")
def revoke_cred(cred_id: str, request: Request):
    org = org_from_request(request)
    rid = rid_from_request(request)
    creds = request.app.state.creds
    audit = request.app.state.audit
    try:
        creds.revoke(cred_id, org)
    except LookupError:
        return error_response("CREDENTIAL_NOT_FOUND", "not found", rid, 404)
    audit.record("CREDENTIAL_REVOKED", organization_id=org, credential_id=cred_id)
    return envelope({"status": "revoked"}, rid)
