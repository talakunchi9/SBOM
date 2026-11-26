"""Vulnerability triage and scan vulnerability management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.api.common import envelope, error_response, org_from_request, rid_from_request, snap_for_scan

router = APIRouter(tags=["vulnerabilities"])


@router.get("/api/v1/scans/{scan_id}/vulnerabilities")
def scan_vulns(scan_id: str, request: Request):
    org = org_from_request(request)
    rid = rid_from_request(request)
    scans = request.app.state.scans
    boms = request.app.state.boms
    vuln_service = request.app.state.vuln_service
    snap, err = snap_for_scan(scans, boms, scan_id, org, rid)
    if err:
        return err
    enriched = vuln_service.enrich_scan_vulnerabilities(org, snap)
    return envelope(enriched, rid)


@router.get("/api/v1/vulnerabilities/triage")
def list_vuln_triage(request: Request):
    triage_repo = request.app.state.triage_repo
    data = triage_repo.list_triage(org_from_request(request))
    return envelope(data, rid_from_request(request))


@router.patch("/api/v1/vulnerabilities/{cve_id}/status")
async def update_vuln_status(cve_id: str, request: Request):
    org = org_from_request(request)
    rid = rid_from_request(request)
    vuln_service = request.app.state.vuln_service
    try:
        body = await request.json()
    except Exception:
        body = {}
    status = str(body.get("status") or "").strip()
    if not status:
        return error_response("INVALID_INPUT", "status is required", rid, 400)
    vex_status = str(body.get("vex_status") or body.get("vexStatus") or "").strip()
    project_name = str(body.get("project") or body.get("project_name") or "").strip()
    app_name = str(body.get("application") or body.get("application_name") or "").strip()
    ticket_id = str(body.get("ticket_id") or body.get("ticketId") or "").strip()
    owner = str(body.get("owner") or "").strip()
    justification = str(body.get("justification") or "").strip()

    result, err = vuln_service.update_vulnerability_status(
        org=org,
        cve_id=cve_id,
        status=status,
        vex_status=vex_status,
        project_name=project_name,
        app_name=app_name,
        ticket_id=ticket_id,
        owner=owner,
        justification=justification,
    )
    if err:
        err_code, err_msg, status_code = err
        return error_response(err_code, err_msg, rid, status_code)
    return envelope(result, rid)
