"""SBOM snapshot inspection and export endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response

from app.api.common import envelope, error_response, owned_scan, org_from_request, rid_from_request, snap_for_scan
from app.export.formats import export_snapshot
from app.repositories.store import iso, utcnow
from app.services.scan_service import export_filename

router = APIRouter(tags=["boms"])


@router.get("/api/v1/scans/{scan_id}/sbom")
def scan_sbom(scan_id: str, request: Request):
    scans = request.app.state.scans
    boms = request.app.state.boms
    rid = rid_from_request(request)
    scan = owned_scan(scans, scan_id, org_from_request(request))
    if scan is None:
        return error_response("SCAN_NOT_FOUND", "not found", rid, 404)
    if not scan.get("snapshot_id"):
        return error_response("SBOM_NOT_READY", "sbom not ready yet", rid, 404)
    snap = boms.get_snapshot(scan["snapshot_id"])
    if snap is None:
        return error_response("BOM_NOT_FOUND", "not found", rid, 404)
    return envelope(snap, rid)


@router.get("/api/v1/scans/{scan_id}/components")
def scan_components(scan_id: str, request: Request):
    scans = request.app.state.scans
    boms = request.app.state.boms
    rid = rid_from_request(request)
    snap, err = snap_for_scan(scans, boms, scan_id, org_from_request(request), rid)
    if err:
        return err
    return envelope(snap["components"], rid)


@router.get("/api/v1/scans/{scan_id}/dependencies")
def scan_deps(scan_id: str, request: Request):
    scans = request.app.state.scans
    boms = request.app.state.boms
    rid = rid_from_request(request)
    snap, err = snap_for_scan(scans, boms, scan_id, org_from_request(request), rid)
    if err:
        return err
    return envelope(snap["dependencies"], rid)


@router.get("/api/v1/scans/{scan_id}/export")
def scan_export(scan_id: str, request: Request, format: str = "cyclonedx-json"):
    scans = request.app.state.scans
    boms = request.app.state.boms
    bulk_service = request.app.state.bulk_service
    db = request.app.state.db
    org = org_from_request(request)
    rid = rid_from_request(request)

    scan = owned_scan(scans, scan_id, org)
    if scan is not None and scan.get("snapshot_id"):
        query = request.url.query
        return RedirectResponse(f"/api/v1/boms/{scan['snapshot_id']}/export?{query}", status_code=302)

    # Check if scan_id is a bulk scan
    bulk = bulk_service.get_bulk(scan_id, org)
    if bulk is not None:
        format_name = request.query_params.get("format", format)
        child_rows = db.execute(
            """SELECT s.sbom_id, s.project_id, s.application_name, s.application_version
               FROM scans s
               WHERE s.bulk_scan_id = ? AND s.sbom_id IS NOT NULL AND s.scan_status = 'COMPLETED'""",
            (scan_id,),
        ).fetchall()
        snapshots = [boms.get_snapshot(r[0]) for r in child_rows if r[0]]
        snapshots = [s for s in snapshots if s is not None]
        if not snapshots:
            return error_response("NO_SNAPSHOTS", "no completed scans found in this bulk scan", rid, 404)

        composite = {
            "id": scan_id,
            "organization_id": org,
            "project_id": bulk.get("project_id") or "Bulk Scan",
            "application_id": bulk.get("project_id") or "Bulk Scan",
            "application_version": f"{len(snapshots)} items",
            "scanner_name": "bom-engine",
            "scanner_version": "sbom-engine-1.0.0",
            "generated_at": bulk.get("completed_at") or bulk.get("created_at") or iso(utcnow()),
            "components": [],
            "dependencies": [],
        }
        seen_comps = set()
        for snap in snapshots:
            for comp in snap.get("components") or []:
                key = (comp.get("name"), comp.get("version"), comp.get("purl"))
                if key not in seen_comps:
                    seen_comps.add(key)
                    composite["components"].append(comp)
            for dep in snap.get("dependencies") or []:
                composite["dependencies"].append(dep)
        try:
            payload, content_type = export_snapshot(format_name, composite)
        except KeyError:
            return error_response("UNSUPPORTED_FORMAT", "unsupported format", rid, 400)

        # Use application name for user-friendly export filenames without UUIDs
        app_label = bulk.get("project_id") or "application"
        filename = export_filename(app_label, format_name)
        headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
        return Response(payload, media_type=content_type, headers=headers)

    return error_response("SCAN_NOT_FOUND", "not found", rid, 404)


@router.get("/api/v1/boms/{bom_id}")
def get_bom(bom_id: str, request: Request):
    boms = request.app.state.boms
    rid = rid_from_request(request)
    snap = boms.get_snapshot(bom_id)
    if snap is None or snap.get("organization_id") != org_from_request(request):
        return error_response("BOM_NOT_FOUND", "not found", rid, 404)
    return envelope(snap, rid)


@router.get("/api/v1/boms/{bom_id}/export")
def export_bom(bom_id: str, request: Request, format: str = "cyclonedx-json"):
    boms = request.app.state.boms
    rid = rid_from_request(request)
    snap = boms.get_snapshot(bom_id)
    if snap is None or snap.get("organization_id") != org_from_request(request):
        return error_response("BOM_NOT_FOUND", "not found", rid, 404)
    try:
        payload, content_type = export_snapshot(format, snap)
    except KeyError:
        return error_response("UNSUPPORTED_FORMAT", "unsupported format", rid, 400)

    # Use application name for user-friendly export filenames without UUIDs
    app_label = snap.get("project_id") or snap.get("application_id") or "application"
    filename = export_filename(app_label, format)
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(payload, media_type=content_type, headers=headers)


@router.get("/api/v1/applications/{application_id}/boms")
def app_boms(application_id: str, request: Request):
    boms = request.app.state.boms
    org = org_from_request(request)
    snaps = [snap for snap in boms.list_for_application(application_id, 50) if snap.get("organization_id") == org]
    return envelope(snaps, rid_from_request(request))
