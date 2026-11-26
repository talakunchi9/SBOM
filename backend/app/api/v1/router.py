"""Master API v1 router that aggregates all endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.applications import router as applications_router
from app.api.v1.endpoints.boms import router as boms_router
from app.api.v1.endpoints.bulk_scans import router as bulk_scans_router
from app.api.v1.endpoints.catalog import router as catalog_router
from app.api.v1.endpoints.credentials import router as credentials_router
from app.api.v1.endpoints.health import router as health_router
from app.api.v1.endpoints.inventory import router as inventory_router
from app.api.v1.endpoints.scans import router as scans_router
from app.api.v1.endpoints.vulnerabilities import router as vulnerabilities_router
from app.api.v1.endpoints.webhooks import router as webhooks_router

v1_router = APIRouter()

# Register all modular endpoint routers
v1_router.include_router(health_router)
v1_router.include_router(credentials_router)
v1_router.include_router(webhooks_router)
v1_router.include_router(catalog_router)
v1_router.include_router(applications_router)
v1_router.include_router(inventory_router)
v1_router.include_router(vulnerabilities_router)
v1_router.include_router(bulk_scans_router)
v1_router.include_router(boms_router)
v1_router.include_router(scans_router)
