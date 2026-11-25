# SBOM Platform – Complete Architecture, Database & Functional Flow Audit (Plan Only)

> **Status:** Analysis & Planning Only — **No source files, database tables, migrations, or APIs have been modified.**

---

## 1. Current Project Architecture Report

### Backend (`backend/`)
- **Framework & Runtime:** **FastAPI** (`uvicorn`, Python 3.13) with a separate background worker process ([worker.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/worker.py)) that polls PostgreSQL (`scans` table) for queued jobs using `cfg.scanner_workers` (default `4`) threads.
- **Database Access:** **Raw `psycopg` v3** (no ORM, no Alembic) wrapped in a custom `Database` class in [db.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/core/db.py) using `?` → `%s` parameter translation and SQL migration scripts in [backend/migrations/](file:///c:/Users/Dell/Desktop/SBOM/backend/migrations).
- **Entry Points:**
  - API Server: [main.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/main.py) → `app.api.build(load())` in [server.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/api/server.py).
  - Background Worker: [worker.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/worker.py) → `Orchestrator.execute(job)`.
- **Key Architectural Reality:**
  - The backend *already* has partial domain folders (`catalog/`, `scans/`, `scanner/`, `repositories/`, `vulnerabilities/`, `projects/`, `export/`, `credentials/`, `sources/`, `storage/`, `security/`), **but** [server.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/api/server.py) (1,665 lines / 76.5 KB) mixes **HTTP routing, request parsing, validation, raw SQL queries, business logic (preflight, triage rules, package history, bulk submission), and error formatting** in one `build()` closure.
  - There is **no real authentication/RBAC** middleware: `_org(request)` reads `X-Organization-Id` header defaulting to `"default"`, and audit logs hardcode `changed_by = 'admin'`.

### Frontend (`frontend/`)
- **Framework & Runtime:** **React 18.3 + TypeScript 5.7 + Vite 6.1 + Tailwind CSS 3.4 + React Router v6 + Recharts**.
- **State & API Layer:**
  - Single monolithic [AppStateContext.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/context/AppStateContext.tsx) (1,351 lines / 51.6 KB) holds global arrays (`projects`, `vulnerabilities`, `components`, `scansHistory`, `tickets`, `policies`, `timelineEvents`, `users`) and executes data fetching.
  - Single monolithic [client.ts](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/client.ts) (36.5 KB) holds all API calls, TypeScript DTOs, and response mappers.
- **Key Architectural Reality:**
  - Massive page "god-components": [SecurityScans.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/SecurityScans.tsx) (**212.3 KB**), [SoftwareInventory.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/SoftwareInventory.tsx) (**123.1 KB**), [VulnerabilityDetail.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/VulnerabilityDetail.tsx) (**72.5 KB**), [Vulnerabilities.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/Vulnerabilities.tsx) (**68.0 KB**), [Dashboard.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/dashboard/Dashboard.tsx) (**64.9 KB**).
  - Several UI modules (Compliance, Policies, Users, Monitoring, Integrations, Profile, Settings) have **no backend API** and rely on empty [mockData.ts](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/data/mockData.ts) arrays, `localStorage`, or toast-only stubs.

---

## 2. Current Folder Structure & Structural Issues

```text
SBOM/
├── package.json                          # Root scripts: setup, dev:all, db:export, db:import
├── Corework_Sbom, S_BOM.md, SCAN_API_FLOW.md, File_structure_workflow.md,
│   project_workflow.md, S-BOM_Functional_Audit_and_Technical_Specification.docx,
│   S-BOM_update.sql, sbom_backup.sql     # Root-level docs, SQL dumps, and notes
├── scripts/                              # dev-all.mjs, setup.mjs, db.mjs, clear/export/import_db.py
├── data/                                 # Workspace data dir
├── docs/                                 # Existing docs folder
├── backend/
│   ├── .env, .env.example, docker-compose.yml, requirements.txt
│   ├── data/objects/ & data/test-objects/ # Local object storage for uploaded manifests/zips
│   ├── migrations/                       # 001..010 SQL migrations (003 missing/skipped)
│   ├── tests/                            # 13 pytest test files
│   └── app/
│       ├── main.py                       # Uvicorn API entrypoint
│       ├── worker.py                     # 4-thread background scan worker
│       ├── api/server.py                 # 76.5 KB monolith: 34 routes + SQL + business logic
│       ├── catalog/store.py              # CatalogRepo (applications & modules CRUD/binding)
│       ├── core/                         # config.py, db.py, inventory_derived.py, metrics.py, validation.py
│       ├── credentials/service.py        # Encrypted GitHub App/PAT storage + Audit
│       ├── export/formats.py             # SPDX, CycloneDX, CSV, XLSX exporters
│       ├── projects/dashboard.py         # Aggregates scans + snapshots into /api/v1/projects
│       ├── repositories/
│       │   ├── store.py                  # 43.0 KB: ScanRepo, JobQueue, BomRepo, Inventory CRUD
│       │   └── facts.py                  # Normalized findings, NTIA checks, vulnerabilities upsert
│       ├── scanner/                      # detector.py, parsers.py (63.9 KB), pipeline.py
│       ├── scans/orchestrator.py         # Scan lifecycle state machine & auto-closure
│       ├── security/archives.py          # Zip/tar extraction safety limits
│       ├── sources/workspace.py          # Local upload packing, GitHub cloning, bulk CSV/XLSX parsing
│       ├── storage/object_store.py       # LocalStore filesystem blob storage
│       └── vulnerabilities/              # cvss.py, provider.py (OSV / MITRE CVE correlation)
└── frontend/
    └── src/
        ├── App.tsx, main.tsx, index.css
        ├── api/client.ts                 # 36.5 KB API client + mappers
        ├── context/                      # AppStateContext.tsx (51.6 KB), ThemeContext.tsx
        ├── data/mockData.ts              # Mostly empty arrays + initialIntegrations
        ├── hooks/useCatalogOptions.ts
        ├── types/index.ts
        ├── components/                   # layout/ (Layout, Sidebar, TopHeader) & common/ (modals, pagination)
        └── pages/                        # compliance, dashboard, export, inventory, monitoring,
                                          # projects, scans, settings, supply-chain, vulnerabilities
```

### Key Structural Issues Identified (with File Evidence)
1. **God-Files / Too Many Responsibilities:**
   - [server.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/api/server.py) (1,665 lines): Route handlers directly run raw SQL (`preflight_check`, `scan_vulns`, `list_vuln_triage`, `update_vuln_status`, `update_app_lifecycle_status`, `get_inventory_audit_log`, `get_package_history`, `_submit_bulk`, `_get_bulk`).
   - [SecurityScans.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/SecurityScans.tsx) (212 KB): Combines Scans Table, Launch Scan Wizard (Local/GitHub/Bulk), Live Progress Monitor, Scan History, Schedules (`localStorage`), and Modals in one file.
   - [SoftwareInventory.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/SoftwareInventory.tsx) (123 KB): Combines catalog table, filters, manual JSON/package add, delete modal, package history drawer, and occurrences drawer.
2. **Duplicated Logic:**
   - Duplicate/lifecycle checks and audit logging (`INSERT INTO inventory_change_log`) are inline-duplicated in `update_vuln_status`, `create_inventory`, and `delete_inventory` inside [server.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/api/server.py).
   - `update_app_lifecycle_status` updates `applications` and then runs a `try/except` `UPDATE projects ...` even though `projects` is now a read-only compatibility view.
3. **Root Clutter & Unclear Docs:**
   - Multiple overlapping markdown/SQL/docx files in root (`S-BOM_update.sql`, `sbom_backup.sql`, `Corework_Sbom`, `File_structure_workflow.md`, `project_workflow.md`, `SCAN_API_FLOW.md`, `S_BOM.md`).
4. **Configuration / Environment Mixing:**
   - [config.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/core/config.py#L120) embeds a default PostgreSQL DSN (`postgresql://sbom:123456789@127.0.0.1:5432/S-BOM`).
   - Frontend [AppStateContext.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/context/AppStateContext.tsx#L232-L258) has simulated `triggerSelfHeal()` with a `setTimeout` that fakes reconnecting.

---

## 3. Backend Endpoint Inventory (`backend/app/api/server.py`)

All **34 endpoints** currently live inside `build(cfg)` in [server.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/api/server.py):

| Method & Path | Handler (`server.py`) | Purpose | Tables Read / Modified | Proposed Destination |
|---|---|---|---|---|
| `GET /health/live` | `live` | Liveness probe | None | `api/v1/endpoints/health.py` |
| `GET /health/ready` | `ready` | Readiness + DB ping + metrics | `SELECT 1` | `api/v1/endpoints/health.py` |
| `GET /metrics.json` | `metrics` | In-memory metrics snapshot | None | `api/v1/endpoints/health.py` |
| `POST /api/v1/scans/preflight-check` | `preflight_check` | Duplicate hash/metadata check | R: `scans`, `applications`, `modules` | `api/v1/endpoints/scans.py` → `ScanService` |
| `POST /api/v1/scans/local` | `local_scan` | Upload manifest/zip/folder & queue | R/W: `applications`, `modules`, `scans`, `organizations` | `api/v1/endpoints/scans.py` → `ScanService` |
| `POST /api/v1/scans/github` | `github_scan` | Queue GitHub repo scan | R/W: `applications`, `modules`, `scans` | `api/v1/endpoints/scans.py` → `ScanService` |
| `GET /api/v1/scans` | `list_scans` | List up to 100 scans + source labels | R: `scans` | `api/v1/endpoints/scans.py` → `ScanRepo` |
| `GET /api/v1/scans/{scan_id}` | `get_scan` | Get single scan metadata | R: `scans` | `api/v1/endpoints/scans.py` |
| `GET /api/v1/scans/{scan_id}/status` | `scan_status` | Poll scan status & stage | R: `scans` | `api/v1/endpoints/scans.py` |
| `POST /api/v1/scans/{scan_id}/rescan` | `rescan` | Requeue completed/failed scan | R/W: `scans` | `api/v1/endpoints/scans.py` → `Orchestrator` |
| `POST /api/v1/scans/{scan_id}/cancel` | `cancel_scan` | Cancel pending/running scan | R/W: `scans` | `api/v1/endpoints/scans.py` → `Orchestrator` |
| `GET /api/v1/scans/{scan_id}/events` | `scan_events` | Scan stage event log (`scans.events`) | R: `scans` | `api/v1/endpoints/scans.py` |
| `GET /api/v1/scans/{scan_id}/sbom` | `scan_sbom` | Full SBOM snapshot for scan | R: `scans`, `sboms`, `sbom_components`, `findings`, `vulnerabilities` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/scans/{scan_id}/components` | `scan_components` | Components list for scan | R: `scans`, `sboms`, `sbom_components`, `findings` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/scans/{scan_id}/dependencies` | `scan_deps` | Dependency graph edges for scan | R: `scans`, `sboms`, `sbom_components` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/scans/{scan_id}/vulnerabilities` | `scan_vulns` | Vuln matches + `findings` + `vulnerability_triage` overlay | R: `scans`, `sboms`, `findings`, `vulnerabilities`, `vulnerability_triage` | `api/v1/endpoints/vulnerabilities.py` → `VulnerabilityService` |
| `GET /api/v1/scans/{scan_id}/export` | `scan_export` | Redirect to BOM export or composite bulk export | R: `scans`, `sboms`, `sbom_components` | `api/v1/endpoints/boms.py` |
| `POST /api/v1/scans/bulk` | `bulk_upload` | Parse CSV/XLSX & queue child GitHub scans | R/W: `scans`, `applications`, `modules` | `api/v1/endpoints/bulk_scans.py` → `BulkScanService` |
| `GET /api/v1/bulk-scans/{bulk_id}` | `get_bulk` | Aggregate bulk scan status | R: `scans` | `api/v1/endpoints/bulk_scans.py` |
| `GET /api/v1/bulk-scans/{bulk_id}/results` | `bulk_results` | Bulk scan child items list | R: `scans` | `api/v1/endpoints/bulk_scans.py` |
| `GET /api/v1/projects` | `projects_dashboard` | Aggregated Apps & Microservices KPIs/rows | R: `scans`, `applications`, `sboms`, `sbom_components`, `findings` | `api/v1/endpoints/applications.py` → `dashboard.py` |
| `PATCH /api/v1/applications/{target}/lifecycle-status` | `update_app_lifecycle_status` | Set `Active` / `Decommissioned` | W: `applications` | `api/v1/endpoints/applications.py` |
| `GET /api/v1/applications/{app_id}/boms` | `app_boms` | List SBOMs for an app | R: `sboms` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/catalog/projects` | `catalog_projects` | Paginated `applications` dropdown | R: `applications` | `api/v1/endpoints/catalog.py` |
| `POST /api/v1/catalog/projects` | `create_catalog_project` | Create application + modules | W: `applications`, `modules` | `api/v1/endpoints/catalog.py` |
| `GET /api/v1/catalog/projects/{id}/applications-services` | `catalog_applications` | Paginated `modules` dropdown | R: `modules` | `api/v1/endpoints/catalog.py` |
| `POST /api/v1/catalog/projects/{id}/applications-services` | `create_catalog_application` | Ensure/create module under app | W: `modules` | `api/v1/endpoints/catalog.py` |
| `GET /api/v1/vulnerabilities/triage` | `list_vuln_triage` | List all triage overrides | R: `vulnerability_triage` | `api/v1/endpoints/vulnerabilities.py` |
| `PATCH /api/v1/vulnerabilities/{cve_id}/status` | `update_vuln_status` | Update status/VEX + validate Open→Closed + sync `findings` + audit | R/W: `vulnerability_triage`, `findings`, `inventory_change_log` | `api/v1/endpoints/vulnerabilities.py` → `VulnerabilityService` |
| `GET /api/v1/boms/{bom_id}` | `get_bom` | Get SBOM snapshot by ID | R: `sboms`, `sbom_components`, `findings` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/boms/{bom_id}/export` | `export_bom` | Export SPDX/CycloneDX/CSV/XLSX | R: `sboms`, `sbom_components`, `findings` | `api/v1/endpoints/boms.py` |
| `GET /api/v1/inventory/components` | `list_inventory` | Paginated manual inventory | R: `inventory_components`, `applications`, `modules` | `api/v1/endpoints/inventory.py` |
| `POST /api/v1/inventory/components` | `create_inventory` | Add manual inventory + audit log | R/W: `inventory_components`, `applications`, `modules`, `inventory_change_log` | `api/v1/endpoints/inventory.py` |
| `DELETE /api/v1/inventory/components/{id}` | `delete_inventory` | Delete manual inventory + audit log | R/W: `inventory_components`, `inventory_change_log` | `api/v1/endpoints/inventory.py` |
| `GET /api/v1/inventory/audit-log` | `get_inventory_audit_log` | Query inventory & vuln status audit log | R: `inventory_change_log` | `api/v1/endpoints/inventory.py` |
| `GET /api/v1/packages/{package_name}/history` | `get_package_history` | Package version timeline (scans + audit) | R: `sbom_components`, `sboms`, `applications`, `modules`, `inventory_change_log` | `api/v1/endpoints/inventory.py` |
| `GET /api/v1/packages/occurrences` | `get_package_occurrences` | Cross-app package usage count | R: `sbom_components`, `inventory_components`, `sboms`, `applications`, `modules` | `api/v1/endpoints/inventory.py` |
| `POST /api/v1/credentials/github` | `create_cred` | Encrypt & store GitHub App/PAT | W: `credentials` | `api/v1/endpoints/credentials.py` |
| `GET /api/v1/credentials/github` | `list_creds` | List active credentials | R: `credentials` | `api/v1/endpoints/credentials.py` |
| `DELETE /api/v1/credentials/github/{cred_id}` | `revoke_cred` | Revoke credential | W: `credentials` | `api/v1/endpoints/credentials.py` |
| `POST /api/v1/github/webhooks` | `webhook` | HMAC-SHA256 verified GitHub push/release scan | R/W: `scans`, `organizations` | `api/v1/endpoints/webhooks.py` |

*(Note: Total is 41 route decorators including `/health/*` and `/metrics.json`, 38 under `/api/v1/*`.)*

---

## 4. Frontend API Mapping (`frontend/src/api/client.ts`)

| Frontend Module / File | API Functions Used (`client.ts`) | Backend Endpoint(s) | Status |
|---|---|---|---|
| **Global State** (`AppStateContext.tsx`) | `healthReady`, `listScans`, `listInventoryComponents`, `listProjects`, `scanPackageTotals`, `getBulkScan`, `scanComponents`, `scanVulnerabilities`, `listVulnerabilityTriage`, `createLocalScan`, `createGitHubScan`, `createGitHubPat`, `createBulkScan`, `rescanScan`, `cancelScan`, `createInventoryComponents`, `deleteInventoryComponent`, `updateVulnerabilityStatus`, `updateApplicationLifecycleStatus`, `exportUrl` | `/health/ready`, `/api/v1/scans*`, `/api/v1/inventory/components*`, `/api/v1/projects`, `/api/v1/bulk-scans/*`, `/api/v1/vulnerabilities/*`, `/api/v1/applications/*/lifecycle-status`, `/api/v1/credentials/github` | Connected |
| **Security Scans** (`SecurityScans.tsx`, `ScanResultDetails.tsx`) | `checkScanDuplicate`, `scanEvents`, `scanComponents`, `scanVulnerabilities`, `scanStatus`, + `useAppState()` | `/api/v1/scans/preflight-check`, `/api/v1/scans/{id}/*` | Connected (Schedules tab uses `localStorage` only) |
| **Projects & Microservices** (`ProjectsMicroservices.tsx`) | `listProjects` + `useAppState()` | `/api/v1/projects` | Connected |
| **Software Inventory** (`SoftwareInventory.tsx`, `AddInventoryComponent.tsx`, `UploadInventoryModal.tsx`, `SBOMArtifacts.tsx`) | `getPackageHistory`, `getInventoryAuditLog`, `getPackageOccurrences`, `useCatalogOptions` + `useAppState()` | `/api/v1/packages/*`, `/api/v1/inventory/*`, `/api/v1/catalog/*` | Connected |
| **Vulnerabilities** (`Vulnerabilities.tsx`, `VulnerabilityDetail.tsx`, `Remediation.tsx`) | `useAppState()` (`updateVulnerabilityStatus`), `getPackageOccurrences` | `/api/v1/vulnerabilities/*` | Connected (`Remediation` tickets are in-memory UI state only) |
| **Dashboard, Export, Supply Chain** (`Dashboard.tsx`, `ExportCenter.tsx`, `SupplyChain.tsx`) | Derived from `useAppState()` (`projects`, `components`, `vulnerabilities`, `scansHistory`) | Indirect via `AppStateContext` | Connected |
| **Compliance, Policies, Monitoring, Integrations, Users, Profile, Settings** | None (`mockData.ts`, `localStorage`, or toast stubs) | **None** | **Frontend-only / Disconnected** |
| **Unused Backend Endpoints in Frontend** | — | `GET /metrics.json`, `GET /api/v1/scans/{id}/sbom`, `GET /api/v1/scans/{id}/dependencies`, `GET /api/v1/boms/{bom_id}`, `GET /api/v1/applications/{id}/boms`, `GET /api/v1/bulk-scans/{id}/results`, `GET/DELETE /api/v1/credentials/github*`, `POST /api/v1/github/webhooks` | Unused by UI (some used by tests/external webhooks) |

---

## 5. Complete Database Audit (Verified Live PostgreSQL Schema)

Verified directly against live PostgreSQL database `S-BOM` (`schema_migrations`: `001` through `010`, skipping `003`).

### A. Complete Table Inventory

| Existing Table Name | Type | Live Rows | Proposed Understandable Name | Purpose | Main Module | Important Relationships |
|---|---|---|---|---|---|---|
| `organizations` | BASE TABLE | 1 | `organizations` *(keep)* | Multi-tenant organization root (`default`) | Core / Tenant | Parent of `applications`, `credentials`, `scans`, `sboms`, `inventory_components` |
| `applications` | BASE TABLE | 3 | `applications` *(keep)* | Top-level software applications (renamed from `projects` in migration 009; `APP-0001` readable ID) | Applications / Catalog | Belongs to `organizations`; has many `modules`, `scans`, `sboms`, `inventory_components` |
| `modules` | BASE TABLE | 3 | `application_modules` *(or keep `modules`)* | Sub-services/microservices under an application (renamed from `applications` in migration 009) | Applications / Catalog | Belongs to `applications`; referenced by `scans`, `sboms`, `inventory_components` |
| `projects` | **VIEW** | — | *(deprecate/drop after code cleanup)* | Compatibility view aliasing `applications` | Legacy compatibility | Read/update remnants in `server.py` |
| `scans` | BASE TABLE | 5 | `security_scans` *(or keep `scans`)* | Scan jobs, queue state (`job_status`, retries), bulk scan grouping, and stage `events` | Security Scans & Worker | Belongs to `organizations`, `applications`, `modules`; links to `sboms` |
| `sboms` | BASE TABLE | 5 | `sbom_snapshots` *(or keep `sboms`)* | Generated SBOM metadata, Git commit info, and format/normalization flags | SBOM / Artifacts | Belongs to `scans`, `organizations`, `applications`, `modules` |
| `sbom_components` | BASE TABLE | 45 | `sbom_components` *(keep)* | Normalized packages discovered in a specific SBOM + NTIA 7-field compliance flags + `depends_on` | Inventory / Scanning | Belongs to `sboms`; referenced by `findings` |
| `vulnerabilities` | BASE TABLE | 58 | `vulnerability_catalog` *(or keep `vulnerabilities`)* | Deduplicated CVE / OSV / GHSA advisory definitions (CVSS, severity, description, refs) | Vulnerability Mgmt | Referenced by `findings` |
| `findings` | BASE TABLE | 114 | `vulnerability_findings` *(or keep `findings`)* | Junction linking a specific `sbom_component` to a `vulnerability` with per-finding status/VEX | Vulnerability Mgmt | Belongs to `sboms`, `sbom_components`, `vulnerabilities` |
| `vulnerability_triage` | BASE TABLE | 4 | `vulnerability_triage_rules` *(or keep `vulnerability_triage`)* | Org/project-level vulnerability triage overrides (status, VEX, ticket, owner, justification) | Vulnerability Mgmt | Logical link to `organizations` & `vulnerabilities.vulnerability_key` (no FKs) |
| `inventory_components` | BASE TABLE | 5 | `manual_inventory_components` *(or keep `inventory_components`)* | Manually added or uploaded SBOM components outside automated scans | Software Inventory | Belongs to `organizations`, `applications`, `modules` |
| `inventory_change_log` | BASE TABLE | 22 | `audit_logs` *(or `inventory_audit_log`)* | Audit trail for manual inventory `ADD`/`REMOVE` and `VULN_STATUS_CHANGE` | Audit / Inventory / Vulns | Logical link to `organizations`, `applications`, `modules` (no FKs) |
| `credentials` | BASE TABLE | 0 | `integration_credentials` *(or keep `credentials`)* | Encrypted GitHub App / Fine-grained PAT secrets | Credentials / GitHub | Belongs to `organizations` |
| `schema_migrations` | BASE TABLE | 9 | `schema_migrations` *(keep)* | Applied SQL migration versions | Core / DB | Standalone |

### B. Column-Level Data Dictionary (Key Tables & Verified Types)
- **`organizations`**: `id` (text PK), `name` (text), `created_at` (timestamptz).
- **`applications`**: `id` (text PK, default `gen_random_uuid()::text`), `organization_id` (text FK→`organizations`), `name` (text), `readable_id` (text, trigger `APP-XXXX`), `business_owner`, `technical_owner`, `development_type` (`In-house|Outsourced|Vendor`), `vendor_name`, `lifecycle_status` (`Active|Inactive|Deprecated|Archived|Planned|Decommissioned`), `created_at`, `updated_at`.
- **`modules`**: `id` (text PK), `application_id` (text FK→`applications`), `organization_id` (text FK→`applications`), `name` (text), `path` (text, default `'/'`), `programming_language`, `package_manager`, `module_type` (`Library|Microservice|Frontend|Service|Backend|Mobile|Other`), `created_at`.
- **`scans`**: `id` (text PK), `organization_id` (text FK), `project_id` (text — *actually stores app name!*), `application_id` (text — *actually stores module name!*), `application_name` (text), `catalog_project_id` (text nullable FK→`applications.id`), `catalog_application_id` (text nullable FK→`modules.id`), `application_version`, `version_strategy`, `bom_type`, `source_type` (`LOCAL|GITHUB`), `scan_status` (`PENDING|QUEUED|RUNNING|COMPLETED|FAILED|CANCELLED|SKIPPED|IGNORED|DEAD_LETTER`), `scan_stage`, `idempotency_key` (unique), `bulk_scan_id`, `bulk_row_number`, `bulk_file_name`, `bulk_status`, `bulk_total_rows`, `bulk_invalid_rows`, `bulk_errors`, `sbom_id` (FK→`sboms.id`), `repository_url`, `branch`, `job_status`, `job_payload`, `priority`, `attempts`, `max_attempts`, `next_attempt_at`, `events` (jsonb), `description`, `trigger`, `generation_context`, timestamps.
- **`sboms`**: `id` (text PK), `organization_id`, `project_id` (text name), `application_id` (text name), `scan_id` (FK→`scans.id`), `catalog_project_id` (FK→`applications.id`), `catalog_application_id` (FK→`modules.id`), `bom_type`, `application_version`, `repository_url`, `repository_branch`, `commit_sha`, `scanner_name`, `scanner_version`, `raw_metadata` (text JSON), `facts_normalized` (boolean), `generated_at`.
- **`sbom_components`**: `id` (text PK), `sbom_id` (FK→`sboms.id`), `name`, `version`, `ecosystem`, `package_manager`, `package_url`, `cpe`, `content_hash`, `license_name`, `supplier_name`, `dependency_scope`, `is_direct_dependency` (boolean), `source_manifest`, `raw_component`, `dependency_depth` (int), 7 `ntia_*` booleans, `depends_on` (`text[]`), `detection_method`, `confidence` (int), `classification`, `first_detected_at`, `last_detected_at`. Unique index `uq_sbom_components_identity`.
- **`vulnerabilities`**: `id` (text PK), `vulnerability_key` (unique text, e.g. `CVE-...` or `GHSA-...`), `source`, `severity`, `cvss_score` (numeric), `cvss_vector`, `description`, `reference_urls` (`text[]`).
- **`findings`**: `id` (text PK), `sbom_id` (FK→`sboms.id`), `sbom_component_id` (FK→`sbom_components.id`), `vulnerability_id` (FK→`vulnerabilities.id`), `source`, `severity`, `cvss_score`, `cvss_vector`, `description`, `fixed_version`, `status` (`Open`, `In Progress`, `Closed`, etc.), `vex_status` (`affected`, etc.), `ticket_id`, `owner`, `created_at`, `updated_at`. Unique `(sbom_component_id, vulnerability_id)`.
- **`vulnerability_triage`**: `id` (text PK), `organization_id`, `vulnerability_key`, `project_name`, `application_name`, `module_name`, `status`, `vex_status`, `ticket_id`, `owner`, `justification`, `updated_at`. Unique `(organization_id, vulnerability_key, project_name, application_name)`.
- **`inventory_components`**: `id` (text PK), `organization_id`, `application_id` (FK→`applications`), `module_id` (FK→`modules`), `name`, `package_name`, `version`, `component_type`, `source_file_name`, `license_name`, `package_url`, `ecosystem`, `risk_level`, `vulnerability_count`, `is_direct_dependency`, `supplier_name`, `created_by`, `created_at`. Unique index `uq_inventory_components_identity`.
- **`inventory_change_log`**: `id` (text PK), `organization_id`, `application_id`, `module_id`, `component_name`, `component_version`, `action`, `old_value` (jsonb), `new_value` (jsonb), `reason`, `changed_by`, `created_at`.
- **`credentials`**: `id` (text PK), `organization_id` (FK→`organizations`), `provider`, `credential_type`, `name`, `secret_reference`, `secret_nonce` (bytea), `secret_ciphertext` (bytea), `repository_scope`, `status`, timestamps.

### C. Entity Relationship Diagram (Verified Schema)

```mermaid
erDiagram
    organizations ||--o{ applications : owns
    organizations ||--o{ credentials : owns
    organizations ||--o{ scans : owns
    organizations ||--o{ sboms : owns
    organizations ||--o{ inventory_components : owns

    applications ||--o{ modules : contains
    applications ||--o{ scans : scoped_to
    applications ||--o{ sboms : scoped_to
    applications ||--o{ inventory_components : tracks

    modules ||--o{ scans : targets
    modules ||--o{ sboms : targets
    modules ||--o{ inventory_components : contains

    scans ||--o| sboms : produces
    sboms ||--o{ sbom_components : contains
    sboms ||--o{ findings : has
    sbom_components ||--o{ findings : affected_by
    vulnerabilities ||--o{ findings : referenced_by
```

### D. Database Integrity & Naming Findings
1. **Confusing Legacy Column Names (High Priority for Data Dictionary):**
   - `scans.project_id` and `sboms.project_id` store the **Application Name** (not a project UUID!), while `scans.catalog_project_id` stores the actual `applications.id` UUID.
   - `scans.application_id` and `sboms.application_id` store the **Module Name** (not an application UUID!), while `scans.catalog_application_id` stores the actual `modules.id` UUID.
   - Constraint/index names on `applications` still carry `projects_*` (`projects_pkey`, `idx_projects_organization`), and on `modules` still carry `applications_*` (`applications_pkey`).
2. **Missing Foreign Keys:**
   - `inventory_change_log` has no FK to `organizations`, `applications`, or `modules` (and stores either UUIDs or names inconsistently between `create_inventory` and `update_vuln_status`).
   - `vulnerability_triage` has no FK to `organizations` or `vulnerabilities`, and has an unused `module_name` column alongside `project_name` and `application_name`.
3. **Mixed `scans` Responsibility:**
   - `scans` acts simultaneously as the **scan domain record**, the **job queue** (`job_status`, `job_payload`, `attempts`), and the **bulk scan parent/child table** (`bulk_scan_id`, `bulk_errors`).

---

## 6. Functional Flow Traceability & Gap Report

### End-to-End Traceability
1. **Security Scan Flow (Local / GitHub / Bulk):**
   - `SecurityScans.tsx` → `AppStateContext.startScan()` → `POST /api/v1/scans/preflight-check` → `POST /api/v1/scans/local|github|bulk` → `server.py` binds catalog (`applications`/`modules`) + stores blob in `LocalStore` + `Orchestrator.create_scan()` writes `scans` (`PENDING`/`QUEUED`).
   - `worker.py` polls `JobQueue.claim()` → `Orchestrator.execute()` extracts workspace → `scanner.scan_tree()` parses manifests → `scanner.normalize()` → `VulnProvider.correlate()` queries OSV/MITRE → `BomRepo.save_snapshot()` writes `sboms`, `sbom_components`, `vulnerabilities`, `findings` → `Orchestrator._auto_close_remediated_vulnerabilities()` closes fixed CVEs in `findings` & `vulnerability_triage` → `scans` marked `COMPLETED`.
   - Frontend polls `GET /api/v1/scans/{id}/status` & `/events` → calls `loadScanResults()` → updates `AppStateContext` → reflects in **Dashboard, Security Scans, Projects, Software Inventory, Vulnerabilities**.
2. **Vulnerability Triage Flow:**
   - `Vulnerabilities.tsx` / `VulnerabilityDetail.tsx` → `AppStateContext.updateVulnerabilityStatus()` → `PATCH /api/v1/vulnerabilities/{cve}/status` → validates `Open → Closed` requires justification → upserts `vulnerability_triage` + updates `findings` + logs to `inventory_change_log`.
3. **Manual Software Inventory Flow:**
   - `AddInventoryComponent.tsx` / `UploadInventoryModal.tsx` → `POST /api/v1/inventory/components` → `_bind_inventory_item()` ensures `applications`/`modules` → `BomRepo.add_inventory_components()` inserts into `inventory_components` + logs to `inventory_change_log` → `refreshAppState()`.

### Confirmed Issues & Gaps
- **Confirmed — Disconnected UI Modules:** `Compliance.tsx`, `Policies.tsx`, `Monitoring.tsx`, `Integrations.tsx`, `Users.tsx`, `Profile.tsx`, `Settings.tsx` have **no backend endpoints** (`Compliance` reads empty `initialComplianceFrameworks`; `SecurityScans` Schedules and `Monitoring` persist only to `localStorage`; `Users` reads empty `initialUsers`).
- **Confirmed — Duplicate API Fetching in Frontend:** `AppStateContext.refreshAppState()` calls `api.scanPackageTotals(id)` (`/components`) AND `loadScanResults(id)` (`/components` + `/vulnerabilities`) for every completed scan, hitting `/components` **twice per scan**.
- **Confirmed — Audit Log Identity Inconsistency:** `inventory_change_log` stores `application_id`/`module_id` as **UUIDs** when written from `create_inventory`/`delete_inventory`, but stores **names** (`project_name`, `app_name`) when written from `update_vuln_status`, and hardcodes `changed_by = 'admin'`.
- **Confirmed — Legacy `projects` View Write Attempt:** `update_app_lifecycle_status` in `server.py` still attempts `UPDATE projects ...` inside a silent `try/except` even though `projects` is a view.
- **Potential Issue (Requires Runtime Testing):** `_auto_close_remediated_vulnerabilities` and `update_vuln_status` match `sboms.project_id` by name; if a scan used an ID vs name, project-scoped `findings` updates could miss rows.

---

## 7. Performance & Bottleneck Analysis

Splitting `server.py` into multiple files **will improve maintainability, not runtime speed**. The actual verifiable bottlenecks in the codebase are:

1. **Single Shared PostgreSQL Connection + Global `RLock` ([db.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/core/db.py#L87-L96)):**
   - All FastAPI threads and all 4 worker threads share **one** `psycopg` connection serialized by `self.lock = threading.RLock()`. Concurrent HTTP requests block behind each other and behind background scan DB writes.
2. **Frontend Request Waterfall on Load/Focus ([AppStateContext.tsx](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/context/AppStateContext.tsx#L339-L373)):**
   - Fires `3 + 3N` requests for `N` completed scans (with `loadScanResults` running sequentially in a `for` loop and calling `/components` twice per scan).
3. **N+1 Queries in `/api/v1/projects` ([dashboard.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/projects/dashboard.py#L85-L94)):**
   - Loops over every project group and calls `boms.get_snapshot()`, executing multiple queries per project instead of one aggregated SQL query.
4. **Per-Component Queries During Scan Persistence ([facts.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/repositories/facts.py#L116-L138)):**
   - Executes `SELECT MIN(sc.created_at)` + `UPDATE sbom_components` inside a loop for every component in the SBOM (`2 × C` queries per scan).
5. **Sequential External HTTP Calls in MITRE/OSV Provider ([provider.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/vulnerabilities/provider.py)):**
   - `preflight_check` also runs `LIKE '%hash%'` against `scans.job_payload::text` (full text scan without index).

---

## 8. Proposed Clean Target Architecture

### Backend (`backend/app/`) — Tailored to FastAPI + Raw `psycopg`
*(Keeps existing domain modules while extracting routes, services, and SQL out of `server.py`)*

```text
backend/app/
├── main.py                         # Uvicorn entrypoint
├── worker.py                       # Background worker entrypoint
├── core/
│   ├── config.py                   # Env config
│   ├── db.py                       # Database connection/pool & migrations
│   ├── metrics.py                  # Metrics snapshot
│   ├── validation.py               # Shared validators
│   └── inventory_derived.py        # Derived package occurrences
├── api/
│   ├── app.py                      # FastAPI app factory, CORS, request_id middleware, error envelope
│   ├── dependencies.py             # _org, rid, repo/service dependency providers
│   └── v1/
│       ├── router.py               # Aggregates all v1 routers
│       └── endpoints/
│           ├── health.py           # /health/live, /health/ready, /metrics.json
│           ├── scans.py            # /api/v1/scans/*
│           ├── bulk_scans.py       # /api/v1/scans/bulk, /api/v1/bulk-scans/*
│           ├── boms.py             # /api/v1/boms/*, /api/v1/applications/*/boms, /export
│           ├── vulnerabilities.py  # /api/v1/scans/*/vulnerabilities, /api/v1/vulnerabilities/*
│           ├── inventory.py        # /api/v1/inventory/*, /api/v1/packages/*
│           ├── applications.py     # /api/v1/projects, /api/v1/applications/*/lifecycle-status
│           ├── catalog.py          # /api/v1/catalog/*
│           ├── credentials.py      # /api/v1/credentials/github*
│           └── webhooks.py         # /api/v1/github/webhooks
├── services/                       # Business logic extracted from server.py
│   ├── scan_service.py             # preflight_check, local/github upload handling, target binding
│   ├── bulk_scan_service.py        # _submit_bulk, _get_bulk, _insert_bulk_row
│   ├── vulnerability_service.py    # Triage validation (Open->Closed), findings sync, audit logging
│   └── inventory_service.py        # Package history timeline, occurrences, audit log formatting
├── repositories/
│   ├── scan_repo.py                # Split from store.py (ScanRepo + JobQueue)
│   ├── bom_repo.py                 # Split from store.py (BomRepo + Inventory DB queries)
│   ├── facts.py                    # Findings, NTIA checks, vulnerabilities
│   ├── triage_repo.py              # SQL extracted from server.py for vulnerability_triage & audit
│   └── catalog_repo.py             # Moved/aliased from catalog/store.py
├── scanner/, scans/, projects/, export/, credentials/, security/, sources/, storage/, vulnerabilities/
└── docs/database-data-dictionary.md
```

### Frontend (`frontend/src/`) — Feature-Modular Structure

```text
frontend/src/
├── App.tsx, main.tsx, index.css
├── api/
│   ├── http.ts                     # Base fetch wrapper, ApiError, headers
│   ├── scans.ts, inventory.ts, vulnerabilities.ts, projects.ts, catalog.ts, index.ts
├── context/
│   ├── AppStateContext.tsx         # Slimmed global store + refreshAppState
│   └── ThemeContext.tsx
├── components/
│   ├── layout/                     # Layout, Sidebar, TopHeader
│   └── common/                     # Shared modals, TablePagination, StatCard, Badge, Toast
├── modules/                        # Feature pages split into subcomponents + hooks
│   ├── scans/                      # SecurityScans.tsx split into ScansTable, LaunchScanForm, LiveMonitor, ScanHistory, ScanSchedules
│   ├── inventory/                  # SoftwareInventory.tsx split into InventoryTable, PackageHistoryDrawer, OccurrencesDrawer
│   ├── vulnerabilities/            # Vulnerabilities.tsx, VulnerabilityDetail.tsx, Remediation.tsx
│   ├── projects/                   # ProjectsMicroservices.tsx
│   ├── dashboard/                  # Dashboard.tsx
│   ├── export/                     # ExportCenter.tsx
│   ├── supply-chain/               # SupplyChain.tsx
│   ├── compliance/                 # Compliance.tsx, Policies.tsx
│   ├── monitoring/                 # Monitoring.tsx, Integrations.tsx
│   └── settings/                   # Profile.tsx, Users.tsx, Settings.tsx
├── hooks/, types/, utils/, data/
```

### Key File Migration Mapping (Summary)
| Existing File | Existing Responsibility | Proposed Destination | Reason |
|---|---|---|---|
| `backend/app/api/server.py` | All 41 routes + SQL + business logic | `api/app.py` + `api/v1/endpoints/*.py` + `services/*.py` + `repositories/triage_repo.py` | Separate HTTP routing from business logic and SQL |
| `backend/app/repositories/store.py` | ScanRepo, JobQueue, BomRepo, Inventory | `repositories/scan_repo.py` + `repositories/bom_repo.py` | Split 43 KB file by domain |
| `frontend/src/api/client.ts` | All API calls & mappers | `frontend/src/api/*.ts` | Modularize 36.5 KB client by domain |
| `frontend/src/pages/scans/SecurityScans.tsx` | 212 KB multi-tab page | `modules/scans/pages/` + `modules/scans/components/` | Isolate table, launch wizard, live monitor, history, schedules |
| `frontend/src/pages/inventory/SoftwareInventory.tsx` | 123 KB catalog + drawers | `modules/inventory/pages/` + `modules/inventory/components/` | Isolate table and drawers |

---

## 9. Step-by-Step Implementation Roadmap & Regression Plan

1. **Phase 1 – Baseline & Documentation:**
   - Capture baseline test results (`pytest` across all 13 files in [backend/tests/](file:///c:/Users/Dell/Desktop/SBOM/backend/tests) + `npm --prefix frontend run build`).
   - Create `docs/database-data-dictionary.md` documenting all 12 tables, legacy column mappings (`scans.project_id` vs `catalog_project_id`), and ER diagram.
   - *Checkpoint:* Baseline tests green, documentation reviewed.
2. **Phase 2 – Backend Refactoring (Zero API Contract Changes):**
   - Extract `services/` and `repositories/triage_repo.py` from `server.py`, then split `server.py` routes into `api/v1/endpoints/*.py` registered via `api/v1/router.py`, keeping `app.api.build()` intact so [main.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/main.py), [worker.py](file:///c:/Users/Dell/Desktop/SBOM/backend/app/worker.py), and all 13 test suites work unchanged.
   - *Checkpoint:* All existing `pytest` suites pass with zero endpoint URL or payload changes.
3. **Phase 3 – Frontend Refactoring:**
   - Split `api/client.ts` by domain (re-exporting from `api/index.ts` for compatibility), decompose `SecurityScans.tsx` and `SoftwareInventory.tsx` into focused subcomponents, and remove duplicate `/components` fetching in `AppStateContext.tsx`.
   - *Checkpoint:* `tsc -b && vite build` passes; manual smoke test of Scans, Inventory, Vulnerabilities, Projects, Dashboard.
4. **Phase 4 – Database Naming & Integrity Improvements (Optional / Migration-Gated):**
   - Clean up legacy `projects` view references in backend code, standardize `inventory_change_log` IDs, and plan safe additive migrations if column/table renames are approved.
   - *Checkpoint:* Migration up/down tested on local PostgreSQL copy.
5. **Phase 5 – Performance Optimization (Measured):**
   - Benchmark `/api/v1/projects`, `AppStateContext` initial load, and scan persistence before/after introducing `psycopg_pool`, batched `facts.py` updates, and single-query `dashboard.py` aggregation.

---

### Next Step
Please review this audit and implementation plan. **No files or database objects have been modified.** Let me know if you approve proceeding with **Phase 1** (or which specific phases you would like to authorize first).
