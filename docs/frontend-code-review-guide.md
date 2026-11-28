# Frontend Architecture & Code Review Guide

This guide explains **every TypeScript/React file** in `frontend/src/`, **what logic each file holds**, **how data flows from the backend API into the UI**, and **which pages are backed by live APIs vs. UI-only/local state**. It is structured as the companion to [`docs/backend-code-review-guide.md`](file:///c:/Users/Dell/Desktop/SBOM/docs/backend-code-review-guide.md) so you can walk through the frontend cleanly in your code review.

---

## 1. The Big Picture (How the Frontend Works)

The frontend is a **React + TypeScript + Tailwind CSS** Single Page Application (built with Vite). Its data flow follows a simple 3-layer pattern:

1. **API Layer (`frontend/src/api/`):**
   - Thin, domain-separated modules (`scans.ts`, `inventory.ts`, `vulnerabilities.ts`, `projects.ts`, `catalog.ts`) built on top of one shared HTTP helper (`http.ts`).
   - Sends `X-Organization-Id: default` on every request, unwraps the backend's `{"success": true, "data": ...}` envelope, and maps raw backend snake_case fields into clean TypeScript objects.
2. **Global State Store (`frontend/src/context/AppStateContext.tsx`):**
   - Acts as the central brain of the UI. On initial load, it fetches scans, inventory components, and projects in parallel, hydrates completed scan components/vulnerabilities, and polls active scans every few seconds until they complete.
3. **Pages & Modular Components (`frontend/src/pages/` & `components/`):**
   - Pages read shared data from `useAppState()` and render tables, drawers, modals, and charts. Complex pages (`SoftwareInventory`, `SecurityScans`) are split into focused subcomponents (`components/`).

```mermaid
flowchart LR
    Backend[("FastAPI Backend")] -->|JSON Envelope| HTTP["api/http.ts"]
    HTTP --> DomainAPI["api/scans.ts, inventory.ts, projects.ts, vulnerabilities.ts, catalog.ts"]
    DomainAPI -->|Mapped Data| Store["context/AppStateContext.tsx"]
    Store -->|useAppState()| Pages["pages/* & components/*"]
    Pages -->|User Actions| Store
```

---

## 2. File-by-File Guide (`frontend/src/`)

### A. App Entry, Routing, Types & Styling

| File | What Logic It Holds |
|---|---|
| [`main.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/main.tsx) | **React Entry Point.** Mounts `<App />` into the DOM root element. |
| [`App.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/App.tsx) | **Router & Providers.** Wraps the app in `ThemeProvider` and `AppStateProvider`, renders `<Layout>`, and maps every URL path (`/dashboard`, `/security-scans/:tab`, `/software-inventory/*`, `/vulnerabilities/:cveId`, etc.) to its page component. |
| [`types/index.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/types/index.ts) | **Shared TypeScript Interfaces.** Defines all core data contracts used across the app: `Project`, `Vulnerability`, `SBOMComponent`, `ScanJob`, `BulkScanItemView`, `UserAccount`, `ToastMessage`, etc. |
| [`index.css`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/index.css) | **Global Styles.** Tailwind CSS imports, custom scrollbar styling, and fade-in animations. |

---

### B. API Client Layer (`frontend/src/api/`)

The API layer was modularized by domain (with `client.ts` and `index.ts` re-exporting everything so existing imports stay intact).

| File | What Logic It Holds |
|---|---|
| [`http.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/http.ts) | **Core Fetch Wrapper.** Defines `BASE`, `ApiError`, and `request<T>()`. Automatically sets `X-Organization-Id` and `Content-Type`, parses JSON responses, and throws `ApiError` if `success === false` or HTTP status is not OK. |
| [`scans.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/scans.ts) | **Scans API & Mappers.** Handles `preflightCheck`, `startLocalScan`, `startGithubScan`, `startBulkScan`, `listScans`, `scanStatus`, `scanEvents`, `scanComponents`, `scanVulnerabilities`, `rescan`, `cancelScan`, GitHub credential status/save, and maps backend responses to `ScanJob` and `SBOMComponent`. |
| [`inventory.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/inventory.ts) | **Inventory & Package Tracking API.** Handles `listInventoryComponents` (auto-paginating with cursor), `createInventoryComponents`, `deleteInventoryComponent`, `getPackageHistory`, `getPackageOccurrences`, `getInventoryAuditLog`, and `mapInventoryComponent`. |
| [`vulnerabilities.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/vulnerabilities.ts) | **Vulnerability & Triage API.** Handles `listTriage`, `updateVulnerabilityStatus` (`PATCH`), and `mapVulns` (combining raw CVE findings with component metadata). |
| [`projects.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/projects.ts) | **Projects & Lifecycle API.** Handles `listProjects` (`GET /api/v1/projects`) and `updateApplicationLifecycleStatus` (`PATCH /api/v1/applications/{target}/lifecycle-status`). |
| [`catalog.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/catalog.ts) | **Catalog Dropdowns API.** Handles `listCatalogProjects`, `listCatalogApplications`, `createCatalogProject`, and `createCatalogApplication` for searchable Application/Module pickers. |
| [`index.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/index.ts) & [`client.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/api/client.ts) | **Barrel Re-Exports.** Re-export all domain API modules so every page can cleanly import from `api/client` or `api/index`. |

---

### C. Global State, Hooks & Static Data

| File | What Logic It Holds |
|---|---|
| [`context/AppStateContext.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/context/AppStateContext.tsx) | **Central Application Store.** Holds `projects`, `components`, `vulnerabilities`, `scansHistory`, `activeScan`, `policies`, `notifications`, and `toasts`. Runs `refreshAppState()` on load, deduplicates scan package/CVE hydration (`loadScanResults`), polls running/queued scans in real time, and exposes actions (`startScan`, `addComponent`, `deleteComponent`, `updateVulnerabilityStatus`, `updateApplicationLifecycle`, `exportSBOM`). |
| [`context/ThemeContext.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/context/ThemeContext.tsx) | **Light/Dark Theme Store.** Persists user theme preference in `localStorage` and toggles the `dark` class on `<html>`. |
| [`hooks/useCatalogOptions.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/hooks/useCatalogOptions.ts) | **Catalog Search Hook.** Powers searchable/paginated Application and Module dropdowns with debounced API calls and abort signals. |
| [`data/mockData.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/data/mockData.ts) | **Static / Placeholder Data.** Holds initial definitions for UI-only sections (Compliance frameworks, Policies, Integrations, Users) that do not have backend endpoints yet. |

---

### D. Layout & Shared Common Components (`frontend/src/components/`)

| File | What Logic It Holds |
|---|---|
| [`layout/Layout.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/layout/Layout.tsx) | **Page Shell.** Renders the Sidebar, TopHeader, main scrollable content area, global modals (`AddProjectModal`, `AddDependencyModal`, `GlobalSearchModal`), and `ToastContainer`. |
| [`layout/Sidebar.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/layout/Sidebar.tsx), [`SidebarIcons.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/layout/SidebarIcons.tsx), [`Squad1Logo.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/layout/Squad1Logo.tsx) | **Navigation Sidebar.** Collapsible left navigation menu with grouped links (Dashboard, Security Scans, Software Inventory, Vulnerabilities, Governance, Settings). |
| [`layout/TopHeader.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/layout/TopHeader.tsx) | **Top Bar.** Displays page title, global search trigger (`Ctrl+K`), theme toggle, notification bell (`NotificationPanel`), and user menu (`UserMenuModal`). |
| [`common/TablePagination.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/TablePagination.tsx) | **Shared Table Pagination.** Reusable pagination bar with row-count summary, page-size selector (`15–100`), First/Previous/Page-Number/Next/Last buttons, and direct page jump. |
| [`common/ProjectApplicationSelect.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/ProjectApplicationSelect.tsx) & [`SearchableSelect.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/SearchableSelect.tsx) | **Dependent Application/Module Picker.** Lets users pick an existing Application and its corresponding Module (or type a new one). Clears stale Module selections automatically if the Application changes. |
| [`common/AddDependencyModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/AddDependencyModal.tsx) & [`AddProjectModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/AddProjectModal.tsx) | **Quick-Add Modals.** Modal dialogs for quickly adding a single component or project. |
| [`common/GlobalSearchModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/GlobalSearchModal.tsx) | **Global Search (`Ctrl+K`).** Searches across projects, components, CVEs, and scans from anywhere in the app. |
| [`common/VulnerabilityDrawer.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/VulnerabilityDrawer.tsx) | **Quick CVE Slide-Over.** Slide-over drawer for inspecting a vulnerability summary. |
| [`common/StatCard.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/StatCard.tsx), [`Badge.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/Badge.tsx), [`Toast.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/Toast.tsx), [`NotificationPanel.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/NotificationPanel.tsx), [`UserMenuModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/components/common/UserMenuModal.tsx) | **Shared UI Primitives.** Reusable KPI cards, severity/status pills, toast notifications, notification center popover, and user profile menu. |

---

### E. Feature Pages (`frontend/src/pages/`)

#### 1. Dashboard & Projects
| File | What Logic It Holds |
|---|---|
| [`dashboard/Dashboard.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/dashboard/Dashboard.tsx) | **Executive Overview (`/dashboard`).** Shows live KPI cards, severity distribution, compliance posture charts, top vulnerabilities, and recent scans computed from `AppStateContext`. |
| [`projects/ProjectsMicroservices.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/projects/ProjectsMicroservices.tsx) | **Applications & Modules (`/software-inventory/projects`).** Fetches `api.listProjects()`, renders KPIs, searchable/filterable application table, risk/compliance badges, and cross-links to Software Inventory and Vulnerabilities. |

#### 2. Security Scans (`frontend/src/pages/scans/`)
| File | What Logic It Holds |
|---|---|
| [`SecurityScans.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/SecurityScans.tsx) | **Main Scans Hub (`/security-scans`).** Coordinates tabs (`table`, `new`, `live`, `history`, `schedules`), handles Local file/folder upload, GitHub repo URL + PAT, Bulk Excel/CSV upload, SHA-256 duplicate pre-flight confirmation modal, and review/launch flow. |
| [`components/ScansTableTab.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/components/ScansTableTab.tsx) | **Scans Table Tab.** Searchable, filterable, paginated table of all scans showing Application Name, Module Name, Scan Date, Status, Type, Lifecycle Status (`Active`/`Decommissioned`), Created By, and `ScanActionMenu`. |
| [`components/LiveScanMonitorTab.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/components/LiveScanMonitorTab.tsx) | **Live Monitor Tab.** Real-time progress view for running/queued scans and bulk scan batches with live pipeline steps and cancel/rescan actions. |
| [`components/ScanHistoryTab.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/components/ScanHistoryTab.tsx) | **Scan History Tab.** Chronological list of past scans with status filter, clickable component/finding counts, and action menu. |
| [`components/ScanSchedulesTab.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/components/ScanSchedulesTab.tsx) | **Schedules Tab (UI-Only / `localStorage`).** Lets users configure recurring scan schedules stored in browser `localStorage`. |
| [`ScanResultDetails.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/ScanResultDetails.tsx) | **Scan Details Modal.** Shows the scan header (including Project, Status, Scan Type, and Application Version badge e.g. `v1.0.0`), 4-stage pipeline grid, discovered components & CVEs, bulk batch row table, stage logs, and export/rescan/cancel buttons. |
| [`ScanActionMenu.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/ScanActionMenu.tsx) | **3-Dot Scan Menu.** Portal-rendered responsive dropdown (auto-flips up/down and scrolls within viewport so it never clips). Includes View Details, Export (SPDX/CycloneDX/CSV), Rescan (automatically hidden when decommissioned), and Lifecycle Toggle (`Decommission` / `Mark Active`). |
| [`bulkRows.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/bulkRows.ts), [`localFolder.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/localFolder.ts), [`scanProgress.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/scans/scanProgress.ts) | **Scan Helpers.** Client-side Excel/CSV bulk row parser & duplicate detector, browser folder picker walker (skipping `node_modules`/`.git`), and 4-stage pipeline step/timestamp formatters. |

#### 3. Software Inventory & SBOM Artifacts (`frontend/src/pages/inventory/`)
| File | What Logic It Holds |
|---|---|
| [`SoftwareInventory.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/SoftwareInventory.tsx) | **Software Inventory Catalog (`/software-inventory`).** Displays all discovered and manually registered components with Application/Module scope filtering, search, multi-facet filters, package occurrence counts, CSV export (all 19 governance/SBOM fields), and pagination. |
| [`AddInventoryComponent.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/AddInventoryComponent.tsx) | **Add Component Page (`/software-inventory/add`).** Full-page form where all 12 fields are mandatory, auto-generates PURLs, and saves directly to `POST /api/v1/inventory/components` with backend error handling. |
| [`UploadInventoryModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/UploadInventoryModal.tsx) | **Bulk Inventory Excel/CSV Upload.** Parses spreadsheets and bulk-creates inventory components via `addComponents()`. |
| [`SBOMArtifacts.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/SBOMArtifacts.tsx) | **SBOM Artifacts (`/software-inventory/artifacts`).** Lists generated/uploaded SBOM artifacts, allows uploading CycloneDX/SPDX files (`parseUploadedSbom.ts`), inspecting details, and downloading in chosen formats. |
| [`InventoryActionMenu.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/InventoryActionMenu.tsx) & [`ArtifactActionMenu.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/ArtifactActionMenu.tsx) | **Row Action Menus.** 3-dot menus for inventory rows (Package History, Audit History, Delete) and artifact rows (View Details, Download). |
| [`components/PackageOccurrencesDrawer.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/PackageOccurrencesDrawer.tsx), [`PackageHistoryDrawer.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/PackageHistoryDrawer.tsx), [`InventoryAuditLogDrawer.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/InventoryAuditLogDrawer.tsx) | **Slide-Over Drawers.** Show cross-app package occurrences (`GET /api/v1/packages/{name}/occurrences`), version timeline (`GET /api/v1/packages/{name}/history`), and audit log (`GET /api/v1/inventory/audit-log` displaying resolved Application names). |
| [`components/DeleteComponentModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/DeleteComponentModal.tsx), [`IngestManifestModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/IngestManifestModal.tsx), [`AuditExportModal.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/components/AuditExportModal.tsx) | **Inventory Modals.** Delete confirmation with mandatory audit reason, manifest/SBOM quick-ingest modal, and regulatory audit dossier export modal. |
| [`parseUploadedSbom.ts`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/inventory/parseUploadedSbom.ts) | **Client-Side SBOM Parser.** Parses uploaded CycloneDX and SPDX JSON files in the browser before sending components to the backend. |

#### 4. Vulnerabilities & Remediation (`frontend/src/pages/vulnerabilities/`)
| File | What Logic It Holds |
|---|---|
| [`Vulnerabilities.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/Vulnerabilities.tsx) | **Vulnerability Management (`/vulnerabilities`).** Paginated CVE table with Application/Module/Severity/Status filters, inline automated/triage status updates (`Open` / `In Progress` / `Resolved`), justification modal when closing CVEs, and comprehensive 24-column CSV export. |
| [`VulnerabilityDetail.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/VulnerabilityDetail.tsx) | **CVE Detail Page (`/vulnerabilities/:cveId`).** Deep-dive view for one CVE: CVSS breakdown, affected components/scans, VEX status & triage update form, and remediation guidance. |
| [`VulnerabilityActionMenu.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/VulnerabilityActionMenu.tsx) | **CVE Row Action Menu.** Quick actions on a vulnerability row (View Details, Update Status, Create Ticket). |
| [`Remediation.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/vulnerabilities/Remediation.tsx) | **Remediation Tracking (`/remediation`).** Prioritized remediation queue and upgrade recommendations derived from live vulnerability findings. |

#### 5. Export, Supply Chain, Governance & Settings
| File | What Logic It Holds |
|---|---|
| [`export/ExportCenter.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/export/ExportCenter.tsx) | **Export Center (`/export-center`).** Centralized hub to export SBOMs (CycloneDX, SPDX, CSV, XLSX) and compliance/audit reports for any scanned application. |
| [`supply-chain/SupplyChain.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/supply-chain/SupplyChain.tsx) | **Supply Chain Graph (`/supply-chain`).** Visualizes direct vs. transitive dependency depth, ecosystems, and license/risk exposure across scanned applications. |
| [`compliance/Compliance.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/compliance/Compliance.tsx) & [`Policies.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/compliance/Policies.tsx) | **Governance Pages (UI-Only / Mock State).** Displays compliance framework checklists and policy toggle rules in React state/mock data (no backend persistence yet). |
| [`monitoring/Monitoring.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/monitoring/Monitoring.tsx) & [`Integrations.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/monitoring/Integrations.tsx) | **Monitoring & Integrations (UI-Only / `localStorage`).** Shows alert rules and CI/CD integration cards (GitHub PAT integration on Security Scans connects to the live backend; remaining cards are UI-only). |
| [`settings/Profile.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/settings/Profile.tsx), [`Users.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/settings/Users.tsx), [`Settings.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/settings/Settings.tsx) | **Settings Pages (UI-Only / Mock State).** User profile, RBAC user directory, and workspace preferences. |
| [`common/NotFound.tsx`](file:///c:/Users/Dell/Desktop/SBOM/frontend/src/pages/common/NotFound.tsx) | **404 Fallback.** Shown for unknown routes. |

---

## 3. Connected Frontend-to-Backend Flows

1. **App Startup & Hydration (`AppStateContext.tsx`):**
   - Calls `listScans()`, `listInventoryComponents()`, and `listProjects()` in parallel (`Promise.all`).
   - For completed scans, calls `loadScanResults()` (single pass per scan—no duplicate `/components` calls) to populate `components` and `vulnerabilities` in context.
2. **Launching a Scan (`SecurityScans.tsx` → `AppStateContext.tsx`):**
   - User picks Application & Module (`ProjectApplicationSelect` → `useCatalogOptions`) and selects Local file/folder, GitHub repo, or Bulk spreadsheet.
   - Runs `api.preflightCheck()` first to warn on duplicate uploads, then submits `startScan()`.
   - `AppStateContext` polls `api.scanStatus()` and `api.scanEvents()` until `completed`, then automatically refreshes Projects, Inventory, and Vulnerabilities.
3. **Manual Component Registration (`AddInventoryComponent.tsx` → `AppStateContext.tsx`):**
   - Validates all 12 mandatory fields in the browser, calls `POST /api/v1/inventory/components`, updates React state immediately on `201 Created`, and refreshes Projects + Inventory.
4. **Vulnerability Triage (`Vulnerabilities.tsx` / `VulnerabilityDetail.tsx` → `AppStateContext.tsx`):**
   - Changing a CVE status to `Resolved`/`Closed` prompts for a mandatory justification, calls `PATCH /api/v1/vulnerabilities/{cve}/status`, and updates both local state and backend `vulnerability_triage` + `findings`.

---

## 4. Flow Status Check (Live Backend vs. UI-Only)

| Feature Area | Connected to Backend? | Status |
|---|---|---|
| **Dashboard KPIs & Charts** | Yes (`GET /api/v1/projects`, `/scans`, `/inventory/components`) | **Working Properly** |
| **Security Scans (Local, GitHub, Bulk, Live Monitor, Details, Lifecycle)** | Yes (`POST/GET /api/v1/scans/*`, `/bulk-scans/*`) | **Working Properly** |
| **Software Inventory (List, Add, Upload, Delete, Occurrences, History, Audit Log, CSV Export)** | Yes (`GET/POST/DELETE /api/v1/inventory/*`, `/packages/*`) | **Working Properly** |
| **Projects & Microservices** | Yes (`GET /api/v1/projects`) | **Working Properly** |
| **Vulnerabilities & Triage** | Yes (`GET /api/v1/vulnerabilities/*`, `PATCH .../status`) | **Working Properly** |
| **SBOM Artifacts & Export Center** | Yes (`GET /api/v1/boms/*/export`) | **Working Properly** |
| **Scan Schedules, Compliance, Policies, Monitoring, Users, Settings** | No (Browser `localStorage` / `mockData.ts`) | **UI-Only (Planned for future backend phase)** |
