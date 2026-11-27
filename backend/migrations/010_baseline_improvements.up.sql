-- Migration 010: Database Deduplication, Component Identity & Inventory Audit Log

-- 1. Deduplicate existing sbom_components (keep latest created_at or ctid)
DELETE FROM sbom_components a USING sbom_components b
WHERE a.ctid < b.ctid
  AND a.sbom_id = b.sbom_id
  AND a.name = b.name
  AND a.version = b.version
  AND COALESCE(a.package_url, '') = COALESCE(b.package_url, '')
  AND COALESCE(a.source_manifest, '') = COALESCE(b.source_manifest, '');

-- 2. Deduplicate existing inventory_components
DELETE FROM inventory_components a USING inventory_components b
WHERE a.ctid < b.ctid
  AND a.module_id = b.module_id
  AND a.name = b.name
  AND a.version = b.version
  AND COALESCE(a.package_url, '') = COALESCE(b.package_url, '')
  AND COALESCE(a.source_file_name, '') = COALESCE(b.source_file_name, '');

-- 3. Unique indices to prevent duplicate component insertions (guarantee idempotency)
CREATE UNIQUE INDEX IF NOT EXISTS uq_sbom_components_identity 
ON sbom_components (sbom_id, name, version, COALESCE(package_url, ''), COALESCE(source_manifest, ''));

CREATE UNIQUE INDEX IF NOT EXISTS uq_inventory_components_identity
ON inventory_components (module_id, name, version, COALESCE(package_url, ''), COALESCE(source_file_name, ''));

-- 4. Inventory Change & Audit Log Table (Tracking Add, Edit, Remove with Reason & History)
CREATE TABLE IF NOT EXISTS inventory_change_log (
    id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL DEFAULT 'default',
    application_id TEXT NOT NULL DEFAULT '',
    module_id TEXT NOT NULL DEFAULT '',
    component_name TEXT NOT NULL,
    component_version TEXT NOT NULL,
    action TEXT NOT NULL, -- 'ADD', 'EDIT', 'REMOVE', 'STATUS_CHANGE', 'AUTO_SCAN'
    old_value JSONB,
    new_value JSONB,
    reason TEXT NOT NULL DEFAULT '',
    changed_by TEXT NOT NULL DEFAULT 'SYSTEM',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_inventory_change_log_comp 
ON inventory_change_log (component_name, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_inventory_change_log_app_mod 
ON inventory_change_log (application_id, module_id, created_at DESC);

-- 5. Expand chk_applications_lifecycle to support 'Inactive'
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_applications_lifecycle') THEN
    ALTER TABLE applications DROP CONSTRAINT chk_applications_lifecycle;
  END IF;
  ALTER TABLE applications ADD CONSTRAINT chk_applications_lifecycle 
    CHECK (lifecycle_status IN ('Active', 'Inactive', 'Deprecated', 'Archived', 'Planned', 'Decommissioned'));
END $$;
