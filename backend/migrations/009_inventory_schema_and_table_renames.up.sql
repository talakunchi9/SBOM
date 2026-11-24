-- Migration 009: 39-Field Inventory Requirements & Table Renaming
-- Renaming:
--   projects     -> applications
--   applications -> modules
-- Adds baseline fields: readable_id, business_owner, technical_owner, development_type, vendor_name, lifecycle_status,
--                       module path, programming_language, package_manager, module_type,
--                       scan trigger, generation_context,
--                       component detection_method, confidence, classification.

-- 1 & 2. Idempotent Rename of applications -> modules and projects -> applications
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'applications' AND table_schema = 'public') 
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'modules' AND table_schema = 'public') THEN
    ALTER TABLE applications RENAME TO modules;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'projects' AND table_schema = 'public') 
     AND NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'applications' AND table_schema = 'public') THEN
    ALTER TABLE projects RENAME TO applications;
  END IF;
END $$;

-- Set default UUID generator on primary keys if not present
ALTER TABLE applications ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE modules ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE scans ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE sboms ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE sbom_components ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;
ALTER TABLE inventory_components ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;

-- Default timestamps and required keys
ALTER TABLE applications ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE modules ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE scans ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE scans ALTER COLUMN idempotency_key SET DEFAULT gen_random_uuid()::text;
ALTER TABLE scans ALTER COLUMN scan_status SET DEFAULT 'completed';
ALTER TABLE sboms ALTER COLUMN generated_at SET DEFAULT NOW();
ALTER TABLE sboms ALTER COLUMN bom_type SET DEFAULT 'cyclonedx';
ALTER TABLE sbom_components ALTER COLUMN created_at SET DEFAULT NOW();
ALTER TABLE sbom_components ALTER COLUMN ecosystem SET DEFAULT 'generic';
ALTER TABLE inventory_components ALTER COLUMN created_at SET DEFAULT NOW();

-- 3. In modules (formerly applications):
-- Rename foreign key column project_id to application_id if not already renamed
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'project_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'application_id') THEN
    ALTER TABLE modules RENAME COLUMN project_id TO application_id;
  END IF;
END $$;

-- Add new baseline columns to modules
ALTER TABLE modules ADD COLUMN IF NOT EXISTS path TEXT NOT NULL DEFAULT '/';
ALTER TABLE modules ADD COLUMN IF NOT EXISTS programming_language TEXT NOT NULL DEFAULT '';
ALTER TABLE modules ADD COLUMN IF NOT EXISTS package_manager TEXT NOT NULL DEFAULT '';
ALTER TABLE modules ADD COLUMN IF NOT EXISTS module_type TEXT NOT NULL DEFAULT 'Microservice';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_modules_module_type') THEN
    ALTER TABLE modules DROP CONSTRAINT chk_modules_module_type;
  END IF;
  ALTER TABLE modules ADD CONSTRAINT chk_modules_module_type 
    CHECK (module_type IN ('Library', 'Microservice', 'Frontend', 'Service', 'Backend', 'Mobile', 'Other'));
END $$;

-- 4. In applications (formerly projects):
ALTER TABLE applications ADD COLUMN IF NOT EXISTS readable_id TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS business_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS technical_owner TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS development_type TEXT NOT NULL DEFAULT 'In-house';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS vendor_name TEXT NOT NULL DEFAULT '';
ALTER TABLE applications ADD COLUMN IF NOT EXISTS lifecycle_status TEXT NOT NULL DEFAULT 'Active';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_applications_dev_type') THEN
    ALTER TABLE applications DROP CONSTRAINT chk_applications_dev_type;
  END IF;
  ALTER TABLE applications ADD CONSTRAINT chk_applications_dev_type 
    CHECK (development_type IN ('In-house', 'Outsourced', 'Vendor'));

  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_applications_lifecycle') THEN
    ALTER TABLE applications DROP CONSTRAINT chk_applications_lifecycle;
  END IF;
  ALTER TABLE applications ADD CONSTRAINT chk_applications_lifecycle 
    CHECK (lifecycle_status IN ('Active', 'Deprecated', 'Archived', 'Planned', 'Decommissioned'));
END $$;

-- Backfill readable_id for existing applications (APP-0001, APP-0002, ...)
WITH numbered AS (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY organization_id ORDER BY created_at, id) as rn
  FROM applications
  WHERE readable_id = '' OR readable_id IS NULL
)
UPDATE applications a
SET readable_id = 'APP-' || LPAD(numbered.rn::text, 4, '0')
FROM numbered
WHERE a.id = numbered.id AND (a.readable_id = '' OR a.readable_id IS NULL);

-- Create sequence generator function for auto-generating readable_id (APP-0001, APP-0002...)
CREATE OR REPLACE FUNCTION generate_next_readable_app_id()
RETURNS TRIGGER AS $$
DECLARE
  v_next_num INTEGER;
  v_prefix TEXT := 'APP-';
BEGIN
  IF NEW.readable_id IS NULL OR NEW.readable_id = '' THEN
    SELECT COALESCE(MAX(
      NULLIF(regexp_replace(readable_id, '^APP-', ''), '')::INTEGER
    ), 0) + 1
    INTO v_next_num
    FROM applications
    WHERE organization_id = NEW.organization_id;

    NEW.readable_id := v_prefix || LPAD(v_next_num::text, 4, '0');
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_applications_readable_id ON applications;
CREATE TRIGGER trg_applications_readable_id
BEFORE INSERT ON applications
FOR EACH ROW
EXECUTE FUNCTION generate_next_readable_app_id();

-- Unique indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_org_readable_id 
  ON applications(organization_id, readable_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_applications_org_lower_name 
  ON applications(organization_id, lower(name));

-- 5. In scans:
ALTER TABLE scans ADD COLUMN IF NOT EXISTS trigger TEXT NOT NULL DEFAULT 'Manual';
ALTER TABLE scans ADD COLUMN IF NOT EXISTS generation_context TEXT NOT NULL DEFAULT 'Development';

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_trigger') THEN
    ALTER TABLE scans DROP CONSTRAINT chk_scans_trigger;
  END IF;
  ALTER TABLE scans ADD CONSTRAINT chk_scans_trigger 
    CHECK (trigger IN ('Manual', 'Webhook', 'CI_CD', 'CI/CD', 'Scheduled', 'API', 'CLI'));

  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_scans_gen_context') THEN
    ALTER TABLE scans DROP CONSTRAINT chk_scans_gen_context;
  END IF;
  ALTER TABLE scans ADD CONSTRAINT chk_scans_gen_context 
    CHECK (generation_context IN ('Development', 'Testing', 'Staging', 'Production', 'Pre-production', 'Source', 'Build', 'Binary', 'Deployed'));
END $$;

-- 6. In sbom_components:
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS detection_method TEXT NOT NULL DEFAULT 'Manifest / Lockfile';
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS confidence INTEGER NOT NULL DEFAULT 100;
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS classification TEXT NOT NULL DEFAULT 'External';
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS first_detected_at TIMESTAMPTZ;
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS last_detected_at TIMESTAMPTZ;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_sbom_components_confidence') THEN
    ALTER TABLE sbom_components DROP CONSTRAINT chk_sbom_components_confidence;
  END IF;
  ALTER TABLE sbom_components ADD CONSTRAINT chk_sbom_components_confidence 
    CHECK (confidence >= 0 AND confidence <= 100);

  IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_sbom_components_classification') THEN
    ALTER TABLE sbom_components DROP CONSTRAINT chk_sbom_components_classification;
  END IF;
  ALTER TABLE sbom_components ADD CONSTRAINT chk_sbom_components_classification 
    CHECK (classification IN ('Internal', 'External', 'Vendor', 'Unknown'));
END $$;

-- 7. In inventory_components:
-- Rename columns: application_id -> module_id, project_id -> application_id
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'application_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'module_id') THEN
    ALTER TABLE inventory_components RENAME COLUMN application_id TO module_id;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'project_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'application_id') THEN
    ALTER TABLE inventory_components RENAME COLUMN project_id TO application_id;
  END IF;
END $$;

-- 8. In vulnerability_triage:
ALTER TABLE vulnerability_triage ADD COLUMN IF NOT EXISTS module_name TEXT NOT NULL DEFAULT '';
UPDATE vulnerability_triage SET module_name = application_name WHERE module_name = '' OR module_name IS NULL;

-- 9. Backward-compatible view for legacy queries expecting 'projects'
CREATE OR REPLACE VIEW projects AS 
  SELECT * FROM applications;
