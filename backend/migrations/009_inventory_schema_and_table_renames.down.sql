-- Migration 009 Rollback: Revert 39-Field Inventory Requirements & Table Renaming

DROP VIEW IF EXISTS projects;

-- 1. In inventory_components:
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'application_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'project_id') THEN
    ALTER TABLE inventory_components RENAME COLUMN application_id TO project_id;
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'module_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'inventory_components' AND column_name = 'application_id') THEN
    ALTER TABLE inventory_components RENAME COLUMN module_id TO application_id;
  END IF;
END $$;

-- 2. In sbom_components:
ALTER TABLE sbom_components DROP COLUMN IF EXISTS classification;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS confidence;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS detection_method;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS first_detected_at;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS last_detected_at;

-- 3. In scans:
ALTER TABLE scans DROP COLUMN IF EXISTS generation_context;
ALTER TABLE scans DROP COLUMN IF EXISTS trigger;

-- 4. In applications (revert back to projects):
DROP TRIGGER IF EXISTS trg_applications_readable_id ON applications;
DROP FUNCTION IF EXISTS trg_assign_readable_app_id();
DROP FUNCTION IF EXISTS generate_next_readable_app_id(TEXT);
DROP INDEX IF EXISTS idx_applications_org_readable_id;
DROP INDEX IF EXISTS idx_applications_org_lower_name;

ALTER TABLE applications DROP COLUMN IF EXISTS lifecycle_status;
ALTER TABLE applications DROP COLUMN IF EXISTS vendor_name;
ALTER TABLE applications DROP COLUMN IF EXISTS development_type;
ALTER TABLE applications DROP COLUMN IF EXISTS technical_owner;
ALTER TABLE applications DROP COLUMN IF EXISTS business_owner;
ALTER TABLE applications DROP COLUMN IF EXISTS readable_id;

-- 5. In modules (revert back to applications):
ALTER TABLE modules DROP COLUMN IF EXISTS module_type;
ALTER TABLE modules DROP COLUMN IF EXISTS package_manager;
ALTER TABLE modules DROP COLUMN IF EXISTS programming_language;
ALTER TABLE modules DROP COLUMN IF EXISTS path;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'application_id')
     AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'modules' AND column_name = 'project_id') THEN
    ALTER TABLE modules RENAME COLUMN application_id TO project_id;
  END IF;
END $$;

-- 6. Rename tables back:
ALTER TABLE IF EXISTS applications RENAME TO projects;
ALTER TABLE IF EXISTS modules RENAME TO applications;
