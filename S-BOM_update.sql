-- ============================================================================
-- S-BOM Database Schema (Latest Production Schema - Baseline 010)
-- ============================================================================
-- Project:        Software Bill of Materials (S-BOM) Management Platform
-- File:           S-BOM_update.sql
-- Compatibility:  PostgreSQL 14, 15, 16, 17, 18+
-- Description:    Comprehensive, cleanly formatted single SQL file containing
--                 the complete and latest relational schema (migrations 001–010),
--                 helper & trigger functions, table constraints, foreign key
--                 relationships, performance & deduplication indexes,
--                 documentation comments, and migration baseline.
-- ============================================================================
--
-- ENTITY RELATIONSHIP HIERARCHY:
--
--  organizations (Tenant root)
--   ├── applications (formerly projects; auto readable_id APP-0001)
--   │     ├── modules (formerly applications)
--   │     │     └── inventory_components (manual / uploaded catalog)
--   │     └── projects (backward-compatible VIEW -> applications)
--   ├── credentials
--   ├── scans
--   │     └── sboms
--   │           └── sbom_components
--   │                 └── findings
--   │                       └── vulnerabilities
--   ├── vulnerability_triage (Cross-scan triage & VEX overrides)
--   └── inventory_change_log (Audit log for inventory & vuln status changes)
--
-- ============================================================================

-- ----------------------------------------------------------------------------
-- 1. Session & Environment Configuration
-- ----------------------------------------------------------------------------
SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;
SET row_security = off;

-- Set search path to public schema
SELECT pg_catalog.set_config('search_path', 'public', false);


-- ----------------------------------------------------------------------------
-- 2. Clean Teardown (Safe drops in reverse dependency order)
-- ----------------------------------------------------------------------------
DROP VIEW IF EXISTS projects CASCADE;

DROP TABLE IF EXISTS inventory_change_log CASCADE;
DROP TABLE IF EXISTS vulnerability_triage CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS sbom_components CASCADE;
DROP TABLE IF EXISTS sboms CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS inventory_components CASCADE;
DROP TABLE IF EXISTS modules CASCADE;
DROP TABLE IF EXISTS applications CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS schema_migrations CASCADE;

DROP FUNCTION IF EXISTS generate_next_readable_app_id() CASCADE;
DROP FUNCTION IF EXISTS sbom_jsonb(text) CASCADE;
DROP FUNCTION IF EXISTS sbom_score(text) CASCADE;


-- ----------------------------------------------------------------------------
-- 3. Stored Functions
-- ----------------------------------------------------------------------------

-- Function: sbom_jsonb
-- Safely parses a text payload into jsonb, returning '{}'::jsonb on null/invalid.
CREATE OR REPLACE FUNCTION sbom_jsonb(raw text)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
AS $$
BEGIN
  IF raw IS NULL OR btrim(raw) = '' THEN
    RETURN '{}'::jsonb;
  END IF;
  RETURN raw::jsonb;
EXCEPTION WHEN others THEN
  RETURN '{}'::jsonb;
END;
$$;

-- Function: sbom_score
-- Safely parses and normalizes a CVSS numeric score within [0.0, 10.0].
CREATE OR REPLACE FUNCTION sbom_score(raw text)
RETURNS numeric
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  n numeric;
BEGIN
  IF raw IS NULL OR btrim(raw) = '' THEN
    RETURN 0;
  END IF;
  n := raw::numeric;
  IF n < 0 THEN
    RETURN 0;
  END IF;
  IF n > 10 THEN
    RETURN 10;
  END IF;
  RETURN round(n, 1);
EXCEPTION WHEN others THEN
  RETURN 0;
END;
$$;

-- Function: generate_next_readable_app_id
-- Auto-generates sequential readable IDs (APP-0001, APP-0002, ...) per organization.
CREATE OR REPLACE FUNCTION generate_next_readable_app_id()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
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
$$;


-- ----------------------------------------------------------------------------
-- 4. Core Relational Tables & Views
-- ----------------------------------------------------------------------------

-- Table 1: organizations
-- Tenant. Applications, scans, and credentials belong to one organization.
CREATE TABLE organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: applications (formerly projects)
-- Top-level application catalog for one organization.
CREATE TABLE applications (
    id                TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    organization_id   TEXT NOT NULL,
    name              TEXT NOT NULL,
    readable_id       TEXT NOT NULL DEFAULT '',
    business_owner    TEXT NOT NULL DEFAULT '',
    technical_owner   TEXT NOT NULL DEFAULT '',
    development_type  TEXT NOT NULL DEFAULT 'In-house',
    vendor_name       TEXT NOT NULL DEFAULT '',
    lifecycle_status  TEXT NOT NULL DEFAULT 'Active',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT projects_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT projects_organization_id_name_key UNIQUE (organization_id, name),
    CONSTRAINT projects_id_organization_id_key UNIQUE (id, organization_id),
    CONSTRAINT chk_applications_dev_type CHECK (development_type IN ('In-house', 'Outsourced', 'Vendor')),
    CONSTRAINT chk_applications_lifecycle CHECK (lifecycle_status IN ('Active', 'Inactive', 'Deprecated', 'Archived', 'Planned', 'Decommissioned'))
);

CREATE TRIGGER trg_applications_readable_id
BEFORE INSERT ON applications
FOR EACH ROW
EXECUTE FUNCTION generate_next_readable_app_id();

-- Backward-compatible view for legacy queries expecting 'projects'
CREATE OR REPLACE VIEW projects AS
    SELECT * FROM applications;

-- Table 3: modules (formerly applications)
-- Microservice, service, or sub-module that belongs to one application.
CREATE TABLE modules (
    id                    TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    application_id        TEXT NOT NULL,
    organization_id       TEXT NOT NULL,
    name                  TEXT NOT NULL,
    path                  TEXT NOT NULL DEFAULT '/',
    programming_language  TEXT NOT NULL DEFAULT '',
    package_manager       TEXT NOT NULL DEFAULT '',
    module_type           TEXT NOT NULL DEFAULT 'Microservice',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT applications_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT applications_organization_id_project_id_name_key UNIQUE (organization_id, application_id, name),
    CONSTRAINT applications_id_project_id_organization_id_key UNIQUE (id, application_id, organization_id),
    CONSTRAINT chk_modules_module_type CHECK (module_type IN ('Library', 'Microservice', 'Frontend', 'Service', 'Backend', 'Mobile', 'Other'))
);

-- Table 4: inventory_components
-- Package tracked on an application/module in the software inventory.
CREATE TABLE inventory_components (
    id                    TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    organization_id       TEXT NOT NULL,
    application_id        TEXT NOT NULL,
    module_id             TEXT NOT NULL,
    name                  TEXT NOT NULL,
    package_name          TEXT NOT NULL,
    version               TEXT NOT NULL,
    component_type        TEXT NOT NULL DEFAULT 'Library',
    source_file_name      TEXT NOT NULL DEFAULT '',
    license_name          TEXT NOT NULL DEFAULT 'Unknown',
    package_url           TEXT NOT NULL DEFAULT '',
    ecosystem             TEXT NOT NULL DEFAULT 'npm',
    risk_level            TEXT NOT NULL DEFAULT 'Safe',
    vulnerability_count   INTEGER NOT NULL DEFAULT 0,
    is_direct_dependency  BOOLEAN NOT NULL DEFAULT TRUE,
    supplier_name         TEXT NOT NULL DEFAULT '',
    created_by            TEXT NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT inventory_components_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT inventory_components_version_check CHECK (length(btrim(version)) > 0),
    CONSTRAINT inventory_components_vulnerability_count_check CHECK (vulnerability_count >= 0)
);

-- Table 5: inventory_change_log
-- Audit trail for manual inventory additions/removals and vulnerability status transitions.
CREATE TABLE inventory_change_log (
    id                 TEXT PRIMARY KEY,
    organization_id    TEXT NOT NULL DEFAULT 'default',
    application_id     TEXT NOT NULL DEFAULT '',
    module_id          TEXT NOT NULL DEFAULT '',
    component_name     TEXT NOT NULL,
    component_version  TEXT NOT NULL,
    action             TEXT NOT NULL,
    old_value          JSONB,
    new_value          JSONB,
    reason             TEXT NOT NULL DEFAULT '',
    changed_by         TEXT NOT NULL DEFAULT 'SYSTEM',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table 6: credentials
-- Git credentials and encrypted secrets.
CREATE TABLE credentials (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL,
    provider            TEXT NOT NULL,
    credential_type     TEXT NOT NULL,
    name                TEXT NOT NULL,
    secret_reference    TEXT,
    secret_nonce        BYTEA,
    secret_ciphertext   BYTEA,
    repository_scope    TEXT NOT NULL DEFAULT '*',
    status              TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    last_validated_at   TIMESTAMPTZ,
    expires_at          TIMESTAMPTZ
);

-- Table 7: scans
-- One scan execution, queue tracking, bulk row metadata, and progress events.
CREATE TABLE scans (
    id                      TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    organization_id         TEXT NOT NULL,
    project_id              TEXT NOT NULL DEFAULT '',
    application_id          TEXT NOT NULL DEFAULT '',
    application_name        TEXT NOT NULL DEFAULT '',
    application_version     TEXT NOT NULL DEFAULT '',
    description             TEXT NOT NULL DEFAULT '',
    version_strategy        TEXT NOT NULL DEFAULT '',
    bom_type                TEXT NOT NULL DEFAULT 'SBOM',
    source_type             TEXT NOT NULL DEFAULT '',
    scan_status             TEXT NOT NULL DEFAULT 'completed',
    scan_stage              TEXT NOT NULL DEFAULT '',
    error_code              TEXT NOT NULL DEFAULT '',
    error_message           TEXT NOT NULL DEFAULT '',
    idempotency_key         TEXT NOT NULL UNIQUE DEFAULT (gen_random_uuid())::text,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at              TIMESTAMPTZ,
    completed_at            TIMESTAMPTZ,
    bulk_scan_id            TEXT,
    bulk_row_number         INTEGER NOT NULL DEFAULT 0,
    bulk_file_name          TEXT NOT NULL DEFAULT '',
    bulk_status             TEXT NOT NULL DEFAULT '',
    bulk_total_rows         INTEGER NOT NULL DEFAULT 0,
    bulk_invalid_rows       INTEGER NOT NULL DEFAULT 0,
    bulk_errors             TEXT,
    sbom_id                 TEXT,
    catalog_project_id      TEXT,
    catalog_application_id  TEXT,
    repository_url          TEXT NOT NULL DEFAULT '',
    branch                  TEXT NOT NULL DEFAULT '',
    job_status              TEXT NOT NULL DEFAULT '',
    job_payload             TEXT NOT NULL DEFAULT '{}',
    priority                INTEGER NOT NULL DEFAULT 0,
    attempts                INTEGER NOT NULL DEFAULT 0,
    max_attempts            INTEGER NOT NULL DEFAULT 3,
    next_attempt_at         TIMESTAMPTZ,
    job_started_at          TIMESTAMPTZ,
    job_completed_at        TIMESTAMPTZ,
    job_error_code          TEXT NOT NULL DEFAULT '',
    job_error_message       TEXT NOT NULL DEFAULT '',
    events                  JSONB NOT NULL DEFAULT '[]'::jsonb,
    trigger                 TEXT NOT NULL DEFAULT 'Manual',
    generation_context      TEXT NOT NULL DEFAULT 'Development',
    CONSTRAINT chk_scans_trigger CHECK (trigger IN ('Manual', 'Webhook', 'CI_CD', 'CI/CD', 'Scheduled', 'API', 'CLI')),
    CONSTRAINT chk_scans_gen_context CHECK (generation_context IN ('Development', 'Testing', 'Staging', 'Production', 'Pre-production', 'Source', 'Build', 'Binary', 'Deployed'))
);

-- Table 8: sboms
-- Software Bill of Materials produced by scans, including VCS repository and commit details.
CREATE TABLE sboms (
    id                      TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    organization_id         TEXT NOT NULL,
    project_id              TEXT NOT NULL DEFAULT '',
    application_id          TEXT NOT NULL DEFAULT '',
    scan_id                 TEXT NOT NULL,
    catalog_project_id      TEXT,
    catalog_application_id  TEXT,
    bom_type                TEXT NOT NULL DEFAULT 'cyclonedx',
    application_version     TEXT NOT NULL DEFAULT '',
    version_strategy        TEXT NOT NULL DEFAULT '',
    repository_url          TEXT NOT NULL DEFAULT '',
    repository_branch       TEXT NOT NULL DEFAULT '',
    commit_sha              TEXT NOT NULL DEFAULT '',
    commit_author           TEXT NOT NULL DEFAULT '',
    commit_email            TEXT NOT NULL DEFAULT '',
    commit_message          TEXT NOT NULL DEFAULT '',
    scanner_name            TEXT NOT NULL,
    scanner_version         TEXT NOT NULL,
    bom_format_version      TEXT NOT NULL DEFAULT '',
    generated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw_metadata            TEXT,
    file_name               TEXT NOT NULL DEFAULT '',
    file_format             TEXT NOT NULL DEFAULT '',
    file_size_bytes         BIGINT NOT NULL DEFAULT 0,
    signature_status        TEXT NOT NULL DEFAULT '',
    facts_normalized        BOOLEAN NOT NULL DEFAULT FALSE
);

-- Table 9: sbom_components
-- Package or dependency found in an SBOM, including NTIA compliance checks and dependency links.
CREATE TABLE sbom_components (
    id                    TEXT PRIMARY KEY DEFAULT (gen_random_uuid())::text,
    sbom_id               TEXT NOT NULL,
    name                  TEXT NOT NULL,
    version               TEXT NOT NULL,
    ecosystem             TEXT NOT NULL DEFAULT 'generic',
    package_manager       TEXT NOT NULL DEFAULT '',
    package_url           TEXT NOT NULL DEFAULT '',
    cpe                   TEXT NOT NULL DEFAULT '',
    content_hash          TEXT NOT NULL DEFAULT '',
    license_name          TEXT NOT NULL DEFAULT '',
    supplier_name         TEXT NOT NULL DEFAULT '',
    dependency_scope      TEXT NOT NULL DEFAULT 'runtime',
    is_direct_dependency  BOOLEAN NOT NULL DEFAULT FALSE,
    source_manifest       TEXT NOT NULL DEFAULT '',
    raw_component         TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dependency_depth      INTEGER,
    ntia_supplier         BOOLEAN,
    ntia_name             BOOLEAN,
    ntia_version          BOOLEAN,
    ntia_identifier       BOOLEAN,
    ntia_relationship     BOOLEAN,
    ntia_author           BOOLEAN,
    ntia_timestamp        BOOLEAN,
    depends_on            TEXT[] NOT NULL DEFAULT '{}'::text[],
    detection_method      TEXT NOT NULL DEFAULT 'Manifest / Lockfile',
    confidence            INTEGER NOT NULL DEFAULT 100,
    classification        TEXT NOT NULL DEFAULT 'External',
    first_detected_at     TIMESTAMPTZ,
    last_detected_at      TIMESTAMPTZ,
    CONSTRAINT sbom_components_id_sbom_id_key UNIQUE (id, sbom_id),
    CONSTRAINT sbom_components_dependency_depth_check CHECK (dependency_depth IS NULL OR dependency_depth >= 0),
    CONSTRAINT chk_sbom_components_confidence CHECK (confidence >= 0 AND confidence <= 100),
    CONSTRAINT chk_sbom_components_classification CHECK (classification IN ('Internal', 'External', 'Vendor', 'Unknown'))
);

-- Table 10: vulnerabilities
-- Canonical CVE repository with CVSS metrics and advisory references.
CREATE TABLE vulnerabilities (
    id                  TEXT PRIMARY KEY,
    vulnerability_key   TEXT NOT NULL UNIQUE,
    source              TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score          NUMERIC NOT NULL DEFAULT 0,
    cvss_vector         TEXT NOT NULL DEFAULT '',
    description         TEXT NOT NULL DEFAULT '',
    reference_urls      TEXT[] NOT NULL DEFAULT '{}'::text[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerabilities_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    CONSTRAINT vulnerabilities_cvss_score_check CHECK (cvss_score >= 0 AND cvss_score <= 10)
);

-- Table 11: findings
-- One vulnerability match for one package in one SBOM, with triage lifecycle status.
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    sbom_id             TEXT NOT NULL,
    sbom_component_id   TEXT NOT NULL,
    vulnerability_id    TEXT NOT NULL,
    source              TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score          NUMERIC NOT NULL DEFAULT 0,
    cvss_vector         TEXT NOT NULL DEFAULT '',
    description         TEXT NOT NULL DEFAULT '',
    fixed_version       TEXT NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status              TEXT NOT NULL DEFAULT 'Open',
    vex_status          TEXT NOT NULL DEFAULT 'affected',
    ticket_id           TEXT NOT NULL DEFAULT '',
    owner               TEXT NOT NULL DEFAULT '',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT findings_sbom_component_id_vulnerability_id_key UNIQUE (sbom_component_id, vulnerability_id),
    CONSTRAINT findings_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    CONSTRAINT findings_cvss_score_check CHECK (cvss_score >= 0 AND cvss_score <= 10)
);

-- Table 12: vulnerability_triage
-- Persistent triage overrides, VEX statements, tickets, and justifications across scans.
CREATE TABLE vulnerability_triage (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL DEFAULT 'default',
    vulnerability_key   TEXT NOT NULL,
    project_name        TEXT NOT NULL DEFAULT '',
    application_name    TEXT NOT NULL DEFAULT '',
    module_name         TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'Open',
    vex_status          TEXT NOT NULL DEFAULT 'affected',
    ticket_id           TEXT NOT NULL DEFAULT '',
    owner               TEXT NOT NULL DEFAULT '',
    justification       TEXT NOT NULL DEFAULT '',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerability_triage_organization_id_vulnerability_key_proj_key
        UNIQUE (organization_id, vulnerability_key, project_name, application_name)
);

-- Table 13: schema_migrations
-- Database migration version history tracker.
CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ----------------------------------------------------------------------------
-- 5. Foreign Key Constraints
-- ----------------------------------------------------------------------------

-- Applications -> Organizations
ALTER TABLE applications
    ADD CONSTRAINT projects_organization_id_fkey
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

-- Modules -> Applications
ALTER TABLE modules
    ADD CONSTRAINT applications_project_id_organization_id_fkey
    FOREIGN KEY (application_id, organization_id)
    REFERENCES applications(id, organization_id)
    ON DELETE CASCADE;

-- Inventory Components -> Organizations, Applications, Modules
ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_organization
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_project
    FOREIGN KEY (application_id, organization_id)
    REFERENCES applications(id, organization_id)
    ON DELETE CASCADE;

ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_application
    FOREIGN KEY (module_id, application_id, organization_id)
    REFERENCES modules(id, application_id, organization_id)
    ON DELETE CASCADE;

-- Credentials -> Organizations
ALTER TABLE credentials
    ADD CONSTRAINT fk_credentials_organization
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

-- Scans -> Organizations, Applications, Modules, SBOMs
ALTER TABLE scans
    ADD CONSTRAINT scans_organization_id_fkey
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_catalog_project
    FOREIGN KEY (catalog_project_id, organization_id)
    REFERENCES applications(id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_catalog_application
    FOREIGN KEY (catalog_application_id, catalog_project_id, organization_id)
    REFERENCES modules(id, application_id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_sbom
    FOREIGN KEY (sbom_id)
    REFERENCES sboms(id)
    ON DELETE SET NULL;

-- SBOMs -> Organizations, Scans, Applications, Modules
ALTER TABLE sboms
    ADD CONSTRAINT fk_sboms_organization
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

ALTER TABLE sboms
    ADD CONSTRAINT fk_sboms_scan
    FOREIGN KEY (scan_id)
    REFERENCES scans(id)
    ON DELETE CASCADE;

ALTER TABLE sboms
    ADD CONSTRAINT fk_sboms_catalog_project
    FOREIGN KEY (catalog_project_id, organization_id)
    REFERENCES applications(id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE sboms
    ADD CONSTRAINT fk_sboms_catalog_application
    FOREIGN KEY (catalog_application_id, catalog_project_id, organization_id)
    REFERENCES modules(id, application_id, organization_id)
    ON DELETE RESTRICT;

-- SBOM Components -> SBOMs
ALTER TABLE sbom_components
    ADD CONSTRAINT sbom_components_sbom_id_fkey
    FOREIGN KEY (sbom_id)
    REFERENCES sboms(id)
    ON DELETE CASCADE;

-- Findings -> SBOMs, SBOM Components, Vulnerabilities
ALTER TABLE findings
    ADD CONSTRAINT findings_sbom_id_fkey
    FOREIGN KEY (sbom_id)
    REFERENCES sboms(id)
    ON DELETE CASCADE;

ALTER TABLE findings
    ADD CONSTRAINT findings_sbom_component_id_sbom_id_fkey
    FOREIGN KEY (sbom_component_id, sbom_id)
    REFERENCES sbom_components(id, sbom_id)
    ON DELETE CASCADE;

ALTER TABLE findings
    ADD CONSTRAINT fk_findings_vulnerability
    FOREIGN KEY (vulnerability_id)
    REFERENCES vulnerabilities(id)
    ON DELETE RESTRICT;


-- ----------------------------------------------------------------------------
-- 6. Performance & Deduplication Indexes
-- ----------------------------------------------------------------------------

-- Applications
CREATE INDEX idx_projects_organization
    ON applications USING btree (organization_id, name);

CREATE UNIQUE INDEX idx_applications_org_readable_id
    ON applications USING btree (organization_id, readable_id)
    WHERE (readable_id <> ''::text);

CREATE UNIQUE INDEX idx_applications_org_lower_name
    ON applications USING btree (organization_id, lower(name));

-- Modules
CREATE INDEX idx_applications_project
    ON modules USING btree (application_id, name);

-- Credentials
CREATE INDEX idx_credentials_organization
    ON credentials USING btree (organization_id, created_at DESC);

-- Inventory Components
CREATE INDEX idx_inventory_components_application
    ON inventory_components USING btree (module_id);

CREATE INDEX idx_inventory_components_organization
    ON inventory_components USING btree (organization_id, created_at DESC, id DESC);

CREATE UNIQUE INDEX uq_inventory_components_identity
    ON inventory_components USING btree (module_id, name, version, COALESCE(package_url, ''::text), COALESCE(source_file_name, ''::text));

-- Inventory Change Log
CREATE INDEX idx_inventory_change_log_comp
    ON inventory_change_log USING btree (component_name, created_at DESC);

CREATE INDEX idx_inventory_change_log_app_mod
    ON inventory_change_log USING btree (application_id, module_id, created_at DESC);

-- Scans
CREATE INDEX idx_scans_organization
    ON scans USING btree (organization_id, created_at DESC);

CREATE INDEX idx_scans_job_queue
    ON scans USING btree (job_status, next_attempt_at);

CREATE INDEX idx_scans_bulk
    ON scans USING btree (bulk_scan_id, bulk_row_number);

-- SBOMs
CREATE INDEX idx_sboms_application
    ON sboms USING btree (application_id, generated_at DESC);

CREATE INDEX idx_sboms_scan
    ON sboms USING btree (scan_id);

-- SBOM Components
CREATE INDEX idx_sbom_components_sbom
    ON sbom_components USING btree (sbom_id);

CREATE INDEX idx_sbom_components_name
    ON sbom_components USING btree (name, version);

CREATE UNIQUE INDEX uq_sbom_components_identity
    ON sbom_components USING btree (sbom_id, name, version, COALESCE(package_url, ''::text), COALESCE(source_manifest, ''::text));

-- Findings
CREATE INDEX idx_findings_sbom
    ON findings USING btree (sbom_id);

CREATE INDEX idx_findings_status
    ON findings USING btree (status);

-- Vulnerability Triage
CREATE INDEX idx_vulnerability_triage_lookup
    ON vulnerability_triage USING btree (organization_id, vulnerability_key);


-- ----------------------------------------------------------------------------
-- 7. Table Comments & Documentation
-- ----------------------------------------------------------------------------
COMMENT ON TABLE organizations IS 'Tenant. Applications, scans, and credentials belong to one organization.';
COMMENT ON TABLE applications IS 'Application catalog for one organization (formerly projects).';
COMMENT ON TABLE modules IS 'Module or service that belongs to one application (formerly applications).';
COMMENT ON VIEW projects IS 'Backward-compatible view aliasing applications for legacy queries.';
COMMENT ON TABLE inventory_components IS 'Package tracked on an application module in the software inventory.';
COMMENT ON TABLE inventory_change_log IS 'Audit log tracking manual inventory additions/removals and vulnerability status changes.';
COMMENT ON TABLE credentials IS 'Git credential and its encrypted secret.';
COMMENT ON TABLE scans IS 'One scan execution, its queue fields, bulk row, and progress events.';
COMMENT ON TABLE sboms IS 'SBOM produced by one scan, including repository and commit text.';
COMMENT ON TABLE sbom_components IS 'Package found in one SBOM, including NTIA checks, detection metadata, and dependency ids.';
COMMENT ON TABLE vulnerabilities IS 'Canonical CVE or advisory. reference_urls lists its links.';
COMMENT ON TABLE findings IS 'One vulnerability match for one package in one SBOM.';
COMMENT ON TABLE vulnerability_triage IS 'Persistent triage overrides, VEX status, ticket IDs, and justifications across scans.';
COMMENT ON TABLE schema_migrations IS 'Database migration version history tracker.';


-- ----------------------------------------------------------------------------
-- 8. Migration Baseline Seed
-- ----------------------------------------------------------------------------
-- Pre-populates migration history so the application migration runner recognizes
-- that all current schema migrations (001 through 010) are already applied.
INSERT INTO schema_migrations (version, applied_at) VALUES
    ('001_initial.up.sql', CURRENT_TIMESTAMP),
    ('002_security_scans_move.up.sql', CURRENT_TIMESTAMP),
    ('004_software_inventory.up.sql', CURRENT_TIMESTAMP),
    ('005_relational_facts.up.sql', CURRENT_TIMESTAMP),
    ('006_ten_tables.up.sql', CURRENT_TIMESTAMP),
    ('007_vulnerability_triage.up.sql', CURRENT_TIMESTAMP),
    ('008_scan_description.up.sql', CURRENT_TIMESTAMP),
    ('009_inventory_schema_and_table_renames.up.sql', CURRENT_TIMESTAMP),
    ('010_baseline_improvements.up.sql', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

-- ----------------------------------------------------------------------------
-- End of S-BOM_update.sql
-- ----------------------------------------------------------------------------
