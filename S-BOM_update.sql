-- ============================================================================
-- S-BOM Database Schema (Latest Production Schema)
-- ============================================================================
-- Project:        Software Bill of Materials (S-BOM) Management Platform
-- File:           S-BOM_update.sql
-- Compatibility:  PostgreSQL 14, 15, 16, 17, 18+
-- Description:    Comprehensive, cleanly formatted single SQL file containing
--                 the complete and latest relational schema, helper functions,
--                 table constraints, foreign key relationships, performance
--                 indexes, documentation comments, and migration baseline.
-- ============================================================================
--
-- ENTITY RELATIONSHIP HIERARCHY:
--
--  organizations (Tenant root)
--   ├── projects
--   │     └── applications
--   │           └── inventory_components
--   ├── credentials
--   ├── scans
--   │     └── sboms
--   │           └── sbom_components
--   │                 └── findings
--   │                       └── vulnerabilities
--   └── vulnerability_triage (Cross-scan triage & VEX overrides)
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
DROP TABLE IF EXISTS vulnerability_triage CASCADE;
DROP TABLE IF EXISTS findings CASCADE;
DROP TABLE IF EXISTS sbom_components CASCADE;
DROP TABLE IF EXISTS sboms CASCADE;
DROP TABLE IF EXISTS scans CASCADE;
DROP TABLE IF EXISTS credentials CASCADE;
DROP TABLE IF EXISTS inventory_components CASCADE;
DROP TABLE IF EXISTS applications CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS schema_migrations CASCADE;

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


-- ----------------------------------------------------------------------------
-- 4. Core Relational Tables
-- ----------------------------------------------------------------------------

-- Table 1: organizations
-- Tenant. Projects, scans, and credentials belong to one organization.
CREATE TABLE organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: projects
-- Project catalog for one organization.
CREATE TABLE projects (
    id               TEXT PRIMARY KEY,
    organization_id  TEXT NOT NULL,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT projects_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT projects_organization_id_name_key UNIQUE (organization_id, name),
    CONSTRAINT projects_id_organization_id_key UNIQUE (id, organization_id)
);

-- Table 3: applications
-- Application or service that belongs to one project.
CREATE TABLE applications (
    id               TEXT PRIMARY KEY,
    project_id       TEXT NOT NULL,
    organization_id  TEXT NOT NULL,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT applications_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT applications_organization_id_project_id_name_key UNIQUE (organization_id, project_id, name),
    CONSTRAINT applications_id_project_id_organization_id_key UNIQUE (id, project_id, organization_id)
);

-- Table 4: inventory_components
-- Package tracked on an application in the software inventory.
CREATE TABLE inventory_components (
    id                    TEXT PRIMARY KEY,
    organization_id       TEXT NOT NULL,
    project_id            TEXT NOT NULL,
    application_id        TEXT NOT NULL,
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
    created_at            TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT inventory_components_name_check CHECK (length(btrim(name)) > 0),
    CONSTRAINT inventory_components_version_check CHECK (length(btrim(version)) > 0),
    CONSTRAINT inventory_components_vulnerability_count_check CHECK (vulnerability_count >= 0)
);

-- Table 5: credentials
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

-- Table 6: scans
-- One scan execution, queue tracking, bulk row metadata, and progress events.
CREATE TABLE scans (
    id                      TEXT PRIMARY KEY,
    organization_id         TEXT NOT NULL,
    project_id              TEXT NOT NULL DEFAULT '',
    application_id          TEXT NOT NULL DEFAULT '',
    application_name        TEXT NOT NULL DEFAULT '',
    application_version     TEXT NOT NULL DEFAULT '',
    version_strategy        TEXT NOT NULL DEFAULT '',
    bom_type                TEXT NOT NULL DEFAULT 'SBOM',
    source_type             TEXT NOT NULL DEFAULT '',
    scan_status             TEXT NOT NULL,
    scan_stage              TEXT NOT NULL DEFAULT '',
    error_code              TEXT NOT NULL DEFAULT '',
    error_message           TEXT NOT NULL DEFAULT '',
    idempotency_key         TEXT NOT NULL UNIQUE,
    created_at              TIMESTAMPTZ NOT NULL,
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
    events                  JSONB NOT NULL DEFAULT '[]'::jsonb
);

-- Table 7: sboms
-- Software Bill of Materials produced by scans, including VCS repository and commit details.
CREATE TABLE sboms (
    id                      TEXT PRIMARY KEY,
    organization_id         TEXT NOT NULL,
    project_id              TEXT NOT NULL DEFAULT '',
    application_id          TEXT NOT NULL DEFAULT '',
    scan_id                 TEXT NOT NULL,
    catalog_project_id      TEXT,
    catalog_application_id  TEXT,
    bom_type                TEXT NOT NULL,
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
    generated_at            TIMESTAMPTZ NOT NULL,
    raw_metadata            TEXT,
    file_name               TEXT NOT NULL DEFAULT '',
    file_format             TEXT NOT NULL DEFAULT '',
    file_size_bytes         BIGINT NOT NULL DEFAULT 0,
    signature_status        TEXT NOT NULL DEFAULT '',
    facts_normalized        BOOLEAN NOT NULL DEFAULT FALSE
);

-- Table 8: sbom_components
-- Package or dependency found in an SBOM, including NTIA compliance checks and dependency links.
CREATE TABLE sbom_components (
    id                    TEXT PRIMARY KEY,
    sbom_id               TEXT NOT NULL,
    name                  TEXT NOT NULL,
    version               TEXT NOT NULL,
    ecosystem             TEXT NOT NULL,
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
    created_at            TIMESTAMPTZ NOT NULL,
    dependency_depth      INTEGER,
    ntia_supplier         BOOLEAN,
    ntia_name             BOOLEAN,
    ntia_version          BOOLEAN,
    ntia_identifier       BOOLEAN,
    ntia_relationship     BOOLEAN,
    ntia_author           BOOLEAN,
    ntia_timestamp        BOOLEAN,
    depends_on            TEXT[] NOT NULL DEFAULT '{}'::text[],
    CONSTRAINT sbom_components_id_sbom_id_key UNIQUE (id, sbom_id),
    CONSTRAINT sbom_components_dependency_depth_check CHECK (dependency_depth IS NULL OR dependency_depth >= 0)
);

-- Table 9: vulnerabilities
-- Canonical CVE repository with CVSS metrics and advisory references.
CREATE TABLE vulnerabilities (
    id                  TEXT PRIMARY KEY,
    vulnerability_key   TEXT NOT NULL UNIQUE,
    source              TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score          NUMERIC(4,1) NOT NULL DEFAULT 0,
    cvss_vector         TEXT NOT NULL DEFAULT '',
    description         TEXT NOT NULL DEFAULT '',
    reference_urls      TEXT[] NOT NULL DEFAULT '{}'::text[],
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerabilities_severity_check CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    CONSTRAINT vulnerabilities_cvss_score_check CHECK (cvss_score >= 0 AND cvss_score <= 10)
);

-- Table 10: findings
-- One vulnerability match for one package in one SBOM, with triage lifecycle status.
CREATE TABLE findings (
    id                  TEXT PRIMARY KEY,
    sbom_id             TEXT NOT NULL,
    sbom_component_id   TEXT NOT NULL,
    vulnerability_id    TEXT NOT NULL,
    source              TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_score          NUMERIC(4,1) NOT NULL DEFAULT 0,
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

-- Table 11: vulnerability_triage
-- Persistent triage overrides, VEX statements, tickets, and justifications across scans.
CREATE TABLE vulnerability_triage (
    id                  TEXT PRIMARY KEY,
    organization_id     TEXT NOT NULL DEFAULT 'default',
    vulnerability_key   TEXT NOT NULL,
    project_name        TEXT NOT NULL DEFAULT '',
    application_name    TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'Open',
    vex_status          TEXT NOT NULL DEFAULT 'affected',
    ticket_id           TEXT NOT NULL DEFAULT '',
    owner               TEXT NOT NULL DEFAULT '',
    justification       TEXT NOT NULL DEFAULT '',
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT vulnerability_triage_organization_id_vulnerability_key_proj_key
        UNIQUE (organization_id, vulnerability_key, project_name, application_name)
);

-- Table 12: schema_migrations
-- Database migration version history tracker.
CREATE TABLE schema_migrations (
    version     TEXT PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ----------------------------------------------------------------------------
-- 5. Foreign Key Constraints
-- ----------------------------------------------------------------------------

-- Projects -> Organizations
ALTER TABLE projects
    ADD CONSTRAINT projects_organization_id_fkey
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

-- Applications -> Projects
ALTER TABLE applications
    ADD CONSTRAINT applications_project_id_organization_id_fkey
    FOREIGN KEY (project_id, organization_id)
    REFERENCES projects(id, organization_id)
    ON DELETE CASCADE;

-- Inventory Components -> Organizations, Projects, Applications
ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_organization
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_project
    FOREIGN KEY (project_id, organization_id)
    REFERENCES projects(id, organization_id)
    ON DELETE CASCADE;

ALTER TABLE inventory_components
    ADD CONSTRAINT fk_inventory_application
    FOREIGN KEY (application_id, project_id, organization_id)
    REFERENCES applications(id, project_id, organization_id)
    ON DELETE CASCADE;

-- Credentials -> Organizations
ALTER TABLE credentials
    ADD CONSTRAINT fk_credentials_organization
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

-- Scans -> Organizations, Projects, Applications, SBOMs
ALTER TABLE scans
    ADD CONSTRAINT scans_organization_id_fkey
    FOREIGN KEY (organization_id)
    REFERENCES organizations(id)
    ON DELETE CASCADE;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_catalog_project
    FOREIGN KEY (catalog_project_id, organization_id)
    REFERENCES projects(id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_catalog_application
    FOREIGN KEY (catalog_application_id, catalog_project_id, organization_id)
    REFERENCES applications(id, project_id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE scans
    ADD CONSTRAINT fk_scans_sbom
    FOREIGN KEY (sbom_id)
    REFERENCES sboms(id)
    ON DELETE SET NULL;

-- SBOMs -> Organizations, Scans, Projects, Applications
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
    REFERENCES projects(id, organization_id)
    ON DELETE RESTRICT;

ALTER TABLE sboms
    ADD CONSTRAINT fk_sboms_catalog_application
    FOREIGN KEY (catalog_application_id, catalog_project_id, organization_id)
    REFERENCES applications(id, project_id, organization_id)
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
-- 6. Performance Indexes
-- ----------------------------------------------------------------------------

-- Applications
CREATE INDEX idx_applications_project
    ON applications USING btree (project_id, name);

-- Credentials
CREATE INDEX idx_credentials_organization
    ON credentials USING btree (organization_id, created_at DESC);

-- Inventory Components
CREATE INDEX idx_inventory_components_application
    ON inventory_components USING btree (application_id);

CREATE INDEX idx_inventory_components_organization
    ON inventory_components USING btree (organization_id, created_at DESC, id DESC);

-- Projects
CREATE INDEX idx_projects_organization
    ON projects USING btree (organization_id, name);

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
COMMENT ON TABLE organizations IS 'Tenant. Projects, scans, and credentials belong to one organization.';
COMMENT ON TABLE projects IS 'Project catalog for one organization.';
COMMENT ON TABLE applications IS 'Application or service that belongs to one project.';
COMMENT ON TABLE inventory_components IS 'Package tracked on an application in the software inventory.';
COMMENT ON TABLE credentials IS 'Git credential and its encrypted secret.';
COMMENT ON TABLE scans IS 'One scan execution, its queue fields, bulk row, and progress events.';
COMMENT ON TABLE sboms IS 'SBOM produced by one scan, including repository and commit text.';
COMMENT ON TABLE sbom_components IS 'Package found in one SBOM, including NTIA checks and dependency ids.';
COMMENT ON TABLE vulnerabilities IS 'Canonical CVE or advisory. reference_urls lists its links.';
COMMENT ON TABLE findings IS 'One vulnerability match for one package in one SBOM.';
COMMENT ON TABLE vulnerability_triage IS 'Persistent triage overrides, VEX status, ticket IDs, and justifications across scans.';
COMMENT ON TABLE schema_migrations IS 'Database migration version history tracker.';


-- ----------------------------------------------------------------------------
-- 8. Migration Baseline Seed
-- ----------------------------------------------------------------------------
-- Pre-populates migration history so the application migration runner recognizes
-- that all current schema migrations (001 through 007) are already applied.
INSERT INTO schema_migrations (version, applied_at) VALUES
    ('001_initial.up.sql', CURRENT_TIMESTAMP),
    ('002_security_scans_move.up.sql', CURRENT_TIMESTAMP),
    ('004_software_inventory.up.sql', CURRENT_TIMESTAMP),
    ('005_relational_facts.up.sql', CURRENT_TIMESTAMP),
    ('006_ten_tables.up.sql', CURRENT_TIMESTAMP),
    ('007_vulnerability_triage.up.sql', CURRENT_TIMESTAMP)
ON CONFLICT (version) DO NOTHING;

-- ----------------------------------------------------------------------------
-- End of S-BOM_update.sql
-- ----------------------------------------------------------------------------
