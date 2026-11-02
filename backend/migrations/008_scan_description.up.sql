-- Migration 008: Add description column to scans table
ALTER TABLE scans ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';

