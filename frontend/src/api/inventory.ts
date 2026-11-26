/**
 * Inventory API operations and types.
 */

import type { ComponentFieldType, Ecosystem, LicenseType, SBOMComponent, Severity } from '../types';
import { request } from './http';

export interface ApiInventoryComponent {
  id: string;
  name: string;
  package_name: string;
  version: string;
  project: string;
  project_application: string;
  field_type: ComponentFieldType;
  license: string;
  cves: number;
  purl: string;
  risk: Severity | 'Safe';
  ecosystem: Ecosystem;
  direct: boolean;
  supplier: string;
  file_name?: string;
  created_by?: string;
}

export interface InventoryComponentInput {
  project: string;
  project_application: string;
  project_id?: string;
  application_id?: string;
  name: string;
  package_name?: string;
  version: string;
  field_type?: ComponentFieldType;
  license?: string;
  cves?: number;
  ecosystem?: Ecosystem;
  risk?: Severity | 'Safe';
  purl?: string;
  direct_dependency?: boolean;
  supplier?: string;
  file_name?: string;
  created_by?: string;
}

export interface InventoryPage {
  items: ApiInventoryComponent[];
  next_cursor: string | null;
}

export async function listInventoryComponents(): Promise<ApiInventoryComponent[]> {
  const items: ApiInventoryComponent[] = [];
  let cursor = '';
  for (let page = 0; page < 1000; page += 1) {
    const query = new URLSearchParams({ limit: '500' });
    if (cursor) query.set('cursor', cursor);
    const data = await request<InventoryPage>(`/api/v1/inventory/components?${query.toString()}`);
    items.push(...(data?.items || []));
    if (!data?.next_cursor) break;
    cursor = data.next_cursor;
  }
  return items;
}

export function createInventoryComponents(components: InventoryComponentInput[], reason?: string): Promise<ApiInventoryComponent[]> {
  return request<ApiInventoryComponent[]>('/api/v1/inventory/components', {
    method: 'POST',
    body: JSON.stringify({ components, reason }),
  });
}

export function deleteInventoryComponent(id: string, reason?: string): Promise<{ deleted: boolean; id: string }> {
  const query = reason ? `?reason=${encodeURIComponent(reason)}` : '';
  return request(`/api/v1/inventory/components/${encodeURIComponent(id)}${query}`, {
    method: 'DELETE',
  });
}

export interface PackageHistoryTimelineEvent {
  type: string;
  change_type: string;
  version: string;
  previous_version?: string | null;
  application: string;
  module: string;
  scan_id?: string | null;
  branch?: string;
  commit_sha?: string;
  source_manifest?: string;
  scope?: string;
  timestamp: string;
  reason?: string;
  author?: string;
}

export interface PackageHistoryResponse {
  package_name: string;
  distinct_versions: string[];
  total_events: number;
  timeline: PackageHistoryTimelineEvent[];
}

export function getPackageHistory(packageName: string): Promise<PackageHistoryResponse> {
  return request<PackageHistoryResponse>(`/api/v1/packages/${encodeURIComponent(packageName)}/history`);
}

export interface InventoryAuditLogItem {
  id: string;
  organization_id: string;
  application_id: string;
  module_id: string;
  component_name: string;
  component_version: string;
  action: string;
  reason: string;
  changed_by: string;
  created_at: string;
}

export function getInventoryAuditLog(componentName?: string): Promise<{ items: InventoryAuditLogItem[]; total: number }> {
  const query = componentName ? `?component_name=${encodeURIComponent(componentName)}` : '';
  return request<{ items: InventoryAuditLogItem[]; total: number }>(`/api/v1/inventory/audit-log${query}`);
}

const knownLicenses = new Set<LicenseType>(['MIT', 'Apache-2.0', 'BSD-3-Clause', 'GPL-3.0', 'LGPL-3.0', 'MPL-2.0', 'ISC', 'Commercial', 'Unknown']);

export function mapLicense(value?: string): LicenseType {
  if (value && knownLicenses.has(value as LicenseType)) return value as LicenseType;
  return 'Unknown';
}

export function mapInventoryComponent(row: ApiInventoryComponent): SBOMComponent {
  return {
    id: row.id,
    name: row.name,
    packageName: row.package_name || row.name,
    version: row.version,
    project: row.project,
    projectApplication: row.project_application,
    fieldType: row.field_type || 'Library',
    license: mapLicense(row.license),
    trustScore: 90,
    risk: row.risk || 'Safe',
    cves: row.cves || 0,
    patchAvailable: false,
    vex: 'not_affected',
    eol: false,
    ecosystem: row.ecosystem || 'npm',
    criticality: row.direct ? 'High' : 'Low',
    directDependency: Boolean(row.direct),
    supplier: row.supplier || '',
    purl: row.purl,
    fileName: row.file_name || undefined,
    createdBy: row.created_by || undefined,
    compliance: 95,
  };
}
