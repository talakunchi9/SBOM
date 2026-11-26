/**
 * Projects and microservices dashboard API.
 */

import { request } from './http';

export interface ApiProjectSummary {
  project_count: number;
  active_projects: number;
  avg_compliance_pct: number;
  compliant_count: number;
  total_count: number;
  total_scans: number;
  sbom_files: number;
}

export interface ApiProjectRow {
  id: string;
  name: string;
  ownership?: string;
  business_owner?: string;
  source?: 'Internal' | 'External' | string;
  repo_branch?: string;
  version?: string;
  module?: string;
  classifier: string;
  risk: 'Healthy' | 'Needs Attention' | 'High Risk';
  compliance: string;
  compliance_pct: number;
  vulns: number;
  vuln_critical?: number;
  vuln_high?: number;
  vuln_medium?: number;
  vuln_low?: number;
  component_count?: number;
  scans: number;
  tags: string[];
  last_scanned_at: string;
  latest_scan_id?: string;
  latest_snapshot_id?: string;
  source_types?: string[];
}

export interface ApiProjectsDashboard {
  summary: ApiProjectSummary;
  projects: ApiProjectRow[];
}

export function listProjects(params?: { q?: string; status?: string }): Promise<ApiProjectsDashboard> {
  const query = new URLSearchParams();
  if (params?.q) query.set('q', params.q);
  if (params?.status && params.status !== 'All Statuses') query.set('status', params.status);
  const suffix = query.toString() ? `?${query}` : '';
  return request(`/api/v1/projects${suffix}`);
}

export async function updateApplicationLifecycleStatus(
  applicationNameOrId: string,
  status: 'Active' | 'Decommissioned' | 'Inactive'
): Promise<{ target: string; lifecycle_status: string }> {
  return request<{ target: string; lifecycle_status: string }>(
    `/api/v1/applications/${encodeURIComponent(applicationNameOrId)}/lifecycle-status`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lifecycle_status: status }),
    }
  );
}
