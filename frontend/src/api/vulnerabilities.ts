/**
 * Vulnerabilities management and package occurrences API.
 */

import type { Ecosystem, Severity, Vulnerability } from '../types';
import { request } from './http';

export interface ApiVulnMatch {
  component_id: string;
  vulnerability_id: string;
  source?: string;
  severity?: string;
  cvss_score?: number;
  cvss_vector?: string;
  description?: string;
  fixed_version?: string;
  status?: string;
  vex_status?: string;
}

export interface VulnerabilityTriageRecord {
  cve: string;
  project: string;
  application: string;
  status: string;
  vex_status: string;
  ticket_id?: string;
  owner?: string;
  justification?: string;
  updated_at?: string;
}

export function titleSeverity(s?: string): Severity {
  switch ((s || '').toUpperCase()) {
    case 'CRITICAL':
      return 'Critical';
    case 'HIGH':
      return 'High';
    case 'MEDIUM':
      return 'Medium';
    case 'LOW':
      return 'Low';
    default:
      return 'Medium';
  }
}

export function extractVulnName(desc?: string, fallbackId = ''): string {
  if (!desc || !desc.trim()) return fallbackId;
  const trimmed = desc.trim();
  const firstLine = trimmed.split(/\r?\n+/)[0].trim();
  const sentenceMatch = trimmed.match(/^(.+?[a-zA-Z0-9\)])\.(?:\s+[A-Z]|\s*$)/s);
  if (sentenceMatch && sentenceMatch[1]) {
    const sentence = sentenceMatch[1].trim();
    if (sentence.length >= 10 && sentence.length <= 220) {
      return sentence;
    }
  }
  return firstLine.length <= 160 ? firstLine : firstLine.slice(0, 157).trim() + '...';
}

const ecosystems: Record<string, Ecosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  maven: 'Maven',
  go: 'Go',
  cargo: 'Cargo',
  rubygems: 'RubyGems',
  nuget: 'NuGet',
  composer: 'Packagist',
  packagist: 'Packagist',
};

export function mapVulns(
  matches: ApiVulnMatch[] | null,
  components: Array<{ id: string; name: string; version: string; ecosystem?: string; purl?: string; direct?: boolean }>,
  project: string,
  application = '',
  scanId = '',
): Vulnerability[] {
  const byId = new Map(components.map((c) => [c.id, c]));
  const rows = Array.isArray(matches) ? matches : [];
  return rows.map((m, i) => {
    const comp = byId.get(m.component_id);
    const desc = m.description || '';
    const cleanName = extractVulnName(desc, m.vulnerability_id);
    const now = new Date();
    const formattedDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    const hash = Math.abs((m.vulnerability_id + project).split('').reduce((acc, char) => ((acc << 5) - acc + char.charCodeAt(0)) | 0, 0));
    return {
      id: `${m.vulnerability_id}-${i}`,
      cve: m.vulnerability_id,
      name: cleanName,
      package: comp?.name || m.component_id,
      version: comp?.version || '',
      project,
      application: application || project,
      scanId: scanId || undefined,
      cvss: m.cvss_score || 0,
      epss: 0,
      severity: titleSeverity(m.severity),
      status: (m.status as any) || 'Open',
      fixVersion: m.fixed_version && m.fixed_version !== '*' ? m.fixed_version : '',
      age: 'Just now',
      description: desc || 'Vulnerability detected during software component composition analysis.',
      cwe: 'CWE-20',
      publishedDate: formattedDate,
      vexStatus: (m.vex_status as any) || 'affected',
      vectorString: m.cvss_vector || 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      exploitAvailable: false,
      affectedVersions: comp?.version || '',
      ecosystem: ecosystems[comp?.ecosystem || ''] || 'npm',
      purl: comp?.purl || `pkg:${(comp?.ecosystem || 'generic').toLowerCase()}/${comp?.name || m.component_id}@${comp?.version || '0.0.0'}`,
      direct: comp?.direct ?? true,
      dependencyPath: `${project} > ${comp?.name || m.component_id}`,
      source: m.source || 'NVD',
      ticketId: `SEC-${(hash % 9000) + 1000}`,
      firstDetected: `${formattedDate} 10:00 AM`,
      lastDetected: `${formattedDate} 10:00 AM`,
      sbomVersion: 'sbom-1.4.2',
      scanVersion: scanId ? `scan-${scanId.substring(0, 8)}` : 'scan-3.7.1',
      statusChanges: (m.status as any) || 'Open',
      justification: (m as any).justification || '',
      owner: (m as any).owner || '',
      businessOwner: (m as any).business_owner || (m as any).businessOwner || '',
    };
  });
}

export function listVulnerabilityTriage(params?: { signal?: AbortSignal }): Promise<VulnerabilityTriageRecord[]> {
  return request<VulnerabilityTriageRecord[]>('/api/v1/vulnerabilities/triage', { signal: params?.signal });
}

export function updateVulnerabilityStatus(
  cveId: string,
  params: {
    status: string;
    vexStatus?: string;
    project?: string;
    application?: string;
    ticketId?: string;
    owner?: string;
    justification?: string;
  },
): Promise<{ cve: string; status: string; vex_status?: string; project?: string }> {
  return request(`/api/v1/vulnerabilities/${encodeURIComponent(cveId)}/status`, {
    method: 'PATCH',
    body: JSON.stringify(params),
  });
}

export interface PackageOccurrenceUsage {
  application_id: string;
  application_name: string;
  module_id: string;
  module_name: string;
  repository_url: string;
  branch: string;
  package_location: string;
  direct_dependency: boolean;
  scope: string;
  detection_method: string;
  confidence: number;
  version: string;
  purl?: string;
  first_detected_at: string | null;
  last_detected_at: string | null;
  status: string;
}

export interface PackageOccurrencesResponse {
  package_name: string;
  occurrence_count: number;
  applications_count: number;
  modules_count: number;
  usages: PackageOccurrenceUsage[];
}

export async function getPackageOccurrences(name: string, purl?: string): Promise<PackageOccurrencesResponse> {
  const params = new URLSearchParams();
  if (name) params.set('name', name);
  if (purl) params.set('purl', purl);
  return request<PackageOccurrencesResponse>(`/api/v1/packages/occurrences?${params.toString()}`);
}
