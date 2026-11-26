/**
 * Security scans execution and status API.
 */

import type { BulkScanItemView, Ecosystem, LicenseType, SBOMComponent, ScanEventView, ScanJob, ScanStatus, Severity } from '../types';
import { formatDuration } from '../pages/scans/scanProgress';
import { ApiError, BASE, request } from './http';
import { mapLicense } from './inventory';
import { ApiVulnMatch, titleSeverity } from './vulnerabilities';

export { formatDuration };

export interface ApiScan {
  id: string;
  project_id: string;
  application_name: string;
  application_version: string;
  source_type: string;
  status: string;
  stage: string;
  created_at: string;
  started_at?: string;
  completed_at?: string;
  snapshot_id?: string;
  error_code?: string;
  error_message?: string;
  bulk_scan_id?: string;
  bulk_row?: number;
  file_name?: string;
  repository_url?: string;
  branch?: string;
  description?: string;
  lifecycle_status?: string;
  business_owner?: string;
}

export interface ApiScanStatus {
  status: string;
  stage: string;
  error_code?: string;
  error_message?: string;
  started_at?: string;
  completed_at?: string;
  source_type?: string;
  file_name?: string;
  repository_url?: string;
  branch?: string;
  description?: string;
  lifecycle_status?: string;
  business_owner?: string;
}

export interface ApiComponent {
  id: string;
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  license?: string;
  direct: boolean;
  source_manifest?: string;
  scope?: string;
}

export interface ApiEvent {
  id: string;
  stage: string;
  message: string;
  created_at: string;
}

export interface DuplicateCheckResult {
  is_duplicate: boolean;
  duplicate_type?: string;
  application_name?: string;
  module_name?: string;
  version?: string;
  completed_at?: string;
  scan_id?: string;
  component_stats?: {
    total_new: number;
    total_previous: number;
    unchanged: number;
    added: number;
    removed: number;
    upgraded: number;
    match_pct: number;
    added_samples?: string[];
    removed_samples?: string[];
    upgraded_samples?: [string, string, string][];
  };
}

export interface ApiBulkItem {
  id?: string;
  row_number?: number;
  scan_id?: string;
  project_name?: string;
  application_name?: string;
  version?: string;
  repository_url?: string;
  status: string;
  error_code?: string;
  error_message?: string;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
}

export interface ApiBulk {
  id: string;
  project_id?: string;
  status: string;
  filename?: string;
  total_rows: number;
  queued_rows?: number;
  invalid_rows: number;
  created_at?: string;
  started_at?: string;
  completed_at?: string;
  items?: ApiBulkItem[];
  validation_errors?: { row?: number; code?: string; message: string }[];
}

export function healthReady(): Promise<{ status: string }> {
  return request('/health/ready');
}

export async function listScans(): Promise<ApiScan[]> {
  return (await request<ApiScan[] | null>('/api/v1/scans')) || [];
}

export function scanStatus(id: string): Promise<ApiScanStatus> {
  return request(`/api/v1/scans/${id}/status`);
}

export function rescanScan(id: string): Promise<{ scan_id: string; status: string; stage: string }> {
  return request(`/api/v1/scans/${id}/rescan`, { method: 'POST' });
}

export function cancelScan(id: string): Promise<{ scan_id: string; status: string; stage: string }> {
  return request(`/api/v1/scans/${id}/cancel`, { method: 'POST' });
}

export async function scanEvents(id: string): Promise<ApiEvent[]> {
  return (await request<ApiEvent[] | null>(`/api/v1/scans/${id}/events`)) || [];
}

export async function scanComponents(id: string): Promise<ApiComponent[]> {
  return (await request<ApiComponent[] | null>(`/api/v1/scans/${id}/components`)) || [];
}

export function scanVulnerabilities(id: string): Promise<ApiVulnMatch[] | null> {
  return request(`/api/v1/scans/${id}/vulnerabilities`);
}

export function checkScanDuplicate(input: {
  applicationName: string;
  moduleName: string;
  version: string;
  file?: File | null;
  folderFiles?: { file: File; relativePath: string }[];
  repositoryUrl?: string;
  branch?: string;
}): Promise<DuplicateCheckResult> {
  const body = new FormData();
  body.append('application_name', input.applicationName);
  body.append('module_name', input.moduleName);
  body.append('version', input.version);
  if (input.file) {
    body.append('file', input.file);
  }
  if (input.folderFiles && input.folderFiles.length > 0) {
    for (const item of input.folderFiles) {
      body.append('files', item.file, item.relativePath);
    }
  }
  if (input.repositoryUrl) body.append('repository_url', input.repositoryUrl);
  if (input.branch) body.append('branch', input.branch);
  return request('/api/v1/scans/preflight-check', { method: 'POST', body });
}

export function createLocalScan(
  source: { file?: File | null; folderFiles?: { file: File; relativePath: string }[] },
  project: string,
  application: string,
  version: string,
  ids?: { projectId?: string; applicationId?: string },
  description?: string,
  governance?: {
    businessOwner?: string;
    technicalOwner?: string;
    developmentType?: string;
    vendorName?: string;
    moduleType?: string;
  },
): Promise<{ scan_id: string; status?: string; stage?: string }> {
  const body = new FormData();
  if (source.folderFiles && source.folderFiles.length > 0) {
    const nonZero = source.folderFiles.filter((item) => item.file.size > 0);
    if (nonZero.length === 0) {
      throw new ApiError('EMPTY_FILE', 'The selected folder contains only empty files (0 bytes). Empty folders cannot be scanned.');
    }
    for (const item of nonZero) {
      const rel = item.relativePath.replace(/\\/g, '/');
      const base = rel.split('/').pop() || item.file.name;
      body.append('files', item.file, base);
      body.append('paths', rel);
    }
  } else if (source.file) {
    if (source.file.size === 0) {
      throw new ApiError('EMPTY_FILE', `The file "${source.file.name}" is empty (0 bytes). Empty files cannot be scanned.`);
    }
    body.append('file', source.file);
  } else {
    throw new ApiError('INVALID_INPUT', 'Choose a folder, a zip archive, or a manifest file.');
  }
  body.append('project_name', project);
  body.append('application_name', application);
  body.append('version', version || 'UNKNOWN');
  if (ids?.projectId) body.append('project_id', ids.projectId);
  if (ids?.applicationId) body.append('application_id', ids.applicationId);
  if (description) body.append('description', description);
  if (governance?.businessOwner) body.append('business_owner', governance.businessOwner);
  if (governance?.technicalOwner) body.append('technical_owner', governance.technicalOwner);
  if (governance?.developmentType) body.append('development_type', governance.developmentType);
  if (governance?.vendorName) body.append('vendor_name', governance.vendorName);
  if (governance?.moduleType) body.append('module_type', governance.moduleType);
  return request('/api/v1/scans/local', { method: 'POST', body });
}

export function createGitHubScan(input: {
  repositoryUrl: string;
  project: string;
  application: string;
  version: string;
  branch: string;
  credentialId?: string;
  projectId?: string;
  applicationId?: string;
  description?: string;
  businessOwner?: string;
  technicalOwner?: string;
  developmentType?: string;
  vendorName?: string;
  moduleType?: string;
}): Promise<{ scan_id: string; status?: string; stage?: string }> {
  return request('/api/v1/scans/github', {
    method: 'POST',
    body: JSON.stringify({
      repository_url: input.repositoryUrl,
      project_name: input.project,
      application_name: input.application,
      project_id: input.projectId || '',
      application_id: input.applicationId || '',
      version: input.version || 'UNKNOWN',
      branch: input.branch,
      description: input.description || '',
      business_owner: input.businessOwner || '',
      technical_owner: input.technicalOwner || '',
      development_type: input.developmentType || 'In-house',
      vendor_name: input.vendorName || '',
      module_type: input.moduleType || 'Microservice',
      authentication: input.credentialId ? { type: 'GITHUB_FINE_GRAINED_PAT', credential_id: input.credentialId } : undefined,
    }),
  });
}

export function createBulkScan(file: File, project: string): Promise<ApiBulk> {
  if (file.size === 0) {
    throw new ApiError('EMPTY_FILE', `The spreadsheet file "${file.name}" is empty (0 bytes). Empty files cannot be scanned.`);
  }
  const body = new FormData();
  body.append('file', file);
  body.append('project_name', project);
  return request('/api/v1/scans/bulk', { method: 'POST', body });
}

export function getBulkScan(id: string): Promise<ApiBulk> {
  return request(`/api/v1/bulk-scans/${id}`);
}

export async function createGitHubPat(name: string, token: string): Promise<string> {
  const created = await request<{ id?: string; ID?: string }>('/api/v1/credentials/github', {
    method: 'POST',
    body: JSON.stringify({
      type: 'GITHUB_FINE_GRAINED_PAT',
      name,
      token,
    }),
  });
  const id = created.id || created.ID;
  if (!id) throw new ApiError('CREDENTIAL_FAILED', 'Credential was stored but no id was returned.');
  return id;
}

export function severityCounts(rows: Array<{ severity?: string }>): {
  criticals: number;
  highs: number;
  mediums: number;
  lows: number;
} {
  const upper = (value?: string) => (value || '').toUpperCase();
  return {
    criticals: rows.filter((row) => upper(row.severity) === 'CRITICAL').length,
    highs: rows.filter((row) => upper(row.severity) === 'HIGH').length,
    mediums: rows.filter((row) => upper(row.severity) === 'MEDIUM').length,
    lows: rows.filter((row) => upper(row.severity) === 'LOW').length,
  };
}

export async function scanPackageTotals(scanId: string): Promise<{
  componentsFound: number;
  cvesFound: number;
  criticals: number;
  highs: number;
  mediums: number;
  lows: number;
}> {
  const [comps, vulns] = await Promise.all([
    scanComponents(scanId),
    scanVulnerabilities(scanId).catch(() => [] as ApiVulnMatch[] | null),
  ]);
  const rows = Array.isArray(vulns) ? vulns : [];
  return {
    componentsFound: comps.length,
    cvesFound: rows.length,
    ...severityCounts(rows),
  };
}

export function exportUrl(scanId: string, format: 'spdx-json' | 'cyclonedx-json' | 'csv' | 'xlsx'): string {
  return `${BASE}/api/v1/scans/${scanId}/export?format=${format}`;
}

export function sourceLabel(scan: {
  source_type?: string;
  file_name?: string;
  repository_url?: string;
  branch?: string;
  description?: string;
  lifecycle_status?: string;
  business_owner?: string;
}): string {
  if (scan.repository_url) {
    return scan.branch ? `${scan.repository_url} (${scan.branch})` : scan.repository_url;
  }
  if (scan.file_name) return scan.file_name;
  if (scan.source_type === 'GITHUB') return 'GitHub repository';
  if (scan.source_type === 'LOCAL') return 'Local upload';
  return scan.source_type || 'Scan';
}

export function formatLocalTimestamp(value?: string): string {
  if (!value) return '';
  let str = value.trim();
  if (!str) return '';
  if (!str.includes('T') && str.includes(' ')) str = str.replace(' ', 'T');
  if (!str.endsWith('Z') && !str.includes('+') && !str.includes('-', 10)) str += 'Z';
  const d = new Date(str);
  if (isNaN(d.getTime())) {
    return value.replace('T', ' ').substring(0, 19);
  }
  const pad = (n: number) => String(n).padStart(2, '0');
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  const seconds = pad(d.getSeconds());
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

export function mapScan(scan: ApiScan): ScanJob {
  const bulkId = scan.bulk_scan_id || undefined;
  const status = mapStatus(scan.status, scan.stage);
  const settled = status === 'completed' || status === 'failed' || status === 'cancelled';
  return {
    id: scan.id,
    targetProject: scan.project_id || scan.application_name,
    appService: scan.application_name,
    releaseTag: scan.application_version,
    description: scan.description || undefined,
    scanType: bulkId ? 'Bulk Scan' : scan.source_type === 'GITHUB' ? 'Remote Git' : 'Local Source',
    source: sourceLabel(scan),
    status,
    stage: scan.stage,
    progress: progressFor(scan.stage, scan.status),
    timestamp: formatLocalTimestamp(scan.created_at),
    componentsFound: 0,
    cvesFound: 0,
    criticals: 0,
    highs: 0,
    mediums: 0,
    lows: 0,
    logMessages: scan.error_message ? [scan.error_message] : [`Stage ${scan.stage || scan.status}`],
    snapshotId: scan.snapshot_id,
    errorCode: scan.error_code || undefined,
    errorMessage: scan.error_message || undefined,
    bulkId,
    bulkRow: scan.bulk_row || undefined,
    startedAt: scan.started_at,
    completedAt: scan.completed_at,
    duration: formatDuration(scan.started_at, settled ? scan.completed_at : undefined),
    lifecycleStatus: (scan as any).lifecycle_status || 'Active',
    businessOwner: scan.business_owner || undefined,
  };
}

export function mapBulkItem(item: ApiBulkItem): BulkScanItemView {
  return {
    rowNumber: item.row_number || 0,
    scanId: item.scan_id || undefined,
    projectName: item.project_name || '',
    applicationName: item.application_name || '',
    version: item.version || '',
    repositoryUrl: item.repository_url || '',
    status: item.status,
    errorCode: item.error_code || undefined,
    errorMessage: item.error_message || undefined,
    createdAt: item.created_at,
    startedAt: item.started_at,
    completedAt: item.completed_at,
    duration: formatDuration(item.started_at, item.completed_at),
  };
}

export function mapBulkStatus(status: string): ScanStatus {
  if (status === 'COMPLETED' || status === 'COMPLETED_WITH_ERRORS') return 'completed';
  if (status === 'FAILED') return 'failed';
  if (status === 'CANCELLED') return 'cancelled';
  if (status === 'PROCESSING') return 'running';
  return 'queued';
}

export function bulkProgress(items: { status: string }[], totalRows: number): number {
  if (!totalRows) return 0;
  const settled = items.filter((item) =>
    ['COMPLETED', 'FAILED', 'SKIPPED', 'DEAD_LETTER', 'CANCELLED'].includes(item.status),
  ).length;
  return Math.min(100, Math.round((settled / totalRows) * 100));
}

export function mapBulkAggregate(bulk: ApiBulk): ScanJob {
  const items = (bulk.items || []).map(mapBulkItem);
  const status = mapBulkStatus(bulk.status);
  const completed = items.filter((item) => item.status === 'COMPLETED').length;
  const failed = items.filter((item) => item.status === 'FAILED' || item.status === 'DEAD_LETTER').length;
  const skipped = items.filter((item) => item.status === 'SKIPPED').length;
  const firstError = bulk.validation_errors?.find((err) => err.message)?.message;
  const settled = status === 'completed' || status === 'failed' || status === 'cancelled';
  const startedAt = bulk.started_at || bulk.created_at;
  const completedAt = bulk.completed_at;
  return {
    id: bulk.id,
    targetProject: bulk.project_id || 'Bulk scan',
    appService: 'Batch',
    releaseTag: `${bulk.total_rows} rows`,
    scanType: 'Bulk Scan',
    source: bulk.filename || 'Bulk spreadsheet',
    status,
    stage: bulk.status,
    progress: settled ? 100 : Math.max(status === 'running' ? 8 : 0, bulkProgress(items, bulk.total_rows)),
    timestamp: formatLocalTimestamp(bulk.created_at),
    componentsFound: 0,
    cvesFound: 0,
    criticals: 0,
    highs: 0,
    mediums: 0,
    lows: 0,
    logMessages: [`${completed} completed, ${failed} failed, ${skipped} skipped, ${bulk.total_rows} total`],
    isBulkAggregate: true,
    bulkId: bulk.id,
    bulkItems: items,
    startedAt,
    completedAt,
    duration: formatDuration(startedAt, settled ? completedAt : undefined),
    errorMessage: status === 'failed' ? (firstError || 'Bulk scan failed') : undefined,
  };
}

export function childJobsFromBulk(bulk: ApiBulk): ScanJob[] {
  return (bulk.items || []).filter((item) => item.scan_id).map((item) => {
    const isSettled = ['COMPLETED', 'FAILED', 'SKIPPED', 'DEAD_LETTER', 'CANCELLED'].includes(item.status);
    const itemStarted = item.started_at || bulk.started_at || bulk.created_at;
    const itemCompleted = isSettled ? (item.completed_at || bulk.completed_at) : undefined;
    return {
      id: item.scan_id as string,
      targetProject: item.project_name || bulk.project_id || 'Bulk scan',
      appService: item.application_name || '',
      releaseTag: item.version || 'UNKNOWN',
      scanType: 'Bulk Scan' as const,
      source: item.repository_url || 'GitHub repository',
      status: mapStatus(item.status, item.status),
      stage: item.status,
      progress: progressFor(item.status === 'QUEUED' || item.status === 'PENDING' ? 'QUEUED' : item.status, item.status),
      timestamp: formatLocalTimestamp(item.created_at || bulk.created_at),
      componentsFound: 0,
      cvesFound: 0,
      criticals: 0,
      highs: 0,
      mediums: 0,
      lows: 0,
      logMessages: item.error_message ? [item.error_message] : [`${item.status}`],
      bulkId: bulk.id,
      bulkRow: item.row_number,
      errorCode: item.error_code || undefined,
      errorMessage: item.error_message || undefined,
      startedAt: itemStarted,
      completedAt: itemCompleted,
      duration: formatDuration(itemStarted, itemCompleted),
    };
  });
}

function lastWorkStage(events: { stage: string }[], stage: string): string {
  if (stage && stage !== 'FAILED' && stage !== 'CANCELLED') return stage;
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const name = events[i].stage;
    if (name && name !== 'FAILED' && name !== 'CANCELLED') return name;
  }
  return stage;
}

export function applyScanUpdate(job: ScanJob, status: ApiScanStatus, events: ApiEvent[] = []): ScanJob {
  const mapped = mapStatus(status.status, status.stage);
  const workStage = lastWorkStage(events, status.stage);
  const eventViews: ScanEventView[] = events.map((event) => ({
    id: event.id,
    stage: event.stage,
    message: event.message,
    createdAt: event.created_at,
  }));
  let source = job.source;
  if (status.repository_url) {
    source = status.branch ? `${status.repository_url} (${status.branch})` : status.repository_url;
  } else if (status.file_name) {
    source = status.file_name;
  }
  const open = mapped === 'queued' || mapped === 'running' || mapped === 'analyzing';
  return {
    ...job,
    status: mapped,
    stage: status.stage,
    progress: progressFor(status.stage, status.status, workStage),
    source,
    errorCode: status.error_code || (open ? undefined : job.errorCode),
    errorMessage: status.error_message || (open ? undefined : job.errorMessage),
    startedAt: status.started_at || job.startedAt,
    completedAt: status.completed_at || (open ? undefined : job.completedAt),
    events: eventViews.length ? eventViews : job.events,
    logMessages: eventViews.length ? eventViews.map((event) => `${event.stage}: ${event.message}`) : job.logMessages,
  };
}

export function mapStatus(status: string, stage: string): ScanStatus {
  if (status === 'COMPLETED') return 'completed';
  if (status === 'CANCELLED') return 'cancelled';
  if (status === 'FAILED' || status === 'DEAD_LETTER') return 'failed';
  if (stage === 'ANALYZING_VULNERABILITIES' || stage === 'GENERATING_SBOM' || stage === 'GENERATING_EXPORT') return 'analyzing';
  if (status === 'RUNNING') return 'running';
  if ((status === 'PENDING' || status === 'QUEUED') && stage && stage !== 'QUEUED') return 'running';
  return 'queued';
}

export function progressFor(stage: string, status: string, fallbackStage = ''): number {
  const table: Record<string, number> = {
    QUEUED: 8,
    PENDING: 8,
    VALIDATING: 18,
    EXTRACTING: 32,
    DETECTING_MANIFESTS: 46,
    PARSING: 55,
    RESOLVING_DEPENDENCIES: 66,
    NORMALIZING: 74,
    ANALYZING_VULNERABILITIES: 86,
    GENERATING_SBOM: 94,
    GENERATING_EXPORT: 97,
    COMPLETED: 100,
  };
  if (status === 'COMPLETED' || stage === 'COMPLETED') return 100;
  const terminal = status === 'FAILED' || status === 'CANCELLED' || status === 'DEAD_LETTER' || stage === 'FAILED' || stage === 'CANCELLED';
  if (terminal) {
    const key = table[stage] != null && stage !== 'FAILED' && stage !== 'CANCELLED' ? stage : fallbackStage;
    return table[key] ?? 12;
  }
  return table[stage] ?? 12;
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

export function mapComponent(c: ApiComponent, project: string, application = '', scanId = ''): SBOMComponent {
  const eco = ecosystems[c.ecosystem] || 'npm';
  return {
    id: c.id,
    name: c.name,
    version: c.version,
    project,
    projectApplication: application,
    scanId: scanId || undefined,
    license: mapLicense(c.license),
    trustScore: 80,
    risk: 'Safe',
    cves: 0,
    patchAvailable: false,
    vex: 'not_affected',
    eol: false,
    ecosystem: eco,
    criticality: c.direct ? 'High' : 'Low',
    directDependency: c.direct,
    supplier: '',
    purl: c.purl,
    compliance: 0,
  };
}
