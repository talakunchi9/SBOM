/**
 * Catalog API operations for projects and modules.
 */

import { request } from './http';

export interface CatalogRecord {
  id: string;
  name: string;
  project_id?: string;
}

export interface CatalogPage {
  items: CatalogRecord[];
  next_cursor: string | null;
}

export function listCatalogProjects(params?: { q?: string; limit?: number; cursor?: string; signal?: AbortSignal }): Promise<CatalogPage> {
  const query = new URLSearchParams({ limit: String(params?.limit || 50) });
  if (params?.q) query.set('q', params.q);
  if (params?.cursor) query.set('cursor', params.cursor);
  return request(`/api/v1/catalog/projects?${query.toString()}`, { signal: params?.signal });
}

export function listCatalogApplications(
  projectId: string,
  params?: { q?: string; limit?: number; cursor?: string; signal?: AbortSignal },
): Promise<CatalogPage> {
  const query = new URLSearchParams({ limit: String(params?.limit || 50) });
  if (params?.q) query.set('q', params.q);
  if (params?.cursor) query.set('cursor', params.cursor);
  return request(`/api/v1/catalog/projects/${encodeURIComponent(projectId)}/applications-services?${query.toString()}`, {
    signal: params?.signal,
  });
}

export function createCatalogProject(input: {
  name: string;
  applications?: string[] | { name: string }[];
}): Promise<{ id: string; name: string; applications: CatalogRecord[] }> {
  return request('/api/v1/catalog/projects', {
    method: 'POST',
    body: JSON.stringify({
      name: input.name,
      applications: input.applications || [],
    }),
  });
}

export function createCatalogApplication(projectId: string, name: string): Promise<CatalogRecord> {
  return request(`/api/v1/catalog/projects/${encodeURIComponent(projectId)}/applications-services`, {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
}
