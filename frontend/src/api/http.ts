/**
 * HTTP client base request handler and error definition.
 */

export const BASE = import.meta.env.VITE_API_BASE || '';

export class ApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface Envelope<T> {
  success: boolean;
  data: T;
  error?: { code: string; message: string };
}

export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('X-Organization-Id', 'default');
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch (error) {
    if (init.signal?.aborted || (error instanceof DOMException && error.name === 'AbortError')) {
      throw error;
    }
    throw error;
  }
  const text = await res.text();
  let body: (Envelope<T> & { detail?: string }) | null = null;
  if (text) {
    try {
      body = JSON.parse(text) as Envelope<T> & { detail?: string };
    } catch {
      throw new ApiError('INVALID_RESPONSE', 'The scan API returned a non-JSON response.');
    }
  }
  if (!res.ok || body?.success === false) {
    const message = body?.error?.message || body?.detail || res.statusText || 'Request failed';
    throw new ApiError(body?.error?.code || 'REQUEST_FAILED', message);
  }
  return body?.data as T;
}
