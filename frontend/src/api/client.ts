import {
  CaptureStatus,
  InterfaceInfo,
  HostTraffic,
  PacketMetadata,
  Alert,
} from './types';

export interface HealthResponse {
  status: string;
  service: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => null);
    const detail = errorBody?.detail?.error || errorBody?.error;
    const message = detail?.message || `Request failed with status ${response.status}: ${response.statusText}`;
    const error = new Error(message);
    (error as unknown as { code?: string }).code = detail?.code || `HTTP_${response.status}`;
    throw error;
  }

  return response.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  return request<HealthResponse>('/api/health');
}

export async function fetchInterfaces(): Promise<InterfaceInfo[]> {
  const data = await request<{ interfaces: InterfaceInfo[] }>('/api/interfaces');
  return data.interfaces;
}

export async function fetchCaptureStatus(): Promise<CaptureStatus> {
  return request<CaptureStatus>('/api/capture/status');
}

export async function startCapture(interfaceName: string): Promise<CaptureStatus> {
  return request<CaptureStatus>('/api/capture/start', {
    method: 'POST',
    body: JSON.stringify({ interface: interfaceName }),
  });
}

export async function stopCapture(): Promise<CaptureStatus> {
  return request<CaptureStatus>('/api/capture/stop', {
    method: 'POST',
  });
}

export async function fetchTopHosts(windowSeconds = 60, limit = 10, sortBy = 'total_bytes'): Promise<HostTraffic[]> {
  const data = await request<{ hosts: HostTraffic[] }>(
    `/api/metrics/hosts?window_seconds=${windowSeconds}&limit=${limit}&sort_by=${sortBy}`
  );
  return data.hosts;
}

export async function fetchRecentPackets(limit = 50): Promise<PacketMetadata[]> {
  const data = await request<{ packets: PacketMetadata[] }>(`/api/packets?limit=${limit}`);
  return data.packets;
}

export async function fetchAlerts(
  severity?: string,
  acknowledged?: boolean,
  ruleId?: string
): Promise<{ alerts: Alert[]; total: number; unacknowledged_count: number }> {
  const params = new URLSearchParams();
  if (severity) params.set('severity', severity);
  if (acknowledged !== undefined) params.set('acknowledged', String(acknowledged));
  if (ruleId) params.set('rule_id', ruleId);

  return request<{ alerts: Alert[]; total: number; unacknowledged_count: number }>(
    `/api/alerts?${params.toString()}`
  );
}

export async function acknowledgeAlert(alertId: string): Promise<Alert> {
  return request<Alert>(`/api/alerts/${alertId}/acknowledge`, {
    method: 'POST',
  });
}
