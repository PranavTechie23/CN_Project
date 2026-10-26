import { useEffect, useRef, useState, useCallback } from 'react';
import { Alert, ChartDataPoint, LiveSnapshot, PacketMetadata } from '../api/types';
import { formatLocalTime } from '../utils/formatTime';

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';

export interface UseLiveUpdatesReturn {
  connectionStatus: ConnectionStatus;
  snapshot: LiveSnapshot | null;
  timeSeries: ChartDataPoint[];
  packets: PacketMetadata[];
  alerts: Alert[];
  error: string | null;
  updateAlertAcknowledged: (alertId: string) => void;
  clearAccumulatedState: () => void;
}

export function useLiveUpdates(): UseLiveUpdatesReturn {
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>('connecting');
  const [snapshot, setSnapshot] = useState<LiveSnapshot | null>(null);
  const [timeSeries, setTimeSeries] = useState<ChartDataPoint[]>([]);
  const [packets, setPackets] = useState<PacketMetadata[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const backoffRef = useRef<number>(1000);
  const isMountedRef = useRef<boolean>(true);
  const lastStartedAtRef = useRef<string | null>(null);

  const clearAccumulatedState = useCallback(() => {
    setTimeSeries([]);
    setPackets([]);
    setAlerts([]);
  }, []);

  const updateAlertAcknowledged = useCallback((alertId: string) => {
    setAlerts((prev) =>
      prev.map((a) => (a.id === alertId ? { ...a, acknowledged: true } : a))
    );
  }, []);

  const connect = useCallback(() => {
    if (!isMountedRef.current) return;

    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }

    setConnectionStatus('connecting');

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/live`;

    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        if (!isMountedRef.current) return;
        setConnectionStatus('connected');
        setError(null);
        backoffRef.current = 1000; // Reset backoff upon successful connection
      };

      ws.onmessage = (event) => {
        if (!isMountedRef.current) return;
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'snapshot') {
            const snap = data as LiveSnapshot;
            setSnapshot(snap);

            // Automatically detect session changes or resets from backend
            const currentStartedAt = snap.capture.started_at;
            if (currentStartedAt !== lastStartedAtRef.current) {
              lastStartedAtRef.current = currentStartedAt;
              setTimeSeries([]);
              setPackets([]);
              setAlerts([]);
            }

            // 1. Update time series (rolling last 60 points)
            const point: ChartDataPoint = {
              time: formatLocalTime(snap.timestamp),
              bytesPerSec: snap.metrics.bytes_per_second,
              packetsPerSec: snap.metrics.packets_per_second,
            };
            setTimeSeries((prev) => {
              const updated = [...prev, point];
              return updated.length > 60 ? updated.slice(updated.length - 60) : updated;
            });

            // 2. Upsert recent packets by packet_id (newest first, max 100)
            if (snap.recent_packets && snap.recent_packets.length > 0) {
              setPackets((prev) => {
                const map = new Map<number, PacketMetadata>();
                // Snap recent packets first (newest)
                for (const p of snap.recent_packets) {
                  map.set(p.packet_id, p);
                }
                // Then previous packets
                for (const p of prev) {
                  if (!map.has(p.packet_id)) {
                    map.set(p.packet_id, p);
                  }
                }
                const sorted = Array.from(map.values()).sort((a, b) => b.packet_id - a.packet_id);
                return sorted.slice(0, 100);
              });
            } else if (snap.capture.packets_seen === 0) {
              setPackets([]);
            }

            // 3. Upsert alerts by ID (newest first, max 500)
            if (snap.recent_alerts && snap.recent_alerts.length > 0) {
              setAlerts((prev) => {
                const map = new Map<string, Alert>();
                for (const a of snap.recent_alerts) {
                  map.set(a.id, a);
                }
                for (const a of prev) {
                  if (!map.has(a.id)) {
                    map.set(a.id, a);
                  }
                }
                const sorted = Array.from(map.values()).sort(
                  (a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime()
                );
                return sorted.slice(0, 500);
              });
            } else if (snap.capture.packets_seen === 0) {
              setAlerts([]);
            }
          }
        } catch (err) {
          console.error('Failed to parse WebSocket message:', err);
        }
      };

      ws.onerror = () => {
        if (!isMountedRef.current) return;
        setError('WebSocket encountered a network error.');
      };

      ws.onclose = () => {
        if (!isMountedRef.current) return;
        setConnectionStatus('disconnected');

        // Bounded exponential backoff retry: 1s, 2s, 4s, 8s, max 10s
        const delay = backoffRef.current;
        backoffRef.current = Math.min(delay * 2, 10000);

        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, delay);
      };
    } catch (err: unknown) {
      if (!isMountedRef.current) return;
      setConnectionStatus('disconnected');
      setError(err instanceof Error ? err.message : 'WebSocket initialization failed');
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    connect();

    return () => {
      isMountedRef.current = false;
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
        socketRef.current = null;
      }
    };
  }, [connect]);

  return {
    connectionStatus,
    snapshot,
    timeSeries,
    packets,
    alerts,
    error,
    updateAlertAcknowledged,
    clearAccumulatedState,
  };
}
