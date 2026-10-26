import React, { useEffect, useState } from 'react';
import { Shield, Play, Square, RefreshCw, Radio } from 'lucide-react';
import { InterfaceInfo, CaptureStatus } from '../api/types';
import { fetchInterfaces, startCapture, stopCapture } from '../api/client';
import { ConnectionStatus } from '../hooks/useLiveUpdates';
import { formatLocalTime } from '../utils/formatTime';

interface AppHeaderProps {
  captureStatus: CaptureStatus | null;
  connectionStatus: ConnectionStatus;
  onStatusChange: (status: CaptureStatus) => void;
  onError: (msg: string) => void;
  onStartSession: () => void;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  captureStatus,
  connectionStatus,
  onStatusChange,
  onError,
  onStartSession,
}) => {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedIface, setSelectedIface] = useState<string>('');
  const [loadingIfaces, setLoadingIfaces] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);

  const loadInterfaces = async () => {
    setLoadingIfaces(true);
    try {
      const list = await fetchInterfaces();
      setInterfaces(list);
      if (list.length > 0 && !selectedIface) {
        // Prioritize interface with active IPv4 address (e.g. en0 Wi-Fi or eth0 Ethernet)
        const hasIpv4 = (i: InterfaceInfo) =>
          i.addresses.some((a) => a.includes('.') && !a.startsWith('127.'));
        const preferred =
          list.find((i) => !i.is_loopback && i.is_up && hasIpv4(i)) ||
          list.find((i) => (i.name === 'en0' || i.name === 'eth0') && i.is_up) ||
          list.find((i) => !i.is_loopback && i.is_up) ||
          list[0];
        setSelectedIface(preferred.name);
      }
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to query host network interfaces');
    } finally {
      setLoadingIfaces(false);
    }
  };

  useEffect(() => {
    loadInterfaces();
  }, []);

  // Update selected iface if running
  useEffect(() => {
    if (captureStatus?.interface) {
      setSelectedIface(captureStatus.interface);
    }
  }, [captureStatus?.interface]);

  const handleStart = async () => {
    if (!selectedIface) return;
    const iface = selectedIface.trim();
    if (!iface) return;
    setActionLoading(true);
    try {
      onStartSession();
      const updated = await startCapture(iface);
      onStatusChange(updated);
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to start packet capture');
    } finally {
      setActionLoading(false);
    }
  };

  const handleStop = async () => {
    setActionLoading(true);
    try {
      const updated = await stopCapture();
      onStatusChange(updated);
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to stop packet capture');
    } finally {
      setActionLoading(false);
    }
  };

  const isRunning = captureStatus?.state === 'running';
  const isTransitioning = captureStatus?.state === 'starting' || captureStatus?.state === 'stopping' || actionLoading;

  return (
    <header
      className="glass-panel"
      style={{
        padding: '1.25rem 1.75rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1.25rem',
        marginBottom: '1.5rem',
      }}
    >
      {/* Brand & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
        <div
          style={{
            width: '44px',
            height: '44px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, #0284c7, #6366f1)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            boxShadow: '0 4px 16px rgba(2, 132, 199, 0.4)',
          }}
        >
          <Shield size={24} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 700, letterSpacing: '-0.02em', color: '#fff' }}>
              Sniffy
            </h1>
            <span
              style={{
                fontSize: '0.7rem',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
              }}
            >
              v1.0 MVP
            </span>
          </div>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
            Network Traffic Analyzer & Heuristic Anomaly Detector
          </p>
        </div>
      </div>

      {/* Capture Controls & Interface Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
        {/* Connection status badge */}
        {connectionStatus === 'connected' ? (
          <div className="badge badge-success" title="WebSocket live stream active">
            <span className="pulse-dot"></span> Live Stream
          </div>
        ) : connectionStatus === 'connecting' ? (
          <div className="badge badge-info" title="Connecting to WebSocket">
            <span className="pulse-dot"></span> Reconnecting...
          </div>
        ) : (
          <div className="badge badge-error" title="Live stream disconnected">
            <span className="pulse-dot"></span> Offline
          </div>
        )}

        {/* Capture state badge */}
        <div
          className={`badge ${
            isRunning ? 'badge-success' : captureStatus?.state === 'error' ? 'badge-error' : 'badge-info'
          }`}
          style={{ textTransform: 'uppercase' }}
        >
          {captureStatus?.state || 'stopped'}
        </div>

        {/* Interface Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
          <select
            value={selectedIface}
            onChange={(e) => setSelectedIface(e.target.value)}
            disabled={isRunning || isTransitioning}
            style={{
              background: 'rgba(17, 24, 39, 0.9)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-color)',
              borderRadius: 'var(--radius-sm)',
              padding: '0.45rem 0.75rem',
              fontSize: '0.8125rem',
              fontFamily: 'var(--font-mono)',
              outline: 'none',
              cursor: isRunning ? 'not-allowed' : 'pointer',
            }}
          >
            {interfaces.map((i) => (
              <option key={i.name} value={i.name}>
                {i.name} {i.is_loopback ? '(loopback)' : ''} {i.addresses.length > 0 ? `[${i.addresses[0]}]` : ''}
              </option>
            ))}
          </select>

          <button
            className="btn btn-secondary"
            onClick={loadInterfaces}
            disabled={isRunning || loadingIfaces}
            title="Refresh network interfaces"
            style={{ padding: '0.45rem 0.65rem' }}
          >
            <RefreshCw size={14} style={{ animation: loadingIfaces ? 'spin 1s linear infinite' : 'none' }} />
          </button>
        </div>

        {/* Start / Stop Toggle Button */}
        {isRunning ? (
          <button
            onClick={handleStop}
            disabled={isTransitioning}
            className="btn"
            style={{
              background: 'rgba(244, 63, 94, 0.2)',
              color: '#fb7185',
              border: '1px solid rgba(244, 63, 94, 0.4)',
              fontWeight: 600,
            }}
          >
            <Square size={14} fill="#fb7185" />
            <span>Stop Capture</span>
          </button>
        ) : (
          <button
            onClick={handleStart}
            disabled={!selectedIface || isTransitioning}
            className="btn"
            style={{
              background: 'linear-gradient(135deg, #0284c7, #2563eb)',
              color: '#fff',
              border: '1px solid rgba(56, 189, 248, 0.5)',
              fontWeight: 600,
              boxShadow: '0 2px 10px rgba(2, 132, 199, 0.3)',
            }}
          >
            <Play size={14} fill="#fff" />
            <span>Start Capture</span>
          </button>
        )}
      </div>

      {/* Active Session Info strip if running */}
      {isRunning && captureStatus?.interface && (
        <div
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingTop: '0.75rem',
            borderTop: '1px solid rgba(255, 255, 255, 0.06)',
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Radio size={14} color="#34d399" />
            <span>
              Capturing passively on interface: <strong style={{ color: '#fff' }}>{captureStatus.interface}</strong>
            </span>
          </div>
          <div>
            Session started at: <strong>{formatLocalTime(captureStatus.started_at)}</strong>
          </div>
        </div>
      )}
    </header>
  );
};
