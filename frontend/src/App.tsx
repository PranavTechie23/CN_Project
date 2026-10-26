import React, { useState, useEffect } from 'react';
import { useLiveUpdates } from './hooks/useLiveUpdates';
import { AppHeader } from './components/AppHeader';
import { StatCard } from './components/StatCard';
import { ProtocolChart } from './components/ProtocolChart';
import { BandwidthChart } from './components/BandwidthChart';
import { HostTable } from './components/HostTable';
import { RecentPacketsTable } from './components/RecentPacketsTable';
import { AlertsPanel } from './components/AlertsPanel';
import { ErrorBanner } from './components/ErrorBanner';
import { fetchCaptureStatus } from './api/client';
import { CaptureStatus } from './api/types';
import { formatBytes } from './utils/formatBytes';
import {
  Layers,
  Database,
  Activity,
  AlertTriangle,
} from 'lucide-react';

export default function App(): React.JSX.Element {
  const {
    connectionStatus,
    snapshot,
    timeSeries,
    packets,
    alerts,
    error: liveError,
    updateAlertAcknowledged,
    clearAccumulatedState,
  } = useLiveUpdates();

  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Sync capture status initially via REST and continuously via snapshot
  useEffect(() => {
    fetchCaptureStatus()
      .then(setCaptureStatus)
      .catch((err) => {
        setErrorMessage(err instanceof Error ? err.message : 'Failed to query initial capture status');
      });
  }, []);

  useEffect(() => {
    if (snapshot?.capture) {
      setCaptureStatus(snapshot.capture);
    }
  }, [snapshot?.capture]);

  const unackAlertsCount = alerts.filter((a) => !a.acknowledged).length;
  const currentBps = snapshot?.metrics.bytes_per_second || 0;
  const currentPps = snapshot?.metrics.packets_per_second || 0;
  const totalSessionPackets = snapshot?.metrics.session_packets ?? captureStatus?.packets_seen ?? 0;
  const totalSessionBytes = snapshot?.metrics.session_bytes ?? 0;

  return (
    <div style={{ maxWidth: '1440px', margin: '0 auto', padding: '1.5rem 1.25rem 3rem' }}>
      {/* Header with Capture Controls */}
      <AppHeader
        captureStatus={captureStatus}
        connectionStatus={connectionStatus}
        onStatusChange={setCaptureStatus}
        onError={setErrorMessage}
        onStartSession={clearAccumulatedState}
      />

      {/* Error Banners */}
      {errorMessage && (
        <ErrorBanner message={errorMessage} onDismiss={() => setErrorMessage(null)} />
      )}
      {liveError && connectionStatus !== 'connected' && (
        <ErrorBanner message={`${liveError} Live streaming may be paused.`} />
      )}

      {/* KPI Stats Row */}
      <section
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '1rem',
          marginBottom: '1.5rem',
        }}
      >
        <StatCard
          title="Session Packets"
          value={totalSessionPackets.toLocaleString()}
          subtitle="Processed in active session"
          icon={Layers}
          iconColor="#38bdf8"
        />

        <StatCard
          title="Observed Volume"
          value={formatBytes(totalSessionBytes)}
          subtitle="Total wire bytes observed"
          icon={Database}
          iconColor="#818cf8"
        />

        <StatCard
          title="Current Throughput"
          value={`${formatBytes(currentBps)}/s`}
          subtitle={`${currentPps} packets / second`}
          icon={Activity}
          iconColor="var(--accent-cyan)"
          badge="60s window"
        />

        <StatCard
          title="Unreviewed Alerts"
          value={unackAlertsCount}
          subtitle={`${alerts.length} total anomalies detected`}
          icon={AlertTriangle}
          iconColor={unackAlertsCount > 0 ? '#fb7185' : '#34d399'}
          badge={unackAlertsCount > 0 ? 'Action required' : 'All clear'}
        />
      </section>

      {/* Visualizations Row: Protocols & Live Throughput */}
      <section
        style={{
          display: 'grid',
          gridTemplateColumns: 'minmax(320px, 1fr) minmax(420px, 2fr)',
          gap: '1.5rem',
          marginBottom: '1.5rem',
        }}
      >
        <ProtocolChart protocols={snapshot?.protocols || []} />
        <BandwidthChart data={timeSeries} currentRate={currentBps} />
      </section>

      {/* Upper Data Row: Top Network Talkers */}
      <section style={{ marginBottom: '1.5rem' }}>
        <HostTable hosts={snapshot?.top_hosts || []} />
      </section>

      {/* Lower Data Grid: Recent Packets (headers only) & Anomaly Alerts Feed */}
      <section
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(480px, 1fr))',
          gap: '1.5rem',
        }}
      >
        <RecentPacketsTable packets={packets} />
        <AlertsPanel
          alerts={alerts}
          onAlertAcknowledged={updateAlertAcknowledged}
          onError={setErrorMessage}
        />
      </section>
    </div>
  );
}
