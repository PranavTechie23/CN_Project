import React, { useState } from 'react';
import { Alert } from '../api/types';
import { EmptyState } from './EmptyState';
import { AlertDetailsModal } from './AlertDetailsModal';
import { ShieldAlert, CheckCircle, AlertTriangle } from 'lucide-react';
import { formatRelativeTime } from '../utils/formatTime';
import { acknowledgeAlert } from '../api/client';

interface AlertsPanelProps {
  alerts: Alert[];
  onAlertAcknowledged: (alertId: string) => void;
  onError: (msg: string) => void;
}

export const AlertsPanel: React.FC<AlertsPanelProps> = ({
  alerts,
  onAlertAcknowledged,
  onError,
}) => {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [filter, setFilter] = useState<'all' | 'unack' | 'high' | 'medium'>('all');
  const [acknowledgingId, setAcknowledgingId] = useState<string | null>(null);

  const filteredAlerts = alerts.filter((a) => {
    if (filter === 'unack') return !a.acknowledged;
    if (filter === 'high') return a.severity.toLowerCase() === 'high';
    if (filter === 'medium') return a.severity.toLowerCase() === 'medium';
    return true;
  });

  const handleAcknowledge = async (alertId: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setAcknowledgingId(alertId);
    try {
      await acknowledgeAlert(alertId);
      onAlertAcknowledged(alertId);
      if (selectedAlert?.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, acknowledged: true } : null));
      }
    } catch (err: unknown) {
      onError(err instanceof Error ? err.message : 'Failed to acknowledge alert');
    } finally {
      setAcknowledgingId(null);
    }
  };

  const unackCount = alerts.filter((a) => !a.acknowledged).length;

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>Heuristic Anomaly Alerts</h2>
          {unackCount > 0 && (
            <span
              style={{
                fontSize: '0.6875rem',
                padding: '0.15rem 0.5rem',
                borderRadius: '9999px',
                background: 'rgba(244, 63, 94, 0.2)',
                color: '#fb7185',
                border: '1px solid rgba(244, 63, 94, 0.4)',
                fontFamily: 'var(--font-mono)',
                fontWeight: 600,
              }}
            >
              {unackCount} unreviewed
            </span>
          )}
        </div>

        {/* Filter buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem' }}>
          <button
            onClick={() => setFilter('all')}
            className={`btn ${filter === 'all' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            All ({alerts.length})
          </button>
          <button
            onClick={() => setFilter('unack')}
            className={`btn ${filter === 'unack' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            Unack ({unackCount})
          </button>
          <button
            onClick={() => setFilter('high')}
            className={`btn ${filter === 'high' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            High
          </button>
          <button
            onClick={() => setFilter('medium')}
            className={`btn ${filter === 'medium' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            Medium
          </button>
        </div>
      </div>

      {filteredAlerts.length === 0 ? (
        <EmptyState
          icon={ShieldAlert}
          title="No Anomalies Detected"
          description="Deterministic heuristic rules will flag port scans, floods (SYN, ICMP, UDP), stealth scans (XMAS, NULL, SYN-FIN), LAND attacks, or ARP conflicts here."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem', maxHeight: '380px', overflowY: 'auto' }}>
          {filteredAlerts.map((alert) => {
            const isHigh = alert.severity.toLowerCase() === 'high';
            return (
              <div
                key={alert.id}
                onClick={() => setSelectedAlert(alert)}
                style={{
                  padding: '0.875rem 1rem',
                  borderRadius: '8px',
                  background: alert.acknowledged ? 'rgba(255, 255, 255, 0.02)' : 'rgba(255, 255, 255, 0.04)',
                  border: alert.acknowledged
                    ? '1px solid rgba(255, 255, 255, 0.06)'
                    : isHigh
                    ? '1px solid rgba(244, 63, 94, 0.35)'
                    : '1px solid rgba(245, 158, 11, 0.35)',
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '1rem',
                  transition: 'all 0.15s ease',
                  opacity: alert.acknowledged ? 0.65 : 1,
                }}
                onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.06)')}
                onMouseLeave={(e) =>
                  (e.currentTarget.style.backgroundColor = alert.acknowledged
                    ? 'rgba(255, 255, 255, 0.02)'
                    : 'rgba(255, 255, 255, 0.04)')
                }
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
                  <div
                    style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '6px',
                      background: isHigh ? 'rgba(244, 63, 94, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: isHigh ? '#fb7185' : '#fbbf24',
                    }}
                  >
                    <AlertTriangle size={16} />
                  </div>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.2rem' }}>
                      <span style={{ fontWeight: 600, color: '#fff', fontSize: '0.875rem' }}>{alert.title}</span>
                      <span
                        style={{
                          fontSize: '0.625rem',
                          padding: '0.1rem 0.375rem',
                          borderRadius: '4px',
                          textTransform: 'uppercase',
                          fontFamily: 'var(--font-mono)',
                          fontWeight: 700,
                          background: isHigh ? 'rgba(244, 63, 94, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                          color: isHigh ? '#fb7185' : '#fbbf24',
                        }}
                      >
                        {alert.severity}
                      </span>
                      {alert.occurrence_count > 1 && (
                        <span
                          style={{
                            fontSize: '0.625rem',
                            padding: '0.1rem 0.375rem',
                            borderRadius: '4px',
                            background: 'rgba(56, 189, 248, 0.15)',
                            color: '#38bdf8',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          &times;{alert.occurrence_count}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      Target: <span style={{ fontFamily: 'var(--font-mono)', color: '#e2e8f0' }}>{alert.target_ip || 'N/A'}</span>
                      {alert.source_ip && (
                        <> &bull; Source: <span style={{ fontFamily: 'var(--font-mono)', color: '#38bdf8' }}>{alert.source_ip}</span></>
                      )}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {formatRelativeTime(alert.last_seen)}
                  </span>
                  {!alert.acknowledged ? (
                    <button
                      className="btn btn-secondary"
                      onClick={(e) => handleAcknowledge(alert.id, e)}
                      disabled={acknowledgingId === alert.id}
                      style={{ padding: '0.35rem 0.65rem', fontSize: '0.75rem' }}
                      title="Acknowledge alert"
                    >
                      <CheckCircle size={14} color="#34d399" />
                      <span>{acknowledgingId === alert.id ? '...' : 'Acknowledge'}</span>
                    </button>
                  ) : (
                    <span
                      style={{
                        fontSize: '0.6875rem',
                        color: 'var(--text-muted)',
                        padding: '0.2rem 0.4rem',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.04)',
                      }}
                    >
                      Reviewed
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {selectedAlert && (
        <AlertDetailsModal
          alert={selectedAlert}
          onClose={() => setSelectedAlert(null)}
          onAcknowledge={(id) => handleAcknowledge(id)}
          acknowledging={acknowledgingId === selectedAlert.id}
        />
      )}
    </div>
  );
};
