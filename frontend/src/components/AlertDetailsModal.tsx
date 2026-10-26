import React from 'react';
import { X, AlertTriangle, CheckCircle, Clock, Repeat } from 'lucide-react';
import { Alert } from '../api/types';
import { formatLocalTime } from '../utils/formatTime';

interface AlertDetailsModalProps {
  alert: Alert | null;
  onClose: () => void;
  onAcknowledge: (alertId: string) => void;
  acknowledging: boolean;
}

export const AlertDetailsModal: React.FC<AlertDetailsModalProps> = ({
  alert,
  onClose,
  onAcknowledge,
  acknowledging,
}) => {
  if (!alert) return null;

  const isHigh = alert.severity.toLowerCase() === 'high';

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
        backdropFilter: 'blur(6px)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        padding: '1.5rem',
      }}
      onClick={onClose}
    >
      <div
        className="glass-panel"
        style={{
          width: '100%',
          maxWidth: '580px',
          background: 'rgba(15, 23, 42, 0.95)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          overflow: 'hidden',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div
          style={{
            padding: '1.25rem 1.5rem',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: isHigh ? 'rgba(244, 63, 94, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: isHigh ? '#fb7185' : '#fbbf24',
              }}
            >
              <AlertTriangle size={18} />
            </div>
            <div>
              <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: '#fff' }}>{alert.title}</h3>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {alert.id} &bull; Rule: {alert.rule_id}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              padding: '0.25rem',
            }}
          >
            <X size={20} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', fontSize: '0.8125rem' }}>
          {/* Description & Heuristic disclaimer */}
          <div
            style={{
              padding: '0.875rem 1rem',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.03)',
              border: '1px solid rgba(255, 255, 255, 0.06)',
              lineHeight: 1.6,
            }}
          >
            <p style={{ color: '#f3f4f6', marginBottom: '0.5rem' }}>{alert.description}</p>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.75rem', fontStyle: 'italic' }}>
              Note: This is a heuristic detection pattern. Legitimate network tools, vulnerability scanners, or address migrations may trigger similar behaviors.
            </p>
          </div>

          {/* Target & Source */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.875rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Source IP</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#38bdf8' }}>
                {alert.source_ip || 'Multiple / Distributed / N/A'}
              </div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Target IP</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#fb7185' }}>
                {alert.target_ip || 'N/A'}
              </div>
            </div>
          </div>

          {/* Timestamps & Occurrence */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.875rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={12} /> First Seen
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{formatLocalTime(alert.first_seen)}</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Clock size={12} /> Last Seen
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', color: '#fff' }}>{formatLocalTime(alert.last_seen)}</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <Repeat size={12} /> Recurrence
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--accent-cyan)' }}>
                {alert.occurrence_count} times
              </div>
            </div>
          </div>

          {/* Evidence Drawer */}
          <div>
            <div style={{ color: 'var(--text-muted)', marginBottom: '0.375rem', fontWeight: 500 }}>
              Detection Evidence:
            </div>
            <pre
              style={{
                background: 'rgba(0, 0, 0, 0.4)',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                borderRadius: '6px',
                padding: '0.875rem',
                fontSize: '0.75rem',
                fontFamily: 'var(--font-mono)',
                color: '#34d399',
                maxHeight: '140px',
                overflowY: 'auto',
              }}
            >
              {JSON.stringify(alert.evidence, null, 2)}
            </pre>
          </div>

          {/* Action Footer */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
            <button className="btn btn-secondary" onClick={onClose}>
              Close
            </button>
            {!alert.acknowledged && (
              <button
                className="btn"
                onClick={() => onAcknowledge(alert.id)}
                disabled={acknowledging}
                style={{
                  background: 'rgba(16, 185, 129, 0.2)',
                  color: '#34d399',
                  border: '1px solid rgba(16, 185, 129, 0.4)',
                  fontWeight: 600,
                }}
              >
                <CheckCircle size={16} />
                <span>{acknowledging ? 'Acknowledging...' : 'Acknowledge Alert'}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
