import React from 'react';
import { X, Network } from 'lucide-react';
import { PacketMetadata } from '../api/types';
import { formatLocalTime } from '../utils/formatTime';

interface PacketDetailModalProps {
  packet: PacketMetadata | null;
  onClose: () => void;
}

export const PacketDetailModal: React.FC<PacketDetailModalProps> = ({ packet, onClose }) => {
  if (!packet) return null;

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
          maxWidth: '560px',
          background: 'rgba(15, 23, 42, 0.95)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          overflow: 'hidden',
          boxShadow: '0 20px 40px rgba(0, 0, 0, 0.6)',
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
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
            <Network size={20} color="var(--accent-cyan)" />
            <h3 style={{ fontSize: '1.0625rem', fontWeight: 600, color: '#fff' }}>
              Packet #{packet.packet_id} Metadata
            </h3>
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

        {/* Modal Body */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.875rem', fontSize: '0.8125rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.875rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Protocol</div>
              <div style={{ fontWeight: 600, color: '#38bdf8', fontFamily: 'var(--font-mono)' }}>{packet.protocol}</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Captured Length</div>
              <div style={{ fontWeight: 600, color: '#fff', fontFamily: 'var(--font-mono)' }}>{packet.length_bytes} bytes</div>
            </div>
          </div>

          <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
            <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Timestamp (UTC / Local)</div>
            <div style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>
              {packet.timestamp} ({formatLocalTime(packet.timestamp)})
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.875rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Source IP:Port</div>
              <div style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>
                {packet.src_ip || '—'} {packet.src_port ? `:${packet.src_port}` : ''}
              </div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Destination IP:Port</div>
              <div style={{ color: '#fff', fontFamily: 'var(--font-mono)' }}>
                {packet.dst_ip || '—'} {packet.dst_port ? `:${packet.dst_port}` : ''}
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.875rem' }}>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Source MAC</div>
              <div style={{ color: '#a78bfa', fontFamily: 'var(--font-mono)' }}>{packet.src_mac || '—'}</div>
            </div>
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>Destination MAC</div>
              <div style={{ color: '#a78bfa', fontFamily: 'var(--font-mono)' }}>{packet.dst_mac || '—'}</div>
            </div>
          </div>

          {packet.protocol === 'TCP' && (
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>TCP Flags</div>
              <div style={{ color: '#fff', fontFamily: 'var(--font-mono)', display: 'flex', gap: '1rem' }}>
                <span>Flags: <strong>{packet.tcp_flags || '—'}</strong></span>
                <span>SYN: <strong>{packet.tcp_syn ? 'Yes' : 'No'}</strong></span>
                <span>ACK: <strong>{packet.tcp_ack ? 'Yes' : 'No'}</strong></span>
              </div>
            </div>
          )}

          {packet.protocol === 'ARP' && (
            <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '0.75rem', borderRadius: '6px' }}>
              <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>ARP Mapping</div>
              <div style={{ color: '#fff', fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>
                Sender: {packet.arp_sender_ip} [{packet.arp_sender_mac}] &rarr; Target: {packet.arp_target_ip}
              </div>
            </div>
          )}

          <div
            style={{
              padding: '0.625rem 0.75rem',
              borderRadius: '6px',
              background: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.15)',
              fontSize: '0.75rem',
              color: '#38bdf8',
            }}
          >
            Passive monitoring notice: raw payload bytes and packet contents are strictly excluded from storage and transmission.
          </div>
        </div>
      </div>
    </div>
  );
};
