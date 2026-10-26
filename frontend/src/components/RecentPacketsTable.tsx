import React, { useState } from 'react';
import { PacketMetadata } from '../api/types';
import { EmptyState } from './EmptyState';
import { PacketDetailModal } from './PacketDetailModal';
import { Radio } from 'lucide-react';
import { formatLocalTime } from '../utils/formatTime';

interface RecentPacketsTableProps {
  packets: PacketMetadata[];
}

export const RecentPacketsTable: React.FC<RecentPacketsTableProps> = ({ packets }) => {
  const [selectedPacket, setSelectedPacket] = useState<PacketMetadata | null>(null);

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>Recent Packets</h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Bounded ring buffer (headers only, click row for L2/flags metadata)
          </span>
        </div>
        <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          {packets.length} packets
        </div>
      </div>

      {packets.length === 0 ? (
        <EmptyState
          icon={Radio}
          title="No Packets Captured"
          description="Captured packet headers will stream in live as traffic arrives."
        />
      ) : (
        <div style={{ overflowX: 'auto', maxHeight: '340px', overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead style={{ position: 'sticky', top: 0, background: 'rgba(17, 24, 39, 0.98)', zIndex: 1 }}>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: 'var(--text-muted)', textAlign: 'left' }}>
                <th style={{ padding: '0.5rem 0.625rem' }}>ID</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Time</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Proto</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Source</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Destination</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Length</th>
                <th style={{ padding: '0.5rem 0.625rem' }}>Flags</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt) => (
                <tr
                  key={pkt.packet_id}
                  onClick={() => setSelectedPacket(pkt)}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    cursor: 'pointer',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.04)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    #{pkt.packet_id}
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)' }}>
                    {formatLocalTime(pkt.timestamp)}
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem' }}>
                    <span
                      style={{
                        padding: '0.15rem 0.4rem',
                        borderRadius: '4px',
                        fontSize: '0.6875rem',
                        fontWeight: 600,
                        fontFamily: 'var(--font-mono)',
                        background:
                          pkt.protocol === 'TCP'
                            ? 'rgba(56, 189, 248, 0.15)'
                            : pkt.protocol === 'UDP'
                            ? 'rgba(129, 140, 248, 0.15)'
                            : pkt.protocol === 'ARP'
                            ? 'rgba(251, 191, 36, 0.15)'
                            : 'rgba(255, 255, 255, 0.08)',
                        color:
                          pkt.protocol === 'TCP'
                            ? '#38bdf8'
                            : pkt.protocol === 'UDP'
                            ? '#818cf8'
                            : pkt.protocol === 'ARP'
                            ? '#fbbf24'
                            : '#94a3b8',
                      }}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)' }}>
                    {pkt.src_ip ? `${pkt.src_ip}${pkt.src_port ? `:${pkt.src_port}` : ''}` : '—'}
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)' }}>
                    {pkt.dst_ip ? `${pkt.dst_ip}${pkt.dst_port ? `:${pkt.dst_port}` : ''}` : '—'}
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)' }}>
                    {pkt.length_bytes} B
                  </td>
                  <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'var(--font-mono)', color: pkt.tcp_syn ? '#fb7185' : 'var(--text-muted)' }}>
                    {pkt.tcp_flags || (pkt.tcp_syn ? 'SYN' : '—')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedPacket && (
        <PacketDetailModal packet={selectedPacket} onClose={() => setSelectedPacket(null)} />
      )}
    </div>
  );
};
