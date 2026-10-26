import React, { useState } from 'react';
import { HostTraffic } from '../api/types';
import { EmptyState } from './EmptyState';
import { Users, ArrowUpDown } from 'lucide-react';
import { formatBytes, formatRate } from '../utils/formatBytes';
import { formatLocalTime } from '../utils/formatTime';

interface HostTableProps {
  hosts: HostTraffic[];
}

type SortField = 'total' | 'tx' | 'rx';

export const HostTable: React.FC<HostTableProps> = ({ hosts }) => {
  const [sortField, setSortField] = useState<SortField>('total');

  const sortedHosts = [...hosts].sort((a, b) => {
    if (sortField === 'tx') return b.tx_bytes - a.tx_bytes;
    if (sortField === 'rx') return b.rx_bytes - a.rx_bytes;
    return (b.tx_bytes + b.rx_bytes) - (a.tx_bytes + a.rx_bytes);
  });

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
        <div>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>Top Network Talkers</h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Per-host traffic and rolling bandwidth rates
          </span>
        </div>

        {/* Sort Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem', fontSize: '0.75rem' }}>
          <span style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <ArrowUpDown size={12} /> Sort by:
          </span>
          <button
            onClick={() => setSortField('total')}
            className={`btn ${sortField === 'total' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            Total
          </button>
          <button
            onClick={() => setSortField('tx')}
            className={`btn ${sortField === 'tx' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            TX
          </button>
          <button
            onClick={() => setSortField('rx')}
            className={`btn ${sortField === 'rx' ? 'btn-secondary' : ''}`}
            style={{ padding: '0.2rem 0.5rem', fontSize: '0.7rem' }}
          >
            RX
          </button>
        </div>
      </div>

      {sortedHosts.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No Hosts Detected"
          description="Addressable host nodes will appear as traffic is captured on the interface."
        />
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8125rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)', color: 'var(--text-muted)', textAlign: 'left' }}>
                <th style={{ padding: '0.625rem 0.75rem' }}>Host IP</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>TX Bytes</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>RX Bytes</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>TX Rate</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>RX Rate</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>Packets (TX/RX)</th>
                <th style={{ padding: '0.625rem 0.75rem' }}>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {sortedHosts.map((host) => (
                <tr
                  key={host.host_ip}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.04)',
                    transition: 'background 0.15s ease',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)')}
                  onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
                >
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 600, color: '#38bdf8' }}>
                    {host.host_ip}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)' }}>
                    {formatBytes(host.tx_bytes)}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)' }}>
                    {formatBytes(host.rx_bytes)}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)' }}>
                    {formatRate(host.tx_bytes_per_second)}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)', color: '#a78bfa' }}>
                    {formatRate(host.rx_bytes_per_second)}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                    {host.tx_packets} / {host.rx_packets}
                  </td>
                  <td style={{ padding: '0.625rem 0.75rem', color: 'var(--text-muted)' }}>
                    {formatLocalTime(host.last_seen)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
