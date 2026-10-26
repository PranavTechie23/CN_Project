import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';
import { ProtocolMetric } from '../api/types';
import { EmptyState } from './EmptyState';
import { PieChart as PieIcon } from 'lucide-react';
import { formatBytes } from '../utils/formatBytes';

interface ProtocolChartProps {
  protocols: ProtocolMetric[];
}

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: '#38bdf8',       // Cyan
  UDP: '#818cf8',       // Indigo
  ICMP: '#34d399',      // Emerald
  ICMPv6: '#10b981',    // Teal
  ARP: '#fbbf24',       // Amber
  'IPv6-OTHER': '#a78bfa', // Purple
  OTHER: '#94a3b8',     // Slate
};

export const ProtocolChart: React.FC<ProtocolChartProps> = ({ protocols }) => {
  const activeProtocols = protocols.filter((p) => p.packets > 0);
  const totalPackets = activeProtocols.reduce((sum, p) => sum + p.packets, 0);

  const chartData = activeProtocols.map((p) => ({
    name: p.protocol,
    value: p.packets,
    bytes: p.bytes,
    percentage: totalPackets > 0 ? ((p.packets / totalPackets) * 100).toFixed(1) : '0',
    color: PROTOCOL_COLORS[p.protocol] || '#94a3b8',
  }));

  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>Protocol Distribution</h2>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
          {totalPackets} packets
        </span>
      </div>

      {chartData.length === 0 ? (
        <EmptyState
          icon={PieIcon}
          title="No Traffic Observed"
          description="Protocol breakdown will populate when packets are captured."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', flex: 1, justifyContent: 'space-between' }}>
          <div style={{ width: '100%', height: '190px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0.5)" />
                  ))}
                </Pie>
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div
                          style={{
                            background: 'rgba(15, 23, 42, 0.95)',
                            border: '1px solid var(--border-color)',
                            borderRadius: '6px',
                            padding: '0.5rem 0.75rem',
                            fontSize: '0.75rem',
                            color: '#fff',
                            boxShadow: '0 4px 14px rgba(0,0,0,0.4)',
                          }}
                        >
                          <div style={{ fontWeight: 600, color: data.color, marginBottom: '0.25rem' }}>
                            {data.name}
                          </div>
                          <div>Packets: <strong>{data.value}</strong> ({data.percentage}%)</div>
                          <div>Bytes: <strong>{formatBytes(data.bytes)}</strong></div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Protocol Legend with names, counts, and percentages */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
              gap: '0.5rem',
              marginTop: '0.75rem',
              borderTop: '1px solid rgba(255, 255, 255, 0.06)',
              paddingTop: '0.75rem',
            }}
          >
            {chartData.map((item) => (
              <div
                key={item.name}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  fontSize: '0.75rem',
                  padding: '0.2rem 0.4rem',
                  borderRadius: '4px',
                  background: 'rgba(255, 255, 255, 0.02)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
                  <span
                    style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      backgroundColor: item.color,
                    }}
                  />
                  <span style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{item.name}</span>
                </div>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  {item.value} ({item.percentage}%)
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
