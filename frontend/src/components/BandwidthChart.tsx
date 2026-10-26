import React from 'react';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from 'recharts';
import { ChartDataPoint } from '../api/types';
import { EmptyState } from './EmptyState';
import { Activity } from 'lucide-react';
import { formatBytes } from '../utils/formatBytes';

interface BandwidthChartProps {
  data: ChartDataPoint[];
  currentRate: number;
}

export const BandwidthChart: React.FC<BandwidthChartProps> = ({ data, currentRate }) => {
  return (
    <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1rem', fontWeight: 600, color: '#fff' }}>Live Network Throughput</h2>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Rolling 60-second window bandwidth rate
          </span>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: '1.125rem', fontWeight: 700, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>
            {formatBytes(currentRate)}/s
          </div>
        </div>
      </div>

      {data.length === 0 ? (
        <EmptyState
          icon={Activity}
          title="No Bandwidth Data"
          description="Live throughput points will stream once packet capture is started."
        />
      ) : (
        <div style={{ width: '100%', height: '230px', flex: 1 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="bandwidthGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="time"
                stroke="var(--text-muted)"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                minTickGap={25}
              />
              <YAxis
                stroke="var(--text-muted)"
                fontSize={11}
                tickLine={false}
                axisLine={false}
                tickFormatter={(val) => formatBytes(val)}
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const item = payload[0].payload as ChartDataPoint;
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
                        <div style={{ color: 'var(--text-muted)', marginBottom: '0.25rem' }}>{item.time}</div>
                        <div>Throughput: <strong style={{ color: '#38bdf8' }}>{formatBytes(item.bytesPerSec)}/s</strong></div>
                        <div>Packet Rate: <strong>{item.packetsPerSec} pkts/s</strong></div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Area
                type="monotone"
                dataKey="bytesPerSec"
                stroke="#06b6d4"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#bandwidthGradient)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};
