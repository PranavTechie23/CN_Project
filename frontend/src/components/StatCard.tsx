import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  iconColor?: string;
  accentColor?: string;
  badge?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  iconColor = 'var(--accent-cyan)',
  badge,
}) => {
  return (
    <div
      className="glass-panel"
      style={{
        padding: '1.25rem 1.5rem',
        display: 'flex',
        alignItems: 'flex-start',
        justifyContent: 'space-between',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div>
        <div
          style={{
            fontSize: '0.8125rem',
            color: 'var(--text-secondary)',
            fontWeight: 500,
            marginBottom: '0.375rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>{title}</span>
          {badge && (
            <span
              style={{
                fontSize: '0.6875rem',
                padding: '0.1rem 0.375rem',
                borderRadius: '4px',
                background: 'rgba(255, 255, 255, 0.08)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {badge}
            </span>
          )}
        </div>
        <div
          style={{
            fontSize: '1.625rem',
            fontWeight: 700,
            letterSpacing: '-0.02em',
            color: '#fff',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {value}
        </div>
        {subtitle && (
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--text-muted)',
              marginTop: '0.25rem',
            }}
          >
            {subtitle}
          </div>
        )}
      </div>

      <div
        style={{
          width: '38px',
          height: '38px',
          borderRadius: '8px',
          background: 'rgba(255, 255, 255, 0.04)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: iconColor,
        }}
      >
        <Icon size={20} />
      </div>
    </div>
  );
};
