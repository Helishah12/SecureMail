import type { RiskLevel, FindingSeverity } from '../../types/api'

// ============================================================
// SEVERITY BADGE
// ============================================================

interface SeverityBadgeProps {
  level: RiskLevel | FindingSeverity | string
  size?: 'sm' | 'md'
}

const levelClass: Record<string, string> = {
  CRITICAL: 'badge-critical',
  HIGH: 'badge-high',
  MEDIUM: 'badge-medium',
  LOW: 'badge-low',
  SECURE: 'badge-secure',
}

export function SeverityBadge({ level, size = 'md' }: SeverityBadgeProps) {
  const cls = levelClass[level?.toUpperCase()] ?? 'badge-neutral'
  return (
    <span className={`badge ${cls}`} style={size === 'sm' ? { fontSize: 10 } : {}}>
      {level}
    </span>
  )
}

// ============================================================
// PROTOCOL BADGE
// ============================================================

interface ProtocolBadgeProps {
  protocol: string
}

export function ProtocolBadge({ protocol }: ProtocolBadgeProps) {
  return (
    <span className="badge badge-neutral" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
      {protocol}
    </span>
  )
}

// ============================================================
// STATUS DOT
// ============================================================

interface StatusDotProps {
  status: 'ok' | 'warn' | 'error' | 'neutral'
  label?: string
}

const dotColors: Record<string, string> = {
  ok:      'var(--secure)',
  warn:    'var(--medium)',
  error:   'var(--critical)',
  neutral: 'var(--text-tertiary)',
}

export function StatusDot({ status, label }: StatusDotProps) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span
        style={{
          width: 7,
          height: 7,
          borderRadius: '50%',
          background: dotColors[status],
          flexShrink: 0,
          display: 'inline-block',
        }}
      />
      {label && (
        <span style={{ fontSize: 'var(--text-12)', color: 'var(--text-secondary)' }}>
          {label}
        </span>
      )}
    </span>
  )
}
