import type { Session, RiskLevel } from '../types/api'

// ─── Color System ──────────────────────────────────────────────

export function getRiskColor(level: RiskLevel | string): string {
  switch (level?.toUpperCase()) {
    case 'CRITICAL': return 'var(--critical)'
    case 'HIGH':     return 'var(--high)'
    case 'MEDIUM':   return 'var(--medium)'
    case 'LOW':      return 'var(--low)'
    default:         return 'var(--secure)'
  }
}

export function getRiskBg(level: RiskLevel | string): string {
  switch (level?.toUpperCase()) {
    case 'CRITICAL': return 'var(--critical-muted)'
    case 'HIGH':     return 'var(--high-muted)'
    case 'MEDIUM':   return 'var(--medium-muted)'
    case 'LOW':      return 'var(--low-muted)'
    default:         return 'var(--secure-muted)'
  }
}

export function getScoreColor(score: number): string {
  if (score >= 70) return 'var(--critical)'
  if (score >= 40) return 'var(--high)'
  if (score >= 20) return 'var(--medium)'
  return 'var(--secure)'
}

// ─── Formatting ────────────────────────────────────────────────

export function formatBytes(bytes: number): string {
  if (!bytes || isNaN(bytes)) return '—'
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(seconds: number): string {
  if (!seconds || isNaN(seconds)) return '—'
  if (seconds < 0.001) return '<1ms'
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`
  if (seconds < 60) return `${seconds.toFixed(1)}s`
  const m = Math.floor(seconds / 60)
  const s = Math.round(seconds % 60)
  return `${m}m ${s}s`
}

export function safeNum(v: number | null | undefined, fallback = '—'): string {
  if (v === null || v === undefined || isNaN(v as number)) return fallback
  return String(v)
}

export function safeStr(v: string | null | undefined, fallback = '—'): string {
  if (v === null || v === undefined || v === '' || v === 'undefined' || v === 'null') return fallback
  return v
}

// ─── Dashboard Metrics ─────────────────────────────────────────

export interface DashboardMetrics {
  totalSessions: number
  avgRiskScore: number
  peakRiskLevel: RiskLevel
  critical: number
  high: number
  medium: number
  low: number
  anomalous: number
  secure: number

  tlsDistribution: { name: string; value: number; color: string }[]
  protocolDistribution: { name: string; value: number; color: string }[]
  encryptionDistribution: { name: string; value: number; color: string }[]

  categoryFindings: { name: string; count: number; color: string }[]
  topFindings: { rule: string; severity: string; message: string; count: number }[]
  recentSessions: Session[]

  totalFindings: number
  findingsBySeverity: { name: string; count: number; color: string }[]
}

export function computeMetrics(sessions: Session[]): DashboardMetrics {
  const total = sessions.length
  const avgScore = total
    ? Math.round(sessions.reduce((s, x) => s + (x.security_risk_score ?? 0), 0) / total)
    : 0

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  let anomalous = 0
  let secure = 0

  for (const s of sessions) {
    const lvl = s.security_risk_level?.toUpperCase() as RiskLevel
    if (lvl in counts) counts[lvl]++
    if (s.anomaly === -1) anomalous++
    if (s.assessment === 'NO_NOTABLE_ISSUES') secure++
  }

  let peakRiskLevel: RiskLevel = 'LOW'
  if (counts.CRITICAL > 0)    peakRiskLevel = 'CRITICAL'
  else if (counts.HIGH > 0)   peakRiskLevel = 'HIGH'
  else if (counts.MEDIUM > 0) peakRiskLevel = 'MEDIUM'

  // TLS distribution
  const tlsCounts: Record<string, number> = {}
  for (const s of sessions) {
    const v = s.tls_version ?? (s.encryption_mode === 'PLAINTEXT' ? 'Plaintext' : 'Unknown')
    tlsCounts[v] = (tlsCounts[v] ?? 0) + 1
  }
  const tlsColors: Record<string, string> = {
    'TLS 1.3':  'var(--secure)',
    'TLS 1.2':  'var(--low)',
    'TLS 1.1':  'var(--high)',
    'TLS 1.0':  'var(--critical)',
    'Plaintext':'var(--critical)',
    'Unknown':  'var(--text-tertiary)',
  }
  const tlsDistribution = Object.entries(tlsCounts).map(([name, value]) => ({
    name, value, color: tlsColors[name] ?? 'var(--text-tertiary)',
  }))

  // Protocol distribution
  const protoCounts: Record<string, number> = {}
  for (const s of sessions) {
    protoCounts[s.protocol] = (protoCounts[s.protocol] ?? 0) + 1
  }
  const protoColors: Record<string, string> = {
    'SMTP': 'var(--accent)',
    'IMAP': '#06b6d4',
    'POP3': '#8b5cf6',
  }
  const protocolDistribution = Object.entries(protoCounts).map(([name, value]) => ({
    name, value, color: protoColors[name] ?? 'var(--text-tertiary)',
  }))

  // Encryption mode distribution
  const encCounts: Record<string, number> = {}
  for (const s of sessions) {
    const e = s.encryption_mode ?? 'Unknown'
    encCounts[e] = (encCounts[e] ?? 0) + 1
  }
  const encColors: Record<string, string> = {
    'TLS': 'var(--secure)',
    'STARTTLS': 'var(--medium)',
    'PLAINTEXT': 'var(--critical)',
    'Unknown': 'var(--text-tertiary)',
  }
  const encryptionDistribution = Object.entries(encCounts).map(([name, value]) => ({
    name, value, color: encColors[name] ?? 'var(--text-tertiary)',
  }))

  // Category findings (used for bar chart)
  const catCounts: Record<string, number> = {
    'TLS/Cipher': 0,
    'Certificate': 0,
    'Key Strength': 0,
    'STARTTLS': 0,
    'Behavioral': 0,
    'Other': 0,
  }
  const catColors: Record<string, string> = {
    'TLS/Cipher': 'var(--accent)',
    'Certificate': 'var(--high)',
    'Key Strength': 'var(--medium)',
    'STARTTLS': '#06b6d4',
    'Behavioral': 'var(--anomaly)',
    'Other': 'var(--text-tertiary)',
  }

  for (const s of sessions) {
    for (const f of s.rule_explanations ?? []) {
      const rule = f.rule?.toLowerCase() ?? ''
      if (rule.includes('tls') || rule.includes('cipher') || rule.includes('forward') || rule.includes('key_exchange')) {
        catCounts['TLS/Cipher']++
      } else if (rule.includes('cert') || rule.includes('hostname') || rule.includes('self_signed') || rule.includes('expired')) {
        catCounts['Certificate']++
      } else if (rule.includes('key_size') || rule.includes('signature') || rule.includes('algorithm')) {
        catCounts['Key Strength']++
      } else if (rule.includes('starttls') || rule.includes('plaintext')) {
        catCounts['STARTTLS']++
      } else {
        catCounts['Other']++
      }
    }
    for (const _ of s.behavioral_explanations ?? []) {
      catCounts['Behavioral']++
    }
  }

  const categoryFindings = Object.entries(catCounts)
    .filter(([, v]) => v > 0)
    .map(([name, count]) => ({ name, count, color: catColors[name] }))

  // Findings by severity (for donut chart)
  const findingSevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const s of sessions) {
    for (const f of s.rule_explanations ?? []) {
      const sev = f.severity?.toUpperCase()
      if (sev in findingSevCounts) findingSevCounts[sev]++
    }
  }
  const findingsBySeverity = [
    { name: 'Critical', count: findingSevCounts.CRITICAL, color: 'var(--critical)' },
    { name: 'High',     count: findingSevCounts.HIGH,     color: 'var(--high)' },
    { name: 'Medium',   count: findingSevCounts.MEDIUM,   color: 'var(--medium)' },
    { name: 'Low',      count: findingSevCounts.LOW,      color: 'var(--low)' },
  ].filter(x => x.count > 0)

  // Top findings
  const findingCounts: Record<string, { rule: string; severity: string; message: string; count: number }> = {}
  for (const s of sessions) {
    for (const f of s.rule_explanations ?? []) {
      const key = f.rule
      if (!findingCounts[key]) {
        findingCounts[key] = { rule: f.rule, severity: f.severity, message: f.finding, count: 0 }
      }
      findingCounts[key].count++
    }
  }
  const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  const topFindings = Object.values(findingCounts)
    .sort((a, b) =>
      (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99) || b.count - a.count
    )
    .slice(0, 6)

  const recentSessions = [...sessions]
    .sort((a, b) => (b.security_risk_score ?? 0) - (a.security_risk_score ?? 0))
    .slice(0, 8)

  const totalFindings = Object.values(findingCounts).reduce((s, f) => s + f.count, 0)

  return {
    totalSessions: total,
    avgRiskScore: avgScore,
    peakRiskLevel,
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
    anomalous,
    secure,
    tlsDistribution,
    protocolDistribution,
    encryptionDistribution,
    categoryFindings,
    topFindings,
    recentSessions,
    totalFindings,
    findingsBySeverity,
  }
}
