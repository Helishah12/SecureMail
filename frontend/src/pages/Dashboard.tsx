import { useNavigate } from 'react-router-dom'

import {
  AlertTriangle, Shield, Activity, ChevronRight,
  FileText, Wifi, Network, ShieldAlert,
} from 'lucide-react'
import { useAnalysis } from '../store/analysisStore'
import { computeMetrics, getRiskColor, getScoreColor } from '../utils/metrics'
import { SeverityBadge, ProtocolBadge } from '../components/ui/Badges'
import { NoAnalysisState } from '../components/ui/States'



// ── Radial Score Ring ────────────────────────────────────────────
function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 52
  const cx = 68
  const cy = 68
  const circumference = 2 * Math.PI * r
  const clamped = Math.min(score, 100)
  const offset = circumference - (clamped / 100) * circumference

  return (
    <svg width={136} height={136} viewBox="0 0 136 136" aria-label={`Risk score ${score}`}>
      {/* Track */}
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--surface-overlay)" strokeWidth={10} />
      {/* Fill */}
      <circle
        cx={cx} cy={cy} r={r}
        fill="none"
        stroke={color}
        strokeWidth={10}
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.22,1,0.36,1)' }}
      />
      {/* Score text */}
      <text x={cx} y={cy - 4} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={28} fontWeight={700} fontFamily="Inter,sans-serif"
        letterSpacing="-0.04em"
      >{score}</text>
      <text x={cx} y={cy + 18} textAnchor="middle"
        fill="var(--text-tertiary)" fontSize={10} fontWeight={500} fontFamily="Inter,sans-serif"
        letterSpacing="0.06em"
      >RISK SCORE</text>
    </svg>
  )
}

// ── Mini bar (inline severity distribution) ──────────────────────
function SeverityBar({ critical, high, medium, low, total }: {
  critical: number; high: number; medium: number; low: number; total: number
}) {
  if (total === 0) return null
  const pct = (n: number) => `${((n / total) * 100).toFixed(1)}%`
  const segments = [
    { n: critical, color: 'var(--critical)', label: 'Critical' },
    { n: high,     color: 'var(--high)',     label: 'High' },
    { n: medium,   color: 'var(--medium)',   label: 'Medium' },
    { n: low,      color: 'var(--low)',      label: 'Low' },
  ].filter(s => s.n > 0)

  return (
    <div>
      <div style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1 }}>
        {segments.map(s => (
          <div key={s.label} style={{ width: pct(s.n), background: s.color, minWidth: 2 }} title={`${s.label}: ${s.n}`} />
        ))}
      </div>
      <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
        {segments.map(s => (
          <span key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--text-secondary)' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color, flexShrink: 0, display: 'inline-block' }} />
            <span style={{ color: s.color, fontWeight: 600 }}>{s.n}</span>
            <span>{s.label}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

// ── Ranked bar row ───────────────────────────────────────────────
function RankedBar({ label, value, max, color, right }: {
  label: string; value: number; max: number; color: string; right?: React.ReactNode
}) {
  const pct = max > 0 ? (value / max) * 100 : 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
      <span style={{ fontSize: 12, color: 'var(--text-secondary)', width: 90, flexShrink: 0, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{label}</span>
      <div style={{ flex: 1, height: 4, background: 'var(--surface-overlay)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: '100%', height: '100%', background: color, borderRadius: 2, transform: `scaleX(${pct / 100})`, transformOrigin: 'left', transition: 'transform 0.5s ease' }} />
      </div>
      {right ?? <span style={{ fontSize: 12, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums', width: 24, textAlign: 'right' }}>{value}</span>}
    </div>
  )
}

export default function Dashboard() {
  const { state, dispatch } = useAnalysis()
  const navigate = useNavigate()
  const { result } = state

  if (!result) {
    return (
      <div className="page">
        <div className="page-header" style={{ marginBottom: 'var(--space-8)' }}>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-subtitle">Mail transport security overview</p>
        </div>
        <NoAnalysisState onNavigate={() => navigate('/analyze')} />
      </div>
    )
  }

  const m = computeMetrics(result.sessions)
  const scoreColor = getScoreColor(m.avgRiskScore)
  const maxCategoryCount = Math.max(...m.categoryFindings.map(f => f.count), 1)
  const maxTlsCount = Math.max(...m.tlsDistribution.map(d => d.value), 1)
  const maxProtoCount = Math.max(...m.protocolDistribution.map(d => d.value), 1)

  return (
    <div className="page">
      {/* ── Page Header ── */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-5)' }}>
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <p className="page-subtitle">{result.filename} · {result.session_count} session{result.session_count !== 1 ? 's' : ''} analyzed</p>
        </div>
        <button className="btn btn-outline btn-sm" onClick={() => navigate('/analyze')}>
          <FileText size={13} />
          New Analysis
        </button>
      </div>

      {/* ── Row 1: Posture strip ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: '136px 1fr 1fr 1fr',
        gap: 'var(--space-4)',
        marginBottom: 'var(--space-4)',
        alignItems: 'stretch',
      }}>
        {/* Score ring */}
        <div style={{
          background: 'var(--surface-base)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 'var(--space-3)',
        }}>
          <ScoreRing score={m.avgRiskScore} color={scoreColor} />
        </div>

        {/* Session severity breakdown */}
        <div style={{
          background: 'var(--surface-base)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--space-4) var(--space-5)',
        }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 'var(--space-3)' }}>Session Risk Distribution</p>
          <SeverityBar
            critical={m.critical}
            high={m.high}
            medium={m.medium}
            low={m.low}
            total={m.totalSessions}
          />
        </div>

        {/* Key stats */}
        <div style={{
          background: 'var(--surface-base)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--space-4) var(--space-5)',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 'var(--space-3)',
        }}>
          {[
            { label: 'Sessions', val: m.totalSessions, color: undefined },
            { label: 'Findings', val: m.totalFindings, color: m.totalFindings > 0 ? 'var(--high)' : undefined },
            { label: 'Anomalous', val: m.anomalous, color: m.anomalous > 0 ? 'var(--anomaly)' : undefined },
            { label: 'Secure', val: m.secure, color: m.secure > 0 ? 'var(--secure)' : undefined },
          ].map(({ label, val, color }) => (
            <div key={label}>
              <p style={{ fontSize: 11, fontWeight: 500, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</p>
              <p style={{ fontSize: 22, fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1.1, color: color ?? 'var(--text-primary)', marginTop: 2 }}>{val}</p>
            </div>
          ))}
        </div>

        {/* Peak severity + anomaly */}
        <div style={{
          background: 'var(--surface-base)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: 'var(--space-4) var(--space-5)',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          gap: 'var(--space-3)',
        }}>
          <div>
            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>Peak Severity</p>
            <SeverityBadge level={m.peakRiskLevel} />
          </div>
          <div style={{ height: 1, background: 'var(--border-subtle)' }} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {m.anomalous > 0
              ? <><ShieldAlert size={14} style={{ color: 'var(--anomaly)' }} /><span style={{ fontSize: 12, color: 'var(--anomaly)' }}>{m.anomalous} behavioral anomal{m.anomalous === 1 ? 'y' : 'ies'}</span></>
              : <><Shield size={14} style={{ color: 'var(--secure)' }} /><span style={{ fontSize: 12, color: 'var(--secure)' }}>No anomalies detected</span></>
            }
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button className="btn btn-ghost btn-sm" style={{ fontSize: 11, padding: '4px 8px', width: '100%', justifyContent: 'center' }} onClick={() => navigate('/report')}>
              View Full Report <ChevronRight size={11} />
            </button>
          </div>
        </div>
      </div>

      {/* ── Row 2: Finding category bar + TLS + Protocol ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 200px 200px', gap: 'var(--space-4)', marginBottom: 'var(--space-4)' }}>

        {/* Finding categories bar chart */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertTriangle size={13} style={{ color: 'var(--high)' }} />
              Finding Categories
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/report')} style={{ fontSize: 11 }}>
              Report <ChevronRight size={11} />
            </button>
          </div>
          {m.categoryFindings.length > 0 ? (
            <div style={{ padding: 'var(--space-3) var(--space-4) var(--space-4)', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {m.categoryFindings.sort((a,b) => b.count - a.count).map(f => (
                <RankedBar key={f.name} label={f.name} value={f.count} max={maxCategoryCount} color={f.color} />
              ))}
            </div>
          ) : (
            <div style={{ padding: 'var(--space-5)', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--secure)' }}>
              <Shield size={14} />
              <span style={{ fontSize: 12 }}>No findings detected</span>
            </div>
          )}
        </div>

        {/* TLS breakdown */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Wifi size={13} style={{ color: 'var(--text-tertiary)' }} />
              TLS Versions
            </span>
          </div>
          <div style={{ padding: 'var(--space-3) var(--space-4) var(--space-4)', display: 'flex', flexDirection: 'column', gap: 9 }}>
            {m.tlsDistribution.length > 0
              ? m.tlsDistribution.sort((a,b) => b.value - a.value).map(d => (
                <RankedBar key={d.name} label={d.name} value={d.value} max={maxTlsCount} color={d.color} />
              ))
              : <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>No TLS data available</span>
            }
          </div>
        </div>

        {/* Protocol breakdown */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Network size={13} style={{ color: 'var(--text-tertiary)' }} />
              Protocols
            </span>
          </div>
          <div style={{ padding: 'var(--space-3) var(--space-4) var(--space-4)', display: 'flex', flexDirection: 'column', gap: 9 }}>
            {m.protocolDistribution.length > 0
              ? m.protocolDistribution.sort((a,b) => b.value - a.value).map(d => (
                <RankedBar key={d.name} label={d.name} value={d.value} max={maxProtoCount} color={d.color} />
              ))
              : <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>No data</span>
            }
          </div>
        </div>
      </div>

      {/* ── Row 3: Priority findings + High-risk sessions ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 'var(--space-4)' }}>

        {/* Priority findings */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <AlertTriangle size={13} style={{ color: 'var(--high)' }} />
              Investigation Priorities
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>Click row to view report</span>
          </div>
          {m.topFindings.length === 0 ? (
            <div style={{ padding: 'var(--space-5)', display: 'flex', alignItems: 'center', gap: 8, color: 'var(--secure)' }}>
              <Shield size={14} />
              <span style={{ fontSize: 13 }}>No significant findings detected across all sessions.</span>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {m.topFindings.map((f, idx) => (
                <div
                  key={f.rule}
                  onClick={() => navigate('/report')}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 'var(--space-3)',
                    padding: '10px var(--space-4)',
                    borderBottom: idx < m.topFindings.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                    cursor: 'pointer',
                    transition: 'background 0.08s ease',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-raised)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <span style={{ fontSize: 11, color: 'var(--text-tertiary)', fontVariantNumeric: 'tabular-nums', width: 16, textAlign: 'right', flexShrink: 0 }}>{idx + 1}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', lineHeight: 1.3, marginBottom: 2 }}>{f.message}</p>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <SeverityBadge level={f.severity} size="sm" />
                      <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{f.count} session{f.count !== 1 ? 's' : ''} affected</span>
                    </div>
                  </div>
                  <ChevronRight size={14} style={{ color: 'var(--text-tertiary)', flexShrink: 0 }} />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Highest-risk sessions */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Activity size={13} style={{ color: 'var(--text-tertiary)' }} />
              Highest Risk Sessions
            </span>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/sessions')} style={{ fontSize: 11 }}>
              All <ChevronRight size={11} />
            </button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            {m.recentSessions.map((s, idx) => (
              <div
                key={s.session_id}
                onClick={() => { dispatch({ type: 'SELECT_SESSION', payload: s }); navigate('/sessions') }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 'var(--space-3)',
                  padding: '9px var(--space-4)',
                  borderBottom: idx < m.recentSessions.length - 1 ? '1px solid var(--border-subtle)' : 'none',
                  cursor: 'pointer',
                  transition: 'background 0.08s ease',
                }}
                onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-raised)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                {/* Score pill */}
                <span style={{
                  fontSize: 12, fontWeight: 700, letterSpacing: '-0.02em',
                  color: getRiskColor(s.security_risk_level),
                  width: 28, textAlign: 'right', flexShrink: 0,
                  fontVariantNumeric: 'tabular-nums',
                }}>{s.security_risk_score}</span>
                {/* Session ID + protocol */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', marginBottom: 1 }}>{s.session_id}</p>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <ProtocolBadge protocol={s.protocol} />
                    {s.anomaly === -1 && <span className="badge badge-anomaly" style={{ fontSize: 9 }}>Anomaly</span>}
                  </div>
                </div>
                <SeverityBadge level={s.security_risk_level} size="sm" />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
