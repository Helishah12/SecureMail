import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, Tooltip as ReTooltip, ResponsiveContainer, Cell,
} from 'recharts'
import {
  FileText, Calendar, Hash, ChevronDown,
  AlertTriangle, CheckCircle2, Shield, ArrowRight, Network,
} from 'lucide-react'
import { useAnalysis } from '../store/analysisStore'
import { computeMetrics, getScoreColor, getRiskColor } from '../utils/metrics'
import { SeverityBadge } from '../components/ui/Badges'
import { NoAnalysisState, NoSessionsState } from '../components/ui/States'
import type { RuleExplanation, BehavioralExplanation } from '../types/api'

// ─── Score ring (same as Dashboard) ─────────────────────────────

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 40; const cx = 52; const cy = 52
  const circ = 2 * Math.PI * r
  const offset = circ - (Math.min(score, 100) / 100) * circ
  return (
    <svg width={104} height={104} viewBox="0 0 104 104">
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--surface-overlay)" strokeWidth={8} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={8}
        strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 0.8s cubic-bezier(0.22,1,0.36,1)' }}
      />
      <text x={cx} y={cy - 2} textAnchor="middle" dominantBaseline="middle"
        fill={color} fontSize={22} fontWeight={700} fontFamily="Inter,sans-serif" letterSpacing="-0.04em"
      >{score}</text>
      <text x={cx} y={cy + 14} textAnchor="middle" fill="var(--text-tertiary)"
        fontSize={8} fontWeight={600} fontFamily="Inter,sans-serif" letterSpacing="0.07em"
      >RISK</text>
    </svg>
  )
}

// ─── Finding row (compact list with expand) ───────────────────────

function FindingRow({ finding, sessionIds }: { finding: RuleExplanation; sessionIds: string[] }) {
  const [open, setOpen] = useState(false)
  return (
    <div style={{ borderBottom: '1px solid var(--border-subtle)' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%',
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: '10px var(--space-4)',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          textAlign: 'left',
          transition: 'background 0.08s ease',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-raised)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
        aria-expanded={open}
      >
        {/* Severity dot */}
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: getRiskColor(finding.severity), flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{finding.finding}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 3 }}>
            <SeverityBadge level={finding.severity} size="sm" />
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-tertiary)' }}>{finding.rule}</span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>+{finding.points} pts</span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{sessionIds.length} session{sessionIds.length !== 1 ? 's' : ''}</span>
          </div>
        </div>
        <ChevronDown size={13} style={{ color: 'var(--text-tertiary)', flexShrink: 0, transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 0.15s ease' }} />
      </button>

      {open && (
        <div style={{
          padding: 'var(--space-3) var(--space-4) var(--space-4)',
          background: 'var(--surface-raised)',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          flexDirection: 'column',
          gap: 'var(--space-3)',
        }}>
          <div>
            <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 5 }}>Why it matters</p>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{finding.explanation}</p>
          </div>
          <div style={{
            display: 'flex',
            gap: 8,
            padding: 'var(--space-2) var(--space-3)',
            background: 'var(--accent-muted)',
            border: '1px solid var(--accent-border)',
            borderRadius: 'var(--radius-sm)',
          }}>
            <ArrowRight size={13} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 1 }} />
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{finding.recommendation}</p>
          </div>
          {sessionIds.length > 0 && (
            <p style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
              Affected: {sessionIds.slice(0, 6).join(', ')}{sessionIds.length > 6 ? ` +${sessionIds.length - 6} more` : ''}
            </p>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Behavioral row ──────────────────────────────────────────────

function BehavioralRow({ exp }: { exp: BehavioralExplanation & { sessionId: string } }) {
  const [open, setOpen] = useState(false)
  return (
    <div style={{ borderBottom: '1px solid var(--border-subtle)' }}>
      <button
        onClick={() => setOpen(v => !v)}
        style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 'var(--space-3)',
          padding: '10px var(--space-4)', background: 'none', border: 'none',
          cursor: 'pointer', textAlign: 'left',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-raised)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
        aria-expanded={open}
      >
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--anomaly)', flexShrink: 0 }} />
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>{exp.description}</p>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 3 }}>
            <span className="badge badge-anomaly" style={{ fontSize: 9 }}>Anomaly</span>
            <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{exp.percentile.toFixed(0)}th percentile</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-tertiary)' }}>{exp.sessionId}</span>
          </div>
        </div>
        <ChevronDown size={13} style={{ color: 'var(--text-tertiary)', flexShrink: 0, transform: open ? 'rotate(180deg)' : undefined, transition: 'transform 0.15s ease' }} />
      </button>
      {open && (
        <div style={{ padding: 'var(--space-3) var(--space-4) var(--space-4)', background: 'var(--surface-raised)', borderTop: '1px solid var(--border-subtle)' }}>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{exp.recommendation}</p>
        </div>
      )}
    </div>
  )
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export default function SecurityReport() {
  const { state } = useAnalysis()
  const navigate = useNavigate()
  const { result } = state

  if (!result) {
    return (
      <div className="page">
        <div className="page-header"><h1 className="page-title">Security Report</h1></div>
        <NoAnalysisState onNavigate={() => navigate('/analyze')} />
      </div>
    )
  }

  if (result.session_count === 0) {
    return (
      <div className="page">
        <div className="page-header">
          <h1 className="page-title">Security Report</h1>
          <p className="page-subtitle">{result.filename}</p>
        </div>
        <NoSessionsState />
      </div>
    )
  }

  const m = computeMetrics(result.sessions)
  const scoreColor = getScoreColor(m.avgRiskScore)

  // Aggregate all rule explanations, deduplicated by rule
  type AggFinding = RuleExplanation & { sessionIds: string[] }
  const findingMap = new Map<string, AggFinding>()
  for (const session of result.sessions) {
    for (const exp of session.rule_explanations ?? []) {
      const key = exp.rule + '::' + exp.finding
      if (!findingMap.has(key)) findingMap.set(key, { ...exp, sessionIds: [] })
      findingMap.get(key)!.sessionIds.push(session.session_id)
    }
  }

  const groupedFindings: Record<string, AggFinding[]> = {}
  for (const f of findingMap.values()) {
    if (!groupedFindings[f.severity]) groupedFindings[f.severity] = []
    groupedFindings[f.severity].push(f)
  }

  const behavioralFindings = result.sessions
    .filter(s => s.anomaly === -1)
    .flatMap(s => (s.behavioral_explanations ?? []).map(b => ({ ...b, sessionId: s.session_id })))

  const totalFindings = Array.from(findingMap.values()).length

  // Severity bar data
  const severityBarData = [
    { name: 'Crit', count: m.critical, color: 'var(--critical)' },
    { name: 'High', count: m.high,     color: 'var(--high)' },
    { name: 'Med',  count: m.medium,   color: 'var(--medium)' },
    { name: 'Low',  count: m.low,      color: 'var(--low)' },
  ]

  // Risk contribution: top 5 findings by impact (points × sessions affected)
  const riskContributors = Array.from(findingMap.values())
    .map(f => ({ label: f.finding, impact: f.points * f.sessionIds.length, severity: f.severity, count: f.sessionIds.length }))
    .sort((a, b) => b.impact - a.impact)
    .slice(0, 5)
  const maxImpact = Math.max(...riskContributors.map(r => r.impact), 1)

  return (
    <div className="page">
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-5)' }}>
        <div>
          <h1 className="page-title">Security Report</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--space-4)', marginTop: 'var(--space-1)', flexWrap: 'wrap' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)' }}>
              <FileText size={12} style={{ color: 'var(--text-tertiary)' }} />
              {result.filename}
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)' }}>
              <Hash size={12} style={{ color: 'var(--text-tertiary)' }} />
              {result.session_count} sessions
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--text-secondary)' }}>
              <Calendar size={12} style={{ color: 'var(--text-tertiary)' }} />
              {new Date().toLocaleDateString('en-US', { dateStyle: 'medium' })}
            </span>
          </div>
        </div>
        <button className="btn btn-outline btn-sm" onClick={() => navigate('/sessions')}>
          <Network size={13} />
          Inspect Sessions
        </button>
      </div>

      {/* ── Row 1: Score + summary metrics + severity chart + risk contributors ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '104px 1fr 220px 1fr', gap: 'var(--space-4)', marginBottom: 'var(--space-4)', alignItems: 'stretch' }}>

        {/* Score ring */}
        <div style={{
          background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 'var(--space-3)',
        }}>
          <ScoreRing score={m.avgRiskScore} color={scoreColor} />
        </div>

        {/* Key metrics 2x3 grid */}
        <div style={{
          background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)', padding: 'var(--space-4) var(--space-5)',
          display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 'var(--space-3)',
        }}>
          {[
            { label: 'Sessions', val: m.totalSessions, color: undefined },
            { label: 'Findings', val: totalFindings, color: totalFindings > 0 ? 'var(--high)' : undefined },
            { label: 'Anomalous', val: m.anomalous, color: m.anomalous > 0 ? 'var(--anomaly)' : undefined },
            { label: 'Critical', val: m.critical, color: m.critical > 0 ? 'var(--critical)' : undefined },
            { label: 'High Risk', val: m.high, color: m.high > 0 ? 'var(--high)' : undefined },
            { label: 'Secure', val: m.secure, color: m.secure > 0 ? 'var(--secure)' : undefined },
          ].map(({ label, val, color }) => (
            <div key={label}>
              <p style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</p>
              <p style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1.1, color: color ?? 'var(--text-primary)', marginTop: 2 }}>{val}</p>
            </div>
          ))}
        </div>

        {/* Session risk bar chart */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header" style={{ padding: '10px var(--space-4)' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Session Risk</span>
          </div>
          <div style={{ padding: '0 var(--space-3) var(--space-3)', height: 100 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityBarData} barSize={28} margin={{ top: 4, right: 4, bottom: 0, left: 4 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-tertiary)' }} axisLine={false} tickLine={false} />
                <ReTooltip contentStyle={{ background: 'var(--surface-overlay)', border: '1px solid var(--border-default)', borderRadius: 6, fontSize: 12 }} itemStyle={{ color: 'var(--text-secondary)' }} cursor={false} />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {severityBarData.map((e, i) => <Cell key={i} fill={e.color} fillOpacity={0.85} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Risk contributors */}
        <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
          <div className="panel-header" style={{ padding: '10px var(--space-4)' }}>
            <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Top Risk Contributors</span>
          </div>
          <div style={{ padding: 'var(--space-2) var(--space-4) var(--space-3)', display: 'flex', flexDirection: 'column', gap: 7 }}>
            {riskContributors.length > 0 ? riskContributors.map((r, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 11, color: 'var(--text-tertiary)', width: 14, textAlign: 'right', flexShrink: 0, fontVariantNumeric: 'tabular-nums' }}>{i + 1}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ height: 4, background: 'var(--surface-overlay)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${(r.impact / maxImpact) * 100}%`, height: '100%', background: getRiskColor(r.severity), borderRadius: 2 }} />
                  </div>
                  <p style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                     title={r.label}>{r.label}</p>
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-tertiary)', flexShrink: 0 }}>{r.count}×</span>
              </div>
            )) : (
              <span style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>No risk contributions</span>
            )}
          </div>
        </div>
      </div>

      {/* ── Executive Summary ── */}
      <div style={{
        background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)', padding: 'var(--space-4) var(--space-5)',
        marginBottom: 'var(--space-4)',
      }}>
        <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 'var(--space-2)' }}>Executive Summary</p>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.7, maxWidth: 900 }}>
          Analysis of <strong style={{ color: 'var(--text-primary)' }}>{result.filename}</strong> identified{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{result.session_count}</strong> mail session{result.session_count !== 1 ? 's' : ''}
          {totalFindings > 0 ? (
            <> yielding <strong style={{ color: 'var(--text-primary)' }}>{totalFindings}</strong> security {totalFindings === 1 ? 'finding' : 'findings'}</>
          ) : ' with no security findings'}.
          {m.critical + m.high > 0 && (
            <> <strong style={{ color: 'var(--critical)' }}>{m.critical + m.high}</strong> session{m.critical + m.high !== 1 ? 's require' : ' requires'} immediate remediation.</>
          )}
          {m.anomalous > 0 && (
            <> <strong style={{ color: 'var(--anomaly)' }}>{m.anomalous}</strong> session{m.anomalous !== 1 ? 's exhibit' : ' exhibits'} behavioral anomalies consistent with unusual traffic patterns.</>
          )}
          {m.critical === 0 && m.high === 0 && m.anomalous === 0 && (
            <> The overall security posture is <strong style={{ color: 'var(--secure)' }}>acceptable</strong> with no critical or high-severity issues detected.</>
          )}
        </p>
        {(m.critical + m.high > 0) && (
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'flex-start', gap: 8, padding: '8px 12px', background: 'var(--critical-muted)', border: '1px solid var(--critical-border)', borderRadius: 'var(--radius-sm)' }}>
            <AlertTriangle size={13} style={{ color: 'var(--critical)', flexShrink: 0, marginTop: 1 }} />
            <p style={{ fontSize: 12, color: 'var(--critical)', lineHeight: 1.5 }}>
              Immediate remediation recommended. Review critical and high findings below and apply listed recommendations.
            </p>
          </div>
        )}
        {m.critical === 0 && m.high === 0 && m.medium === 0 && (
          <div style={{ marginTop: 'var(--space-3)', display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'var(--secure-muted)', border: '1px solid var(--secure-border)', borderRadius: 'var(--radius-sm)' }}>
            <CheckCircle2 size={13} style={{ color: 'var(--secure)' }} />
            <p style={{ fontSize: 12, color: 'var(--secure)' }}>No critical or high-severity findings. Mail transport security posture is good.</p>
          </div>
        )}
      </div>

      {/* ── Findings by Severity ── */}
      {SEVERITY_ORDER.filter(sev => groupedFindings[sev]?.length > 0).map(severity => (
        <div key={severity} style={{
          background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)', marginBottom: 'var(--space-3)',
          overflow: 'hidden',
        }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <SeverityBadge level={severity} />
              <span>Findings</span>
              <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-tertiary)' }}>
                {groupedFindings[severity].length} unique · {groupedFindings[severity].reduce((s, f) => s + f.sessionIds.length, 0)} instances
              </span>
            </span>
          </div>
          <div>
            {groupedFindings[severity]
              .sort((a, b) => b.sessionIds.length - a.sessionIds.length)
              .map(f => <FindingRow key={f.rule + f.finding} finding={f} sessionIds={f.sessionIds} />)
            }
          </div>
        </div>
      ))}

      {/* ── Behavioral Anomalies ── */}
      {behavioralFindings.length > 0 && (
        <div style={{
          background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)', marginBottom: 'var(--space-3)',
          overflow: 'hidden',
        }}>
          <div className="panel-header">
            <span className="panel-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="badge badge-anomaly">Behavioral</span>
              <span>Anomalies</span>
              <span style={{ fontSize: 12, fontWeight: 400, color: 'var(--text-tertiary)' }}>{behavioralFindings.length} detected</span>
            </span>
          </div>
          <div>
            {behavioralFindings.map((b, i) => <BehavioralRow key={i} exp={b} />)}
          </div>
        </div>
      )}

      {/* No findings */}
      {Object.keys(groupedFindings).length === 0 && behavioralFindings.length === 0 && (
        <div style={{
          background: 'var(--surface-base)', border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)', padding: 'var(--space-8)',
          display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 'var(--space-3)', textAlign: 'center',
        }}>
          <Shield style={{ width: 32, height: 32, color: 'var(--secure)', opacity: 0.7 }} />
          <p style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)' }}>No security findings detected</p>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 360 }}>
            All analyzed sessions passed security checks. No rule violations or behavioral anomalies were found.
          </p>
        </div>
      )}
    </div>
  )
}
