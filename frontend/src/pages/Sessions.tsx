import { useState, useMemo } from 'react'
import {
  Search, ShieldCheck, ChevronDown, ChevronUp, Shield, ShieldAlert, AlertTriangle,
} from 'lucide-react'
import { useAnalysis } from '../store/analysisStore'
import { SessionDetailDrawer } from '../components/sessions/SessionDetailDrawer'
import { SeverityBadge, ProtocolBadge } from '../components/ui/Badges'
import { formatBytes, getRiskColor, safeStr } from '../utils/metrics'
import type { RiskLevel } from '../types/api'
import { NoAnalysisState, NoSessionsState } from '../components/ui/States'
import { useNavigate } from 'react-router-dom'

type SortField =
  | 'session_id'
  | 'protocol'
  | 'security_risk_score'
  | 'anomaly'
  | 'assessment'
  | 'packet_count'
  | 'bytes_total'
  | 'tls_version'

export default function Sessions() {
  const { state, dispatch } = useAnalysis()
  const navigate = useNavigate()
  const { result, selectedSession } = state

  const [search, setSearch] = useState('')
  const [sortField, setSortField] = useState<SortField>('security_risk_score')
  const [sortDesc, setSortDesc] = useState(true)
  const [filterSeverity, setFilterSeverity] = useState<RiskLevel | 'ALL'>('ALL')
  const [filterAnomaly, setFilterAnomaly] = useState<'ALL' | 'ANOMALOUS'>('ALL')
  const [filterProtocol, setFilterProtocol] = useState<string>('ALL')

  const filteredAndSorted = useMemo(() => {
    if (!result) return []
    let data = [...result.sessions]

    if (search) {
      const q = search.toLowerCase()
      data = data.filter(s =>
        s.session_id.toLowerCase().includes(q) ||
        s.protocol.toLowerCase().includes(q) ||
        (s.tls_version && s.tls_version.toLowerCase().includes(q)) ||
        (s.cipher_suite && s.cipher_suite.toLowerCase().includes(q))
      )
    }

    if (filterSeverity !== 'ALL') {
      data = data.filter(s => s.security_risk_level === filterSeverity)
    }
    if (filterAnomaly === 'ANOMALOUS') {
      data = data.filter(s => s.anomaly === -1)
    }
    if (filterProtocol !== 'ALL') {
      data = data.filter(s => s.protocol === filterProtocol)
    }

    data.sort((a, b) => {
      let aVal: string | number = sortField === 'bytes_total'
        ? a.bytes_sent + a.bytes_received
        : (a[sortField] as string | number) ?? ''
      let bVal: string | number = sortField === 'bytes_total'
        ? b.bytes_sent + b.bytes_received
        : (b[sortField] as string | number) ?? ''

      if (typeof aVal === 'string') aVal = aVal || ''
      if (typeof bVal === 'string') bVal = bVal || ''

      if (aVal < bVal) return sortDesc ? 1 : -1
      if (aVal > bVal) return sortDesc ? -1 : 1
      return 0
    })

    return data
  }, [result, search, sortField, sortDesc, filterSeverity, filterAnomaly, filterProtocol])

  const toggleSort = (field: SortField) => {
    if (sortField === field) setSortDesc(!sortDesc)
    else { setSortField(field); setSortDesc(true) }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <span style={{ opacity: 0.2 }}><ChevronDown size={12} /></span>
    return sortDesc ? <ChevronDown size={12} style={{ color: 'var(--accent)' }} /> : <ChevronUp size={12} style={{ color: 'var(--accent)' }} />
  }

  if (!result) {
    return (
      <div className="page">
        <div className="page-header"><h1 className="page-title">Sessions</h1></div>
        <NoAnalysisState onNavigate={() => navigate('/analyze')} />
      </div>
    )
  }

  if (result.session_count === 0) {
    return (
      <div className="page">
        <div className="page-header">
          <h1 className="page-title">Sessions</h1>
          <p className="page-subtitle">{result.filename}</p>
        </div>
        <NoSessionsState />
      </div>
    )
  }

  // Summary counts for strip
  const critical = result.sessions.filter(s => s.security_risk_level === 'CRITICAL').length
  const high = result.sessions.filter(s => s.security_risk_level === 'HIGH').length
  const anomalous = result.sessions.filter(s => s.anomaly === -1).length
  const secure = result.sessions.filter(s => s.assessment === 'NO_NOTABLE_ISSUES').length
  const protocols = [...new Set(result.sessions.map(s => s.protocol))]

  return (
    <div className="page">
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 'var(--space-4)' }}>
        <div>
          <h1 className="page-title">Sessions</h1>
          <p className="page-subtitle">{result.filename} · {result.session_count} session{result.session_count !== 1 ? 's' : ''}</p>
        </div>
      </div>

      {/* ── Summary Strip ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(5, 1fr)',
        gap: 1,
        background: 'var(--border-subtle)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        overflow: 'hidden',
        marginBottom: 'var(--space-4)',
      }}>
        {[
          { label: 'Total', val: result.session_count, color: undefined, icon: <Shield size={13} />, onClick: () => setFilterSeverity('ALL') },
          { label: 'Critical', val: critical, color: critical > 0 ? 'var(--critical)' : undefined, icon: <AlertTriangle size={13} />, onClick: () => setFilterSeverity('CRITICAL') },
          { label: 'High Risk', val: high, color: high > 0 ? 'var(--high)' : undefined, icon: <AlertTriangle size={13} />, onClick: () => setFilterSeverity('HIGH') },
          { label: 'Anomalous', val: anomalous, color: anomalous > 0 ? 'var(--anomaly)' : undefined, icon: <ShieldAlert size={13} />, onClick: () => setFilterAnomaly(filterAnomaly === 'ANOMALOUS' ? 'ALL' : 'ANOMALOUS') },
          { label: 'Secure', val: secure, color: secure > 0 ? 'var(--secure)' : undefined, icon: <ShieldCheck size={13} />, onClick: () => { setFilterSeverity('ALL'); setFilterAnomaly('ALL') } },
        ].map(({ label, val, color, icon, onClick }) => (
          <button
            key={label}
            onClick={onClick}
            style={{
              background: 'var(--surface-base)',
              padding: 'var(--space-3) var(--space-4)',
              border: 'none',
              cursor: 'pointer',
              textAlign: 'left',
              transition: 'background 0.1s ease',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-raised)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'var(--surface-base)')}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: color ?? 'var(--text-tertiary)', marginBottom: 4 }}>
              {icon}
              <span style={{ fontSize: 11, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.05em' }}>{label}</span>
            </div>
            <p style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.03em', lineHeight: 1, color: color ?? 'var(--text-primary)' }}>{val}</p>
          </button>
        ))}
      </div>

      {/* ── Table panel ── */}
      <div style={{
        background: 'var(--surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        display: 'flex',
        flexDirection: 'column',
        minHeight: 400,
      }}>
        {/* Toolbar */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: 'var(--space-3) var(--space-4)',
          borderBottom: '1px solid var(--border-subtle)',
          flexWrap: 'wrap',
        }}>
          <div style={{ position: 'relative', flex: '0 0 260px' }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: 8, color: 'var(--text-tertiary)' }} />
            <input
              className="input"
              placeholder="Search ID, protocol, cipher…"
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ paddingLeft: 30, fontSize: 12, height: 30 }}
            />
          </div>

          <div style={{ width: 1, height: 20, background: 'var(--border-default)', flexShrink: 0 }} />

          {/* Severity chips */}
          <div style={{ display: 'flex', gap: 4 }}>
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
              <button
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                style={{
                  padding: '3px 9px',
                  fontSize: 11,
                  fontWeight: 500,
                  borderRadius: 99,
                  border: `1px solid ${filterSeverity === sev ? 'var(--border-strong)' : 'var(--border-default)'}`,
                  background: filterSeverity === sev
                    ? sev === 'ALL' ? 'var(--surface-selected)'
                    : sev === 'CRITICAL' ? 'var(--critical-muted)'
                    : sev === 'HIGH' ? 'var(--high-muted)'
                    : sev === 'MEDIUM' ? 'var(--medium-muted)'
                    : 'var(--low-muted)'
                    : 'transparent',
                  color: filterSeverity === sev
                    ? sev === 'ALL' ? 'var(--text-primary)'
                    : sev === 'CRITICAL' ? 'var(--critical)'
                    : sev === 'HIGH' ? 'var(--high)'
                    : sev === 'MEDIUM' ? 'var(--medium)'
                    : 'var(--low)'
                    : 'var(--text-secondary)',
                  cursor: 'pointer',
                  transition: 'all 0.1s ease',
                }}
              >{sev === 'ALL' ? 'All' : sev.charAt(0) + sev.slice(1).toLowerCase()}</button>
            ))}
          </div>

          <div style={{ width: 1, height: 20, background: 'var(--border-default)', flexShrink: 0 }} />

          {/* Protocol filter */}
          {protocols.length > 1 && (
            <div style={{ display: 'flex', gap: 4 }}>
              {(['ALL', ...protocols] as const).map(p => (
                <button
                  key={p}
                  onClick={() => setFilterProtocol(p)}
                  style={{
                    padding: '3px 9px',
                    fontSize: 11,
                    fontWeight: 500,
                    borderRadius: 99,
                    border: `1px solid ${filterProtocol === p ? 'var(--accent-border)' : 'var(--border-default)'}`,
                    background: filterProtocol === p ? 'var(--accent-muted)' : 'transparent',
                    color: filterProtocol === p ? 'var(--accent)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                    transition: 'all 0.1s ease',
                    fontFamily: p !== 'ALL' ? 'var(--font-mono)' : undefined,
                  }}
                >{p}</button>
              ))}
            </div>
          )}

          <div style={{ width: 1, height: 20, background: 'var(--border-default)', flexShrink: 0 }} />

          {/* Anomaly toggle */}
          <button
            onClick={() => setFilterAnomaly(filterAnomaly === 'ALL' ? 'ANOMALOUS' : 'ALL')}
            style={{
              padding: '3px 9px',
              fontSize: 11,
              fontWeight: 500,
              borderRadius: 99,
              border: `1px solid ${filterAnomaly === 'ANOMALOUS' ? 'var(--anomaly-border)' : 'var(--border-default)'}`,
              background: filterAnomaly === 'ANOMALOUS' ? 'var(--anomaly-muted)' : 'transparent',
              color: filterAnomaly === 'ANOMALOUS' ? 'var(--anomaly)' : 'var(--text-secondary)',
              cursor: 'pointer',
              transition: 'all 0.1s ease',
            }}
          >Anomalous only</button>
        </div>

        {/* Table */}
        <div style={{ flex: 1, overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => toggleSort('session_id')} style={{ paddingLeft: 'var(--space-4)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>ID <SortIcon field="session_id" /></div>
                </th>
                <th className="sortable" onClick={() => toggleSort('security_risk_score')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>Risk <SortIcon field="security_risk_score" /></div>
                </th>
                <th className="sortable" onClick={() => toggleSort('protocol')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>Protocol <SortIcon field="protocol" /></div>
                </th>
                <th className="sortable" onClick={() => toggleSort('tls_version')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>TLS <SortIcon field="tls_version" /></div>
                </th>
                <th>Cipher</th>
                <th>Fwd Secrecy</th>
                <th className="sortable" onClick={() => toggleSort('packet_count')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>Packets <SortIcon field="packet_count" /></div>
                </th>
                <th className="sortable" onClick={() => toggleSort('bytes_total')}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>Traffic <SortIcon field="bytes_total" /></div>
                </th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {filteredAndSorted.map(s => (
                <tr
                  key={s.session_id}
                  onClick={() => dispatch({ type: 'SELECT_SESSION', payload: s })}
                  className={selectedSession?.session_id === s.session_id ? 'selected' : ''}
                  tabIndex={0}
                  onKeyDown={e => e.key === 'Enter' && dispatch({ type: 'SELECT_SESSION', payload: s })}
                  aria-label={`Session ${s.session_id}`}
                >
                  <td style={{ paddingLeft: 'var(--space-4)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {/* Risk dot */}
                      <span style={{
                        width: 7, height: 7, borderRadius: '50%',
                        background: getRiskColor(s.security_risk_level),
                        flexShrink: 0, display: 'inline-block',
                      }} />
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{s.session_id}</span>
                    </div>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: getRiskColor(s.security_risk_level), fontVariantNumeric: 'tabular-nums', minWidth: 24 }}>
                        {s.security_risk_score}
                      </span>
                      <SeverityBadge level={s.security_risk_level} size="sm" />
                    </div>
                  </td>
                  <td><ProtocolBadge protocol={s.protocol} /></td>
                  <td>
                    <span style={{
                      fontSize: 12,
                      color: s.encryption_mode === 'PLAINTEXT' ? 'var(--critical)' : s.tls_version === 'TLS 1.3' ? 'var(--secure)' : 'var(--text-secondary)',
                      fontWeight: s.encryption_mode === 'PLAINTEXT' ? 600 : undefined,
                    }}>
                      {safeStr(s.tls_version) !== '—' ? s.tls_version : s.encryption_mode}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-tertiary)' }} title={s.cipher_suite ?? undefined}>
                      {s.cipher_suite ? (s.cipher_suite.length > 20 ? s.cipher_suite.slice(0, 20) + '…' : s.cipher_suite) : '—'}
                    </span>
                  </td>
                  <td>
                    {s.forward_secrecy === null ? (
                      <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>—</span>
                    ) : s.forward_secrecy === 1 ? (
                      <span style={{ color: 'var(--secure)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                        <ShieldCheck size={12} /> Yes
                      </span>
                    ) : (
                      <span style={{ color: 'var(--critical)', fontSize: 12 }}>No</span>
                    )}
                  </td>
                  <td>
                    <span style={{ fontVariantNumeric: 'tabular-nums', fontSize: 12 }}>{s.packet_count ?? '—'}</span>
                  </td>
                  <td>
                    <span style={{ color: 'var(--text-secondary)', fontSize: 12 }}>
                      {formatBytes(s.bytes_sent + s.bytes_received)}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      {(s.rule_explanations?.length ?? 0) > 0 && (
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>
                          {s.rule_explanations.length} finding{s.rule_explanations.length !== 1 ? 's' : ''}
                        </span>
                      )}
                      {s.anomaly === -1 && <span className="badge badge-anomaly" style={{ fontSize: 9 }}>Anomaly</span>}
                      {(s.rule_explanations?.length ?? 0) === 0 && s.anomaly !== -1 && (
                        <span style={{ color: 'var(--secure)', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <ShieldCheck size={12} /> Clean
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {filteredAndSorted.length === 0 && (
            <div style={{ padding: 'var(--space-10)', textAlign: 'center' }}>
              <Shield style={{ width: 28, height: 28, color: 'var(--text-tertiary)', opacity: 0.4, margin: '0 auto var(--space-3)' }} />
              <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>No sessions match the current filters</p>
              <button
                className="btn btn-ghost btn-sm"
                style={{ marginTop: 'var(--space-3)' }}
                onClick={() => { setFilterSeverity('ALL'); setFilterAnomaly('ALL'); setFilterProtocol('ALL'); setSearch('') }}
              >Clear filters</button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{
          padding: '8px var(--space-4)',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
            {filteredAndSorted.length} of {result.session_count} sessions · Click row to inspect
          </span>
          {(filterSeverity !== 'ALL' || filterAnomaly !== 'ALL' || filterProtocol !== 'ALL' || search) && (
            <button
              className="btn btn-ghost btn-sm"
              style={{ fontSize: 11 }}
              onClick={() => { setFilterSeverity('ALL'); setFilterAnomaly('ALL'); setFilterProtocol('ALL'); setSearch('') }}
            >Clear filters</button>
          )}
        </div>
      </div>

      <SessionDetailDrawer
        session={selectedSession}
        onClose={() => dispatch({ type: 'SELECT_SESSION', payload: null })}
      />
    </div>
  )
}
