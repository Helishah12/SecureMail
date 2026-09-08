import { Drawer } from '../../components/ui/Drawer'
import { SeverityBadge, ProtocolBadge } from '../../components/ui/Badges'
import { getRiskColor, formatBytes, formatDuration, safeStr, safeNum } from '../../utils/metrics'
import type { Session, RuleExplanation, BehavioralExplanation } from '../../types/api'
import React from 'react'
import { ArrowRight, ShieldCheck, ShieldX, Shield } from 'lucide-react'

interface Props {
  session: Session | null
  onClose: () => void
}

// ─── Detail cell ─────────────────────────────────────────────────
function DC({ label, value, mono = false, full = false }: {
  label: string; value: React.ReactNode; mono?: boolean; full?: boolean
}) {
  return (
    <div className={`detail-cell${full ? ' full-width' : ''}`}>
      <div className="detail-label">{label}</div>
      <div className={`detail-value${mono ? ' mono' : ''}`}>{value}</div>
    </div>
  )
}

// ─── Boolean indicator (no emojis) ──────────────────────────────
function BoolValue({ v, trueLabel = 'Yes', falseLabel = 'No', trueGood = true }: {
  v: 0 | 1 | null | undefined
  trueLabel?: string
  falseLabel?: string
  trueGood?: boolean
}) {
  if (v === null || v === undefined) return <span style={{ color: 'var(--text-tertiary)', fontSize: 12 }}>—</span>
  const isGood = trueGood ? v === 1 : v === 0
  const label = v === 1 ? trueLabel : falseLabel
  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12 }}>
      {isGood
        ? <ShieldCheck size={12} style={{ color: 'var(--secure)', flexShrink: 0 }} />
        : <ShieldX size={12} style={{ color: 'var(--critical)', flexShrink: 0 }} />
      }
      <span style={{ color: isGood ? 'var(--secure)' : 'var(--critical)' }}>{label}</span>
    </span>
  )
}

export function SessionDetailDrawer({ session, onClose }: Props) {
  if (!session) return null

  const dur = session.session_duration_seconds ?? 0

  return (
    <Drawer open={!!session} onClose={onClose} title={`Session ${session.session_id}`}>

      {/* Summary header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 'var(--space-3)',
        padding: 'var(--space-3) var(--space-4)',
        background: 'var(--surface-raised)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-md)',
        marginBottom: 'var(--space-5)',
      }}>
        {/* Color indicator */}
        <div style={{
          width: 3, alignSelf: 'stretch', borderRadius: 2,
          background: getRiskColor(session.security_risk_level), flexShrink: 0,
        }} />
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
            <ProtocolBadge protocol={session.protocol} />
            <SeverityBadge level={session.security_risk_level} />
            {session.anomaly === -1 && <span className="badge badge-anomaly">Anomaly</span>}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>
            Risk score: <strong style={{ color: getRiskColor(session.security_risk_level) }}>{session.security_risk_score}</strong>
            <span style={{ margin: '0 6px' }}>·</span>
            Anomaly score: {isNaN(session.anomaly_score) ? '—' : session.anomaly_score.toFixed(4)}
          </div>
        </div>
      </div>

      {/* ── Identification ── */}
      <p className="section-label">Identification</p>
      <div className="detail-grid" style={{ marginBottom: 'var(--space-4)' }}>
        <DC label="Session ID" value={safeStr(session.session_id)} mono />
        <DC label="Protocol" value={<ProtocolBadge protocol={session.protocol} />} />
        <DC label="Assessment" value={
          <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: session.assessment === 'NO_NOTABLE_ISSUES' ? 'var(--secure)' : 'var(--text-secondary)' }}>
            {session.assessment?.replace(/_/g, ' ') ?? '—'}
          </span>
        } full />
      </div>

      {/* ── TLS / Encryption ── */}
      <p className="section-label">TLS & Encryption</p>
      <div className="detail-grid" style={{ marginBottom: 'var(--space-4)' }}>
        <DC label="Encryption Mode" value={
          <span style={{ fontSize: 12, color: session.encryption_mode === 'PLAINTEXT' ? 'var(--critical)' : 'var(--text-primary)', fontWeight: session.encryption_mode === 'PLAINTEXT' ? 600 : undefined }}>
            {safeStr(session.encryption_mode)}
          </span>
        } />
        <DC label="TLS Version" value={
          <span style={{ fontSize: 12, color: session.tls_version === 'TLS 1.3' ? 'var(--secure)' : session.tls_version === 'TLS 1.1' || session.tls_version === 'TLS 1.0' ? 'var(--high)' : 'var(--text-primary)' }}>
            {safeStr(session.tls_version)}
          </span>
        } />
        <DC label="Forward Secrecy" value={<BoolValue v={session.forward_secrecy} trueLabel="Enabled" falseLabel="Disabled" />} />
        <DC label="Key Exchange" value={safeStr(session.key_exchange)} />
        <DC label="STARTTLS Offered" value={<BoolValue v={session.starttls_offered} trueLabel="Yes" falseLabel="No" />} />
        <DC label="STARTTLS Success" value={<BoolValue v={session.starttls_success} trueLabel="Yes" falseLabel="No" />} />
        <DC label="Cipher Suite" value={safeStr(session.cipher_suite)} mono full />
      </div>

      {/* ── Certificate ── */}
      <p className="section-label">Certificate</p>
      <div className="detail-grid" style={{ marginBottom: 'var(--space-4)' }}>
        <DC label="Validity" value={<BoolValue v={session.cert_expired === 1 ? 0 : session.cert_expired === 0 ? 1 : null} trueLabel="Valid" falseLabel="Expired" />} />
        <DC label="Not Yet Valid" value={<BoolValue v={session.cert_not_yet_valid === 0 ? 1 : session.cert_not_yet_valid === 1 ? 0 : null} trueLabel="No issue" falseLabel="Not yet valid" />} />
        <DC label="Self-Signed" value={<BoolValue v={session.self_signed} trueLabel="Yes" falseLabel="No" trueGood={false} />} />
        <DC label="Hostname Match" value={<BoolValue v={session.hostname_match} trueLabel="Match" falseLabel="Mismatch" />} />
        <DC label="Key Algorithm" value={safeStr(session.cert_key_algorithm)} />
        <DC label="Key Size" value={session.cert_key_size != null && !isNaN(session.cert_key_size) ? `${session.cert_key_size} bits` : '—'} />
        <DC label="Signature Algorithm" value={safeStr(session.cert_signature_algorithm)} mono full />
      </div>

      {/* ── Traffic ── */}
      <p className="section-label">Traffic</p>
      <div className="detail-grid" style={{ marginBottom: 'var(--space-4)' }}>
        <DC label="Packets" value={safeNum(session.packet_count)} />
        <DC label="Duration" value={formatDuration(dur)} />
        <DC label="Bytes Sent" value={formatBytes(session.bytes_sent)} />
        <DC label="Bytes Received" value={formatBytes(session.bytes_received)} />
        <DC label="Retransmissions" value={safeNum(session.retransmission_count)} />
        <DC label="TLS Handshake" value={session.tls_handshake_duration ? formatDuration(session.tls_handshake_duration) : '—'} />
      </div>

      {/* ── Security Findings ── */}
      {(session.rule_explanations?.length ?? 0) > 0 && (
        <>
          <p className="section-label">Security Findings ({session.rule_explanations.length})</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 'var(--space-4)' }}>
            {session.rule_explanations.map((f: RuleExplanation, i: number) => (
              <div key={i} style={{
                background: 'var(--surface-raised)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-md)',
                overflow: 'hidden',
              }}>
                <div style={{ padding: '10px var(--space-4)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, flexWrap: 'wrap' }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: getRiskColor(f.severity), flexShrink: 0, display: 'inline-block' }} />
                    <SeverityBadge level={f.severity} size="sm" />
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-tertiary)' }}>{f.rule}</span>
                    <span style={{ fontSize: 10, color: 'var(--text-tertiary)' }}>+{f.points} pts</span>
                  </div>
                  <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 4 }}>{f.finding}</p>
                  <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 6 }}>{f.explanation}</p>
                  <div style={{ display: 'flex', gap: 6, padding: '6px 8px', background: 'var(--accent-muted)', borderRadius: 'var(--radius-sm)' }}>
                    <ArrowRight size={12} style={{ color: 'var(--accent)', flexShrink: 0, marginTop: 1 }} />
                    <p style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{f.recommendation}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {/* ── Behavioral Anomalies ── */}
      {(session.behavioral_explanations?.length ?? 0) > 0 && (
        <>
          <p className="section-label">Behavioral Anomalies</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginBottom: 'var(--space-4)' }}>
            {session.behavioral_explanations.map((b: BehavioralExplanation, i: number) => (
              <div key={i} style={{
                background: 'var(--surface-raised)',
                border: '1px solid var(--anomaly-border)',
                borderRadius: 'var(--radius-md)',
                padding: '10px var(--space-4)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span className="badge badge-anomaly" style={{ fontSize: 9 }}>Anomaly</span>
                  <span style={{ fontSize: 11, color: 'var(--text-tertiary)' }}>{b.percentile.toFixed(0)}th percentile</span>
                </div>
                <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 4 }}>{b.description}</p>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{b.recommendation}</p>
              </div>
            ))}
          </div>
        </>
      )}

      {/* Clean session */}
      {(session.rule_explanations?.length ?? 0) === 0 && (session.behavioral_explanations?.length ?? 0) === 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: 'var(--space-4)', background: 'var(--secure-muted)', border: '1px solid var(--secure-border)', borderRadius: 'var(--radius-md)' }}>
          <Shield size={14} style={{ color: 'var(--secure)', flexShrink: 0 }} />
          <p style={{ fontSize: 13, color: 'var(--secure)' }}>No security findings or anomalies for this session.</p>
        </div>
      )}
    </Drawer>
  )
}
