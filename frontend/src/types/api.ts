// ============================================================
// BACKEND API TYPES — derived from backend source code
// POST /analyze response shape
// ============================================================

export type Protocol = 'SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN'
export type EncryptionMode = 'TLS' | 'STARTTLS' | 'PLAINTEXT'
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type Assessment =
  | 'NO_NOTABLE_ISSUES'
  | 'SECURITY_RISK'
  | 'BEHAVIORAL_ANOMALY'
  | 'SECURITY_RISK_AND_BEHAVIORAL_ANOMALY'

export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'

export interface SecurityFinding {
  rule: string
  severity: FindingSeverity
  message: string
  points: number
}

export interface RuleExplanation {
  rule: string
  severity: FindingSeverity
  points: number
  finding: string
  explanation: string
  recommendation: string
}

export interface BehavioralExplanation {
  feature: string
  description: string
  percentile: number
  recommendation: string
}

export interface Session {
  session_id: string
  protocol: Protocol

  security_risk_score: number
  security_risk_level: RiskLevel
  anomaly: -1 | 1
  anomaly_score: number
  assessment: Assessment

  security_findings: SecurityFinding[]
  rule_explanations: RuleExplanation[]
  behavioral_explanations: BehavioralExplanation[]

  // Encryption
  encryption_mode: EncryptionMode
  starttls_offered: 0 | 1
  starttls_success: 0 | 1
  tls_version: string | null
  cipher_suite: string | null
  key_exchange: string | null
  forward_secrecy: 0 | 1 | null

  // Certificate
  cert_expired: 0 | 1 | null
  cert_not_yet_valid: 0 | 1 | null
  cert_key_algorithm: string | null
  cert_key_size: number | null
  cert_signature_algorithm: string | null
  self_signed: 0 | 1 | null
  hostname_match: 0 | 1 | null

  // Traffic metrics
  packet_count: number
  bytes_sent: number
  bytes_received: number
  retransmission_count: number
  tls_handshake_duration: number
  session_start: number | null
  session_end: number | null
  session_duration_seconds: number
  bytes_total: number
  avg_packet_size: number
}

export interface AnalysisResult {
  filename: string
  session_count: number
  message?: string
  sessions: Session[]
}

export interface ApiError {
  detail: string
}
