import { AlertCircle } from 'lucide-react'
import { ShieldOff, Inbox, UploadCloud } from 'lucide-react'

// ============================================================
// EMPTY STATE
// ============================================================

interface EmptyStateProps {
  icon?: React.ReactNode
  title: string
  description?: string
  action?: React.ReactNode
}

export function EmptyState({ icon, title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state-icon">{icon}</div>}
      <p className="empty-state-title">{title}</p>
      {description && <p className="empty-state-desc">{description}</p>}
      {action}
    </div>
  )
}

// ============================================================
// ERROR STATE
// ============================================================

interface ErrorStateProps {
  message: string
  onRetry?: () => void
}

export function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div className="empty-state">
      <AlertCircle style={{ width: 36, height: 36, color: 'var(--critical)', opacity: 0.8 }} />
      <p className="empty-state-title">Something went wrong</p>
      <p className="empty-state-desc">{message}</p>
      {onRetry && (
        <button className="btn btn-outline btn-sm" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  )
}

// ============================================================
// LOADING STATE
// ============================================================

interface LoadingStateProps {
  message?: string
  sub?: string
}

export function LoadingState({ message = 'Loading…', sub }: LoadingStateProps) {
  return (
    <div className="analyzing-state">
      <div className="spinner spinner-lg" style={{ color: 'var(--accent)' }} />
      <p className="analyzing-title">{message}</p>
      {sub && <p className="analyzing-sub">{sub}</p>}
    </div>
  )
}

// ============================================================
// NO ANALYSIS STATE
// ============================================================

export function NoAnalysisState({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <div className="empty-state">
      <Inbox style={{ width: 36, height: 36, opacity: 0.3 }} />
      <p className="empty-state-title">No analysis loaded</p>
      <p className="empty-state-desc">
        Upload a PCAP file to analyze mail traffic and see security findings.
      </p>
      {onNavigate && (
        <button className="btn btn-primary btn-sm" onClick={onNavigate}>
          <UploadCloud size={14} />
          Analyze PCAP
        </button>
      )}
    </div>
  )
}

// ============================================================
// NO SESSIONS STATE
// ============================================================

export function NoSessionsState() {
  return (
    <div className="empty-state">
      <ShieldOff style={{ width: 36, height: 36, opacity: 0.3 }} />
      <p className="empty-state-title">No mail sessions detected</p>
      <p className="empty-state-desc">
        No SMTP, IMAP, or POP3 sessions were found in the capture file.
      </p>
    </div>
  )
}
