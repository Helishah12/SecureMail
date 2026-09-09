import { useState, useCallback, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  UploadCloud, File, X, AlertCircle, ShieldCheck, HardDrive, Lock, Activity,
} from 'lucide-react'
import { analyzeFile } from '../api/analyze'
import { useAnalysis } from '../store/analysisStore'

const ACCEPTED = ['.pcap', '.pcapng']
const MAX_SIZE_MB = 500

function isValidFile(f: File): string | null {
  const name = f.name.toLowerCase()
  if (!ACCEPTED.some(ext => name.endsWith(ext))) return 'Only .pcap and .pcapng files are supported.'
  if (f.size > MAX_SIZE_MB * 1024 * 1024) return `File size exceeds ${MAX_SIZE_MB} MB.`
  return null
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

// ── Flow step indicator ──────────────────────────────────────────
function FlowStep({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{
        width: 20, height: 20,
        borderRadius: '50%',
        background: done ? 'var(--secure)' : active ? 'var(--accent)' : 'var(--surface-overlay)',
        border: `1px solid ${done ? 'var(--secure-border)' : active ? 'var(--accent-border)' : 'var(--border-default)'}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0, transition: 'all 0.2s ease',
      }}>
        {done && <svg width="10" height="10" viewBox="0 0 10 10"><polyline points="1.5,5 4,7.5 8.5,2.5" fill="none" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>}
        {!done && <div style={{ width: 5, height: 5, borderRadius: '50%', background: active ? '#fff' : 'var(--border-default)' }} />}
      </div>
      <span style={{ fontSize: 11, fontWeight: 500, color: done ? 'var(--secure)' : active ? 'var(--text-primary)' : 'var(--text-tertiary)', letterSpacing: '0.02em' }}>{label}</span>
    </div>
  )
}

function FlowArrow() {
  return <div style={{ width: 24, height: 1, background: 'var(--border-default)', flexShrink: 0 }} />
}

export default function AnalyzePCAP() {
  const navigate = useNavigate()
  const { state, dispatch } = useAnalysis()
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const selectFile = useCallback((f: File) => {
    const err = isValidFile(f)
    setFileError(err)
    setSelectedFile(err ? null : f)
  }, [])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) selectFile(f)
  }, [selectFile])

  const handleAnalyze = async () => {
    if (!selectedFile || state.loading) return
    dispatch({ type: 'ANALYZE_START' })
    try {
      const result = await analyzeFile(selectedFile)
      dispatch({ type: 'ANALYZE_SUCCESS', payload: result })
      navigate('/report')
    } catch (err) {
      dispatch({ type: 'ANALYZE_ERROR', payload: (err as Error).message ?? 'Analysis failed.' })
    }
  }

  const { loading, error } = state
  const step = loading ? 'analyzing' : selectedFile ? 'ready' : 'select'

  return (
    <div className="page" style={{ maxWidth: 680 }}>
      <div className="page-header" style={{ marginBottom: 'var(--space-5)' }}>
        <h1 className="page-title">Analyze PCAP</h1>
        <p className="page-subtitle">Upload a packet capture to analyze mail transport security</p>
      </div>

      {/* Flow indicator */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        marginBottom: 'var(--space-5)',
        padding: 'var(--space-3) var(--space-4)',
        background: 'var(--surface-base)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-md)',
      }}>
        <FlowStep label="Select PCAP" active={step === 'select'} done={step === 'ready' || step === 'analyzing'} />
        <FlowArrow />
        <FlowStep label="Validate" active={step === 'ready'} done={step === 'analyzing'} />
        <FlowArrow />
        <FlowStep label="Analyze" active={step === 'analyzing'} done={false} />
        <FlowArrow />
        <FlowStep label="Results" active={false} done={false} />
      </div>

      {/* Upload zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload PCAP file"
        onClick={() => !selectedFile && !loading && inputRef.current?.click()}
        onDrop={handleDrop}
        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onKeyDown={e => { if ((e.key === 'Enter' || e.key === ' ') && !selectedFile && !loading) inputRef.current?.click() }}
        style={{
          border: `1px dashed ${dragOver ? 'var(--accent)' : selectedFile ? 'var(--border-default)' : 'var(--border-default)'}`,
          borderRadius: 'var(--radius-xl)',
          background: dragOver ? 'var(--accent-muted)' : selectedFile ? 'var(--surface-raised)' : 'var(--surface-base)',
          padding: loading ? 'var(--space-10) var(--space-6)' : 'var(--space-8) var(--space-6)',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 'var(--space-3)',
          cursor: selectedFile || loading ? 'default' : 'pointer',
          transition: 'background 0.15s ease, border-color 0.15s ease',
          marginBottom: 'var(--space-4)',
          textAlign: 'center',
          boxShadow: dragOver ? '0 0 0 3px rgba(99,102,241,0.08)' : undefined,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng"
          style={{ display: 'none' }}
          onChange={e => { const f = e.target.files?.[0]; if (f) selectFile(f); e.target.value = '' }}
        />

        {loading ? (
          <>
            <div style={{
              width: 52, height: 52,
              borderRadius: 'var(--radius-xl)',
              background: 'var(--accent-muted)',
              border: '1px solid var(--accent-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <div className="spinner spinner-lg" style={{ color: 'var(--accent)' }} />
            </div>
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Analyzing packet capture…</p>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 340, lineHeight: 1.5 }}>
              Extracting sessions · Evaluating TLS · Parsing certificates · Running anomaly detection
            </p>
          </>
        ) : selectedFile ? (
          <>
            <div style={{
              width: 44, height: 44,
              borderRadius: 'var(--radius-lg)',
              background: 'var(--accent-muted)',
              border: '1px solid var(--accent-border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--accent)',
            }}>
              <File size={20} />
            </div>
            <div>
              <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>{selectedFile.name}</p>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 'var(--space-4)', flexWrap: 'wrap' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--text-secondary)' }}>
                  <HardDrive size={12} />{formatFileSize(selectedFile.size)}
                </span>
                <span style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: 'var(--secure)' }}>
                  <ShieldCheck size={12} />Ready to analyze
                </span>
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={e => { e.stopPropagation(); setSelectedFile(null); setFileError(null) }} style={{ color: 'var(--text-tertiary)', marginTop: 'var(--space-1)' }}>
              <X size={12} />Remove
            </button>
          </>
        ) : (
          <>
            <div style={{
              width: 44, height: 44,
              borderRadius: 'var(--radius-lg)',
              background: 'var(--surface-overlay)',
              border: '1px solid var(--border-default)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              color: 'var(--text-tertiary)',
            }}>
              <UploadCloud size={20} />
            </div>
            <div>
              <p style={{ fontSize: 14, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 4 }}>Drop your PCAP file here</p>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                or <span style={{ color: 'var(--accent)', cursor: 'pointer' }}>browse to upload</span>
              </p>
            </div>
            <p style={{ fontSize: 12, color: 'var(--text-tertiary)' }}>.pcap · .pcapng · up to {MAX_SIZE_MB} MB</p>
          </>
        )}
      </div>

      {/* Validation error */}
      {fileError && (
        <div className="error-banner" style={{ marginBottom: 'var(--space-3)' }}>
          <AlertCircle />
          <span>{fileError}</span>
        </div>
      )}

      {/* API error */}
      {error && !loading && (
        <div className="error-banner" style={{ marginBottom: 'var(--space-3)' }}>
          <AlertCircle />
          <div>
            <p style={{ fontWeight: 500 }}>Analysis failed</p>
            <p style={{ fontSize: 12, marginTop: 2, opacity: 0.85 }}>{error}</p>
          </div>
        </div>
      )}

      {/* Action */}
      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 'var(--space-8)' }}>
        <button
          className="btn btn-primary btn-lg"
          onClick={handleAnalyze}
          disabled={!selectedFile || loading}
          style={{ minWidth: 150 }}
        >
          {loading ? (
            <><div className="spinner" style={{ color: '#fff' }} />Analyzing…</>
          ) : (
            <><ShieldCheck size={15} />Analyze File</>
          )}
        </button>
        {selectedFile && !loading && (
          <button className="btn btn-outline btn-lg" onClick={() => inputRef.current?.click()}>
            Change File
          </button>
        )}
      </div>

      {/* What gets analyzed */}
      <div style={{ background: 'var(--surface-base)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-lg)' }}>
        <div className="panel-header">
          <span className="panel-title">What gets analyzed</span>
        </div>
        <div style={{ padding: 'var(--space-4)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 'var(--space-4)' }}>
          {[
            { icon: Lock, title: 'TLS Security', desc: 'Version, cipher suites, key exchange, forward secrecy' },
            { icon: AlertCircle, title: 'STARTTLS', desc: 'Offered/success status and negotiation failures' },
            { icon: File, title: 'Certificates', desc: 'Expiry, self-signing, hostname matching, key strength' },
            { icon: Activity, title: 'Behavioral', desc: 'Anomalous sessions via isolation forest model' },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} style={{ display: 'flex', gap: 'var(--space-3)' }}>
              <div style={{
                width: 30, height: 30,
                borderRadius: 'var(--radius-md)',
                background: 'var(--surface-raised)',
                border: '1px solid var(--border-subtle)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0,
              }}>
                <Icon size={14} style={{ color: 'var(--text-tertiary)' }} />
              </div>
              <div>
                <p style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 2 }}>{title}</p>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.45 }}>{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
