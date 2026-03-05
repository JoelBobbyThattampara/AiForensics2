import { useState, useEffect, useCallback } from 'react'
import { api } from './api/fctt-client'
import type { CaseRecord } from './api/fctt-client'
import Dashboard from './components/Dashboard'
import CaseManager from './components/CaseManager'
import EvidenceIngestion from './components/EvidenceIngestion'
import TriageEngine from './components/TriageEngine'
import MemoryAnalysis from './components/MemoryAnalysis'
import PCAPAnalyser from './components/PCAPAnalyser'
import Timeline from './components/Timeline'
import FullTextSearch from './components/FullTextSearch'
import HexViewer from './components/HexViewer'
import AIRiskEngine from './components/AIRiskEngine'
import ReportGenerator from './components/ReportGenerator'

export type { CaseRecord }
export type ModuleId =
  | 'dashboard' | 'cases' | 'ingestion' | 'triage'
  | 'memory' | 'ioc' | 'timeline' | 'search'
  | 'hex' | 'ai' | 'report'

export interface SharedProps {
  selectedCase: CaseRecord | null
  setSelectedCase: (c: CaseRecord | null) => void
  cases: CaseRecord[]
  setCases: (c: CaseRecord[]) => void
  loadCases: () => Promise<void>
  notify: (msg: string, type?: string) => void
  setModule: (m: ModuleId) => void
}

const NAV: Array<{ id: ModuleId; label: string; icon: string }> = [
  { id: 'dashboard',  label: 'Dashboard',         icon: '📊' },
  { id: 'cases',      label: 'Cases',              icon: '🗂️' },
  { id: 'ingestion',  label: 'Evidence Ingestion', icon: '📥' },
  { id: 'triage',     label: 'Deep Triage',        icon: '🔬' },
  { id: 'memory',     label: 'Memory Analysis',    icon: '🧠' },
  { id: 'ioc',        label: 'PCAP & IOC',         icon: '🌐' },
  { id: 'timeline',   label: 'Timeline',           icon: '📋' },
  { id: 'search',     label: 'Full-Text Search',   icon: '🔍' },
  { id: 'hex',        label: 'Hex Viewer',         icon: '👁️' },
  { id: 'ai',         label: 'AI Risk Engine',     icon: '⚡' },
  { id: 'report',     label: 'Report Generator',   icon: '📄' },
]

export default function App() {
  const [module, setModule] = useState<ModuleId>('dashboard')
  const [selectedCase, setSelectedCase] = useState<CaseRecord | null>(null)
  const [cases, setCases] = useState<CaseRecord[]>([])
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null)
  const [notification, setNotification] = useState<{ msg: string; type: string } | null>(null)

  const notify = useCallback((msg: string, type = 'info') => {
    setNotification({ msg, type })
    setTimeout(() => setNotification(null), 4000)
  }, [])

  const loadCases = useCallback(async () => {
    try {
      const data = await api.listCases()
      setCases(data)
      // Auto-select most recent case if none active
      if (!selectedCase && data.length > 0) {
        setSelectedCase(data[data.length - 1])
      }
    } catch {
      // backend offline
    }
  }, [selectedCase])

  useEffect(() => {
    api.health()
      .then(() => setBackendOnline(true))
      .catch(() => setBackendOnline(false))
    loadCases()
  }, [])

  const props: SharedProps = {
    selectedCase, setSelectedCase,
    cases, setCases,
    loadCases, notify, setModule,
  }

  return (
    <div style={{
      display: 'flex', height: '100vh',
      background: '#060f18',
      fontFamily: "'Inter','Segoe UI',sans-serif",
      color: '#e5e5ea', overflow: 'hidden',
    }}>

      {/* Toast notification */}
      {notification && (
        <div style={{
          position: 'fixed', top: 14, right: 14, zIndex: 9999,
          background: notification.type === 'success' ? '#30d158'
            : notification.type === 'error' ? '#ff2d55' : '#0a84ff',
          color: '#fff', padding: '11px 18px', borderRadius: 8,
          fontSize: 12, fontWeight: 600,
          boxShadow: '0 4px 20px rgba(0,0,0,0.5)', maxWidth: 420,
        }}>
          {notification.type === 'success' ? '✓ ' : notification.type === 'error' ? '✕ ' : 'ℹ '}
          {notification.msg}
        </div>
      )}

      {/* ── Sidebar ────────────────────────────────────────────── */}
      <div style={{
        width: 222, background: '#080e18',
        borderRight: '1px solid #1e2d3d',
        display: 'flex', flexDirection: 'column', flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '16px 16px 12px', borderBottom: '1px solid #1e2d3d' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
            <span style={{ fontSize: 20 }}>🛡</span>
            <span style={{ color: '#e5e5ea', fontWeight: 800, fontSize: 15 }}>FCTT</span>
          </div>
          <div style={{ color: '#636366', fontSize: 9, letterSpacing: 1.5 }}>FORENSIC CYBER TRIAGE TOOL</div>
          <div style={{ color: '#636366', fontSize: 9 }}>v1.0.0 · SOC Edition</div>
        </div>

        {/* Active case panel */}
        <div style={{ padding: '8px 16px 10px', borderBottom: '1px solid #1e2d3d' }}>
          <div style={{ color: '#636366', fontSize: 9, letterSpacing: 1, marginBottom: 4 }}>ACTIVE CASE</div>
          {selectedCase ? (
            <>
              <div style={{ color: '#0a84ff', fontSize: 10, fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {selectedCase.case_id}
              </div>
              <div style={{ color: '#8e8e93', fontSize: 11, marginTop: 2 }}>
                {selectedCase.case_name.slice(0, 26)}{selectedCase.case_name.length > 26 ? '…' : ''}
              </div>
              <div style={{ color: '#636366', fontSize: 10, marginTop: 2 }}>
                #{selectedCase.case_number}
              </div>
            </>
          ) : (
            <div style={{ color: '#636366', fontSize: 11 }}>
              No case selected —{' '}
              <span style={{ color: '#0a84ff', cursor: 'pointer' }} onClick={() => setModule('cases')}>
                create one
              </span>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
          {NAV.map(({ id, label, icon }) => (
            <div
              key={id}
              onClick={() => setModule(id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 9,
                padding: '8px 16px', cursor: 'pointer', fontSize: 12,
                fontWeight: module === id ? 700 : 400,
                color: module === id ? '#0a84ff' : '#8e8e93',
                background: module === id ? '#0a84ff11' : 'transparent',
                borderLeft: `2px solid ${module === id ? '#0a84ff' : 'transparent'}`,
              }}
            >
              <span style={{ fontSize: 13 }}>{icon}</span>
              <span>{label}</span>
            </div>
          ))}
        </nav>

        {/* Status footer */}
        <div style={{ padding: 10, borderTop: '1px solid #1e2d3d' }}>
          <div style={{
            background: '#060f18', borderRadius: 6,
            padding: 8, fontSize: 9, color: '#636366', lineHeight: 2,
          }}>
            <div>🔒 Evidence: Read-Only Mount</div>
            <div>🗄 {cases.length} case{cases.length !== 1 ? 's' : ''} loaded</div>
            <div style={{
              color: backendOnline === null ? '#636366'
                : backendOnline ? '#30d158' : '#ff2d55',
            }}>
              {backendOnline === null ? '⏳ Checking backend...'
                : backendOnline ? '● Backend online (port 8765)'
                : '✕ Backend offline'}
            </div>
          </div>
        </div>
      </div>

      {/* ── Main ───────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Topbar */}
        <div style={{
          background: '#080e18', borderBottom: '1px solid #1e2d3d',
          padding: '10px 24px', display: 'flex',
          alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 13, color: '#8e8e93' }}>
            {NAV.find(n => n.id === module)?.icon}{' '}
            {NAV.find(n => n.id === module)?.label}
          </span>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            {backendOnline === false && (
              <div style={{
                background: '#ff2d5522', border: '1px solid #ff2d5544',
                borderRadius: 6, padding: '4px 12px', fontSize: 10, color: '#ff2d55',
              }}>
                ✕ Backend offline — run: <code>python main.py</code>
              </div>
            )}
            <div style={{
              background: '#0d1f2d', border: '1px solid #1e2d3d',
              borderRadius: 6, padding: '4px 12px', fontSize: 10, color: '#636366',
            }}>
              🕐 {new Date().toUTCString().slice(0, -4)} UTC
            </div>
            <span style={{
              width: 8, height: 8, borderRadius: '50%',
              background: backendOnline ? '#30d158' : '#ff2d55',
              boxShadow: `0 0 5px ${backendOnline ? '#30d158' : '#ff2d55'}`,
              display: 'inline-block',
            }} />
          </div>
        </div>

        {/* Page content */}
        <div style={{ flex: 1, overflow: 'auto', padding: 22 }}>
          {module === 'dashboard'  && <Dashboard       {...props} />}
          {module === 'cases'      && <CaseManager      {...props} />}
          {module === 'ingestion'  && <EvidenceIngestion {...props} />}
          {module === 'triage'     && <TriageEngine      {...props} />}
          {module === 'memory'     && <MemoryAnalysis    {...props} />}
          {module === 'ioc'        && <PCAPAnalyser      {...props} />}
          {module === 'timeline'   && <Timeline          {...props} />}
          {module === 'search'     && <FullTextSearch     {...props} />}
          {module === 'hex'        && <HexViewer          {...props} />}
          {module === 'ai'         && <AIRiskEngine       {...props} />}
          {module === 'report'     && <ReportGenerator    {...props} />}
        </div>
      </div>
    </div>
  )
}
