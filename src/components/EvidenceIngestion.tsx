import { useState, useRef, useEffect } from 'react'
import { api } from '../api/fctt-client'
import type { EvidenceRecord } from '../api/fctt-client'
import { Card, SectionTitle, Btn, ProgressBar } from './shared'
import type { SharedProps } from '../App'

export default function EvidenceIngestion({ selectedCase, setModule, notify }: SharedProps) {
  const [ingesting, setIngesting] = useState(false)
  const [done, setDone] = useState(false)
  const [progress, setProgress] = useState(0)
  const [phase, setPhase] = useState('')
  const [fileName, setFileName] = useState('')
  const [fileSize, setFileSize] = useState('')
  const [result, setResult] = useState<EvidenceRecord | null>(null)
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([])
  const [error, setError] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  // Load existing evidence for active case
  useEffect(() => {
    if (!selectedCase) return
    api.listEvidence(selectedCase.case_id).then(setEvidence).catch(() => {})
  }, [selectedCase, done])

  const handleFileSelect = (file: File) => {
    const allowed = ['.dd', '.img', '.raw', '.vmem', '.pcap', '.log', '.evtx']
    const ext = '.' + (file.name.split('.').pop()?.toLowerCase() || '')
    if (!allowed.includes(ext)) {
      setError(`Unsupported file type: ${ext}. Allowed: ${allowed.join(', ')}`)
      return
    }
    setError('')
    setSelectedFile(file)
    setFileName(file.name)
    setFileSize((file.size / (1024 * 1024)).toFixed(2) + ' MB')
    setDone(false)
    setResult(null)
  }

  const startIngest = async () => {
    if (!selectedFile) { setError('Please select an evidence file first.'); return }
    if (!selectedCase) { setError('No case selected. Go to Cases and select or create one.'); return }

    setIngesting(true); setDone(false); setError(''); setProgress(0)

    const phases = [
      'Mounting evidence (read-only)...',
      'Uploading to backend...',
      'Computing MD5 hash...',
      'Computing SHA-256 hash...',
      'Verifying forensic integrity...',
      'Logging chain of custody...',
    ]
    let idx = 0
    const iv = setInterval(() => {
      idx = Math.min(idx + 1, phases.length - 1)
      setPhase(phases[idx])
      setProgress(Math.min((idx / phases.length) * 90, 90))
    }, 700)

    setPhase(phases[0])

    try {
      const data = await api.ingestEvidence(selectedCase.case_id, selectedFile, 'analyst')
      clearInterval(iv)
      setResult(data)
      setProgress(100)
      setPhase('Complete ✓')
      setDone(true)
      setIngesting(false)
      notify(`Evidence ingested: ${selectedFile.name}. Hashes verified. COC logged.`, 'success')
    } catch (err: any) {
      clearInterval(iv)
      setIngesting(false)
      setProgress(0)
      setPhase('')
      if (err.message?.includes('fetch') || err.message?.includes('Failed to fetch')) {
        setError('Cannot reach backend.\nMake sure Python server is running:\n  cd backend && python main.py')
      } else {
        setError(err.message || 'Ingestion failed.')
      }
    }
  }

  // Guard: no case selected
  if (!selectedCase) {
    return (
      <div style={{ textAlign: 'center', padding: 60 }}>
        <div style={{ fontSize: 36, marginBottom: 12 }}>📥</div>
        <div style={{ color: '#e5e5ea', fontWeight: 700, fontSize: 15, marginBottom: 8 }}>
          No Case Selected
        </div>
        <div style={{ color: '#636366', fontSize: 13, marginBottom: 20 }}>
          You need an active case before ingesting evidence.
        </div>
        <Btn onClick={() => setModule('cases')}>Go to Cases →</Btn>
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ fontWeight: 700, fontSize: 17, marginBottom: 4 }}>Evidence Ingestion</h2>
      <div style={{ color: '#636366', fontSize: 12, marginBottom: 18 }}>
        Case: <span style={{ color: '#0a84ff', fontFamily: 'monospace' }}>{selectedCase.case_id}</span>
        {' — '}{selectedCase.case_name}
      </div>

      <div style={{ background: '#0a84ff11', border: '1px solid #0a84ff33', borderRadius: 6, padding: '9px 14px', marginBottom: 16, fontSize: 12, color: '#8e8e93' }}>
        ℹ Backend must be running at{' '}
        <code style={{ color: '#0a84ff' }}>http://127.0.0.1:8765</code> —
        run: <code style={{ background: '#0d1f2d', padding: '1px 6px', borderRadius: 3 }}>cd backend && python main.py</code>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>

        {/* Upload panel */}
        <Card>
          <SectionTitle icon="🔒" title="Submit Evidence" />

          <div
            style={{ border: `2px dashed ${selectedFile ? '#30d158' : '#1e2d3d'}`, borderRadius: 8, padding: 28, textAlign: 'center', marginBottom: 14, cursor: 'pointer', background: selectedFile ? '#30d15808' : 'transparent' }}
            onClick={() => fileRef.current?.click()}
            onDragOver={e => e.preventDefault()}
            onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files[0]; if (f) handleFileSelect(f) }}
          >
            <div style={{ fontSize: 28, marginBottom: 6 }}>{selectedFile ? '✅' : '📁'}</div>
            <div style={{ color: selectedFile ? '#30d158' : '#636366', fontSize: 12, fontWeight: selectedFile ? 600 : 400 }}>
              {fileName || 'Drop evidence file or click to browse'}
            </div>
            {fileSize && <div style={{ color: '#8e8e93', fontSize: 11, marginTop: 3 }}>Size: {fileSize}</div>}
            <div style={{ color: '#636366', fontSize: 10, marginTop: 4 }}>
              .dd · .img · .raw · .vmem · .pcap · .log · .evtx
            </div>
            <input
              ref={fileRef} type="file"
              accept=".dd,.img,.raw,.vmem,.pcap,.log,.evtx"
              style={{ display: 'none' }}
              onChange={e => { if (e.target.files?.[0]) handleFileSelect(e.target.files[0]) }}
            />
          </div>

          {[
            ['Target Case', selectedCase.case_id],
            ['Case Name', selectedCase.case_name],
            ['Mount Mode', 'READ-ONLY (enforced)'],
            ['Hash Algorithms', 'MD5 · SHA-256'],
            ['Chain of Custody', 'Auto-logged, append-only'],
          ].map(([k, v]) => (
            <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: '1px solid #0d1f2d', fontSize: 11 }}>
              <span style={{ color: '#636366' }}>{k}</span>
              <span style={{ color: k === 'Target Case' ? '#0a84ff' : '#c7c7cc', fontFamily: k === 'Target Case' ? 'monospace' : 'inherit' }}>{v}</span>
            </div>
          ))}

          {error && (
            <div style={{ background: '#ff2d5511', border: '1px solid #ff2d5544', borderRadius: 6, padding: 10, marginTop: 12 }}>
              <div style={{ color: '#ff2d55', fontSize: 11, whiteSpace: 'pre-line' }}>⚠ {error}</div>
            </div>
          )}

          <Btn style={{ width: '100%', marginTop: 14 }} onClick={startIngest} disabled={ingesting || !selectedFile}>
            {ingesting ? '⏳ Ingesting...' : done ? '✓ Ingest Another File' : '🔒 Ingest Evidence'}
          </Btn>
        </Card>

        {/* Result panel */}
        <Card>
          <SectionTitle icon="✅" title="Integrity Verification" />

          {ingesting && (
            <div>
              <div style={{ color: '#0a84ff', fontSize: 12, marginBottom: 8 }}>{phase}</div>
              <ProgressBar progress={progress} height={8} />
              <div style={{ color: '#636366', fontSize: 11, marginTop: 6 }}>{Math.round(progress)}%</div>
            </div>
          )}

          {done && result && (
            <div>
              {[
                ['Evidence ID', result.evidence_id],
                ['Filename', result.filename],
                ['File Size', `${(result.file_size / (1024 * 1024)).toFixed(2)} MB`],
                ['Evidence Type', result.evidence_type],
                ['MD5 Hash', result.md5],
                ['SHA-256 Hash', result.sha256],
                ['Mount Mode', result.mount_mode],
                ['Acquired At', result.acquisition_ts?.slice(0, 19)],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '7px 10px', background: '#060f18', borderRadius: 6, marginBottom: 5 }}>
                  <span style={{ color: '#30d158', fontSize: 14, flexShrink: 0 }}>✓</span>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ color: '#636366', fontSize: 9 }}>{k}</div>
                    <div style={{ color: '#c7c7cc', fontSize: 11, fontFamily: 'monospace', wordBreak: 'break-all' }}>{v}</div>
                  </div>
                </div>
              ))}
              <div style={{ background: '#30d15811', border: '1px solid #30d15844', borderRadius: 6, padding: 10, marginTop: 8 }}>
                <span style={{ color: '#30d158', fontSize: 12 }}>
                  ✓ Linked to <strong>{selectedCase.case_id}</strong>. Chain of custody logged.
                </span>
              </div>
              <Btn style={{ width: '100%', marginTop: 10 }} onClick={() => setModule('triage')}>
                ▶ Run Triage on This Evidence →
              </Btn>
            </div>
          )}

          {!ingesting && !done && (
            <div style={{ color: '#636366', fontSize: 12, textAlign: 'center', padding: 40 }}>
              Select an evidence file and click Ingest to begin.
            </div>
          )}
        </Card>
      </div>

      {/* Existing evidence table */}
      {evidence.length > 0 && (
        <Card style={{ marginTop: 16 }}>
          <SectionTitle icon="📦" title="Evidence Already in This Case" badge={evidence.length} />
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['Filename', 'Type', 'Size', 'SHA-256', 'Acquired At'].map(h => (
                  <th key={h} style={{ color: '#636366', padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #1e2d3d', fontWeight: 600, fontSize: 10 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {evidence.map(ev => (
                <tr key={ev.evidence_id}>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #0d1f2d', color: '#e5e5ea', fontSize: 12, fontWeight: 600 }}>{ev.filename}</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #0d1f2d', fontSize: 11 }}>
                    <span style={{ background: '#0a84ff22', color: '#0a84ff', border: '1px solid #0a84ff44', padding: '1px 6px', borderRadius: 3, fontSize: 10 }}>{ev.evidence_type}</span>
                  </td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #0d1f2d', color: '#8e8e93', fontSize: 11 }}>{(ev.file_size / (1024 * 1024)).toFixed(2)} MB</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #0d1f2d', color: '#30d158', fontSize: 10, fontFamily: 'monospace' }}>{ev.sha256?.slice(0, 20)}...</td>
                  <td style={{ padding: '8px 12px', borderBottom: '1px solid #0d1f2d', color: '#636366', fontSize: 10 }}>{ev.acquisition_ts?.slice(0, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  )
}
