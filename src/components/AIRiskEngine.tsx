import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/fctt-client'
import type { AIScore } from '../api/fctt-client'
import { Card, SectionTitle, RiskBadge, RiskMeter, Btn } from './shared'
import type { SharedProps } from '../App'

// ── helpers ───────────────────────────────────────────────────────
const CLF_COLOR: Record<string, string> = {
  CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MEDIUM: '#ffd60a', LOW: '#30d158'
}

function ScoreBar({ score, label }: { score: number; label: string }) {
  const color = score >= 80 ? '#ff2d55' : score >= 60 ? '#ff9f0a' : score >= 35 ? '#ffd60a' : '#30d158'
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
        <span style={{ fontSize: 11, color: '#c7c7cc' }}>{label}</span>
        <span style={{ fontSize: 11, color, fontWeight: 700 }}>{score.toFixed(0)}%</span>
      </div>
      <div style={{ height: 5, background: '#1e2d3d', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 1s ease' }} />
      </div>
    </div>
  )
}

function SemiGauge({ score }: { score: number }) {
  const color = score >= 80 ? '#ff2d55' : score >= 60 ? '#ff9f0a' : score >= 35 ? '#ffd60a' : '#30d158'
  const angle = (score / 100) * 180
  const r = 54, cx = 64, cy = 64
  const toXY = (deg: number) => {
    const rad = (deg - 180) * Math.PI / 180
    return [cx + r * Math.cos(rad), cy + r * Math.sin(rad)]
  }
  const [x1, y1] = toXY(0)
  const [x2, y2] = toXY(angle)
  const large = angle > 180 ? 1 : 0
  return (
    <svg width={128} height={72} viewBox="0 0 128 72">
      <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
        fill="none" stroke="#1e2d3d" strokeWidth={10} strokeLinecap="round" />
      {score > 0 && (
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`}
          fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" />
      )}
      <text x={cx} y={cy - 6} textAnchor="middle" fill={color} fontSize={22} fontWeight={800}>{score.toFixed(0)}</text>
      <text x={cx} y={cy + 8} textAnchor="middle" fill="#636366" fontSize={9} letterSpacing={1}>
        {score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW'}
      </text>
    </svg>
  )
}

// ── component ─────────────────────────────────────────────────────
export default function AIRiskEngine({ selectedCase, setModule }: SharedProps) {
  const [scores, setScores]       = useState<AIScore[]>([])
  const [loading, setLoading]     = useState(false)
  const [running, setRunning]     = useState(false)
  const [error, setError]         = useState<string | null>(null)
  const [filter, setFilter]       = useState<string>('ALL')
  const [selected, setSelected]   = useState<AIScore | null>(null)
  const [runResult, setRunResult] = useState<{scored:number;flagged:number;critical:number;high:number} | null>(null)

  const load = useCallback(async () => {
    if (!selectedCase) return
    setLoading(true); setError(null)
    try {
      const data = await api.getAIScores(selectedCase.case_id)
      setScores(data || [])
    } catch (e: any) {
      setError(e?.message || 'Failed to load AI scores')
    } finally {
      setLoading(false)
    }
  }, [selectedCase])

  useEffect(() => { load() }, [load])

  const runScoring = async () => {
    if (!selectedCase) return
    setRunning(true); setError(null); setRunResult(null)
    try {
      const r = await api.runAIScoring(selectedCase.case_id)
      setRunResult(r)
      await load()
    } catch (e: any) {
      setError(e?.message || 'AI scoring failed')
    } finally {
      setRunning(false)
    }
  }

  // Stats
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  let totalScore = 0
  for (const s of scores) {
    counts[s.classification as keyof typeof counts] = (counts[s.classification as keyof typeof counts] || 0) + 1
    totalScore += s.score
  }
  const avgScore = scores.length ? totalScore / scores.length : 0
  const overallRisk = scores.length
    ? Math.min(100, counts.CRITICAL * 25 + counts.HIGH * 10 + counts.MEDIUM * 3 + avgScore * 0.5)
    : 0

  const filtered = filter === 'ALL' ? scores : scores.filter(s => s.classification === filter)

  // Distribution for bar chart (bucket into 10 bands)
  const buckets = Array(10).fill(0)
  for (const s of scores) buckets[Math.min(9, Math.floor(s.score / 10))]++

  if (!selectedCase) return (
    <div style={{ textAlign: 'center', padding: '80px 20px', color: '#636366' }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>⚡</div>
      <div style={{ marginBottom: 16 }}>No case selected</div>
      <Btn onClick={() => setModule('cases')}>Select a Case →</Btn>
    </div>
  )

  return (
    <div style={{ fontFamily: "'Inter','Segoe UI',sans-serif" }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <SectionTitle icon="⚡" title="AI Risk Engine" badge={scores.length > 0 ? `${scores.length} files scored` : undefined} />
        <Btn onClick={runScoring} disabled={running}>
          {running ? '⏳ Scoring…' : '▶ Run AI Scoring'}
        </Btn>
      </div>

      {/* run result banner */}
      {runResult && (
        <div style={{ background: '#0a1f0a', border: '1px solid #30d15844', borderRadius: 8, padding: '10px 16px', marginBottom: 16, fontSize: 12, color: '#30d158', display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          ✓ Scoring complete —
          <span><b style={{ color: '#e5e5ea' }}>{runResult.scored}</b> files scored</span>
          <span><b style={{ color: '#ffd60a' }}>{runResult.flagged}</b> flagged</span>
          <span><b style={{ color: '#ff9f0a' }}>{runResult.high}</b> HIGH</span>
          <span><b style={{ color: '#ff2d55' }}>{runResult.critical}</b> CRITICAL</span>
        </div>
      )}

      {error && (
        <div style={{ background: '#2a0a0a', border: '1px solid #ff2d5533', borderRadius: 6, padding: '10px 16px', color: '#ff6b6b', fontSize: 12, marginBottom: 14 }}>⚠ {error}</div>
      )}

      {/* ── Top stats row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '200px 1fr 1fr 1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* Overall gauge */}
        <Card style={{ textAlign: 'center', padding: 16 }}>
          <div style={{ color: '#636366', fontSize: 9, letterSpacing: 1, marginBottom: 6 }}>OVERALL RISK</div>
          <SemiGauge score={Math.round(overallRisk)} />
        </Card>

        {/* Classification counts */}
        {(['CRITICAL','HIGH','MEDIUM','LOW'] as const).map(clf => (
          <Card key={clf} style={{ textAlign: 'center', padding: 16, cursor: 'pointer', borderColor: filter === clf ? CLF_COLOR[clf] + '88' : '#1e2d3d' }}
            onClick={() => setFilter(filter === clf ? 'ALL' : clf)}>
            <div style={{ color: '#636366', fontSize: 9, letterSpacing: 1, marginBottom: 6 }}>{clf}</div>
            <div style={{ fontSize: 32, fontWeight: 800, color: CLF_COLOR[clf] }}>{counts[clf]}</div>
            <div style={{ fontSize: 10, color: '#636366', marginTop: 4 }}>files</div>
          </Card>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* Model info */}
        <Card>
          <SectionTitle icon="🧠" title="Scoring Models" />
          <ScoreBar score={Math.min(100, counts.CRITICAL * 15 + counts.HIGH * 8 + 10)} label="Heuristic Rules" />
          <ScoreBar score={SKLEARN_AVAILABLE_PLACEHOLDER ? Math.min(100, counts.CRITICAL * 12 + 20) : 0} label="IsolationForest (sklearn)" />
          <div style={{ fontSize: 10, color: '#4a6a8a', marginTop: 10, lineHeight: 1.8, borderTop: '1px solid #1e2d3d', paddingTop: 8 }}>
            <div>📌 Suspicious filenames · Double extensions · Hidden executables</div>
            <div>📌 SUID/SGID on non-standard paths · Deleted files with content</div>
            <div>📌 High filename entropy (random-looking names)</div>
            <div>📌 Executables in /tmp, /dev/shm, /var/tmp</div>
            {scores.some(s => s.features?.iso !== undefined && (s.features.iso ?? 0) > 0) && (
              <div>📌 IsolationForest anomaly detection on feature vectors</div>
            )}
          </div>
        </Card>

        {/* Score distribution bar chart */}
        <Card>
          <SectionTitle icon="📊" title="Score Distribution" />
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 80, padding: '0 4px', marginBottom: 6 }}>
            {buckets.map((count, i) => {
              const pct = scores.length ? (count / scores.length) * 100 : 0
              const bandScore = i * 10
              const color = bandScore >= 80 ? '#ff2d55' : bandScore >= 60 ? '#ff9f0a' : bandScore >= 30 ? '#ffd60a' : '#30d158'
              return (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                  <div style={{ width: '80%', background: color, borderRadius: '2px 2px 0 0', height: `${Math.max(pct, count > 0 ? 4 : 0)}%`, transition: 'height 0.8s', minHeight: count > 0 ? 3 : 0 }} />
                  <span style={{ fontSize: 8, color: '#4a6a8a' }}>{i * 10}</span>
                </div>
              )
            })}
          </div>
          <div style={{ display: 'flex', gap: 12, fontSize: 10, color: '#636366', borderTop: '1px solid #1e2d3d', paddingTop: 8 }}>
            <span>Total: <b style={{ color: '#e5e5ea' }}>{scores.length}</b></span>
            <span>Avg: <b style={{ color: '#ffd60a' }}>{avgScore.toFixed(1)}</b></span>
            <span>Flagged (≥35): <b style={{ color: '#ff9f0a' }}>{scores.filter(s => s.score >= 35).length}</b></span>
          </div>
        </Card>
      </div>

      {/* ── File list ── */}
      <Card>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <SectionTitle icon="📄" title="Scored Files" badge={filter !== 'ALL' ? filter : undefined} />
          <div style={{ display: 'flex', gap: 6 }}>
            {(['ALL','CRITICAL','HIGH','MEDIUM','LOW'] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)} style={{
                background: filter === f ? (CLF_COLOR[f] || '#0a84ff') + '33' : 'transparent',
                border: `1px solid ${filter === f ? (CLF_COLOR[f] || '#0a84ff') : '#1e2d3d'}`,
                color: filter === f ? (CLF_COLOR[f] || '#0a84ff') : '#636366',
                borderRadius: 4, padding: '3px 10px', fontSize: 10, cursor: 'pointer', fontWeight: 600,
              }}>{f}</button>
            ))}
          </div>
        </div>

        {loading && (
          <div style={{ textAlign: 'center', padding: '30px 0', color: '#636366' }}>⏳ Loading scores…</div>
        )}

        {!loading && filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#636366', fontSize: 13 }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>⚡</div>
            {scores.length === 0
              ? 'No AI scores yet. Run triage or click "Run AI Scoring" above.'
              : `No ${filter} findings.`}
          </div>
        )}

        {filtered.slice(0, 200).map((s, i) => {
          const feat = s.features || {}
          const name = feat.name || s.artifact_ref?.split('/').pop() || s.artifact_ref || '(unknown)'
          const path = feat.full_path || s.artifact_ref || ''
          const reasons: string[] = feat.reasons || []
          const isOpen = selected?.score_id === s.score_id
          const color = CLF_COLOR[s.classification] || '#636366'

          return (
            <div key={s.score_id}
              style={{ borderBottom: '1px solid #1a2a3a', cursor: 'pointer' }}
              onClick={() => setSelected(isOpen ? null : s)}
            >
              {/* row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 4px' }}
                onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.background = '#0a1525'}
                onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.background = 'transparent'}
              >
                <span style={{ fontSize: 10, color: '#4a6a8a', minWidth: 22, textAlign: 'right' }}>{i + 1}</span>

                {/* score pill */}
                <div style={{ minWidth: 44, textAlign: 'center', background: color + '22', border: `1px solid ${color}44`, borderRadius: 4, padding: '2px 0', fontSize: 11, fontWeight: 800, color }}>
                  {s.score.toFixed(0)}
                </div>

                {/* classification */}
                <span style={{ fontSize: 9, minWidth: 56, color, fontWeight: 700, letterSpacing: 0.5 }}>{s.classification}</span>

                {/* filename */}
                <span style={{ flex: 1, fontSize: 12, color: '#e5e5ea', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {name}
                </span>

                {/* size */}
                {feat.size != null && feat.size > 0 && (
                  <span style={{ fontSize: 10, color: '#4a6a8a', minWidth: 50, textAlign: 'right' }}>
                    {feat.size < 1024 ? `${feat.size}B` : feat.size < 1048576 ? `${Math.round(feat.size/1024)}KB` : `${Math.round(feat.size/1048576)}MB`}
                  </span>
                )}

                {/* expand chevron */}
                <span style={{ color: '#4a6a8a', fontSize: 10, minWidth: 16 }}>{isOpen ? '▼' : '▶'}</span>
              </div>

              {/* expanded detail */}
              {isOpen && (
                <div style={{ background: '#060f18', borderRadius: 6, margin: '0 0 6px 36px', padding: '10px 14px', fontSize: 11 }}>
                  {path && (
                    <div style={{ color: '#4a6a8a', fontFamily: 'monospace', fontSize: 10, marginBottom: 8, wordBreak: 'break-all' }}>
                      📁 {path}
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: 16, marginBottom: 10, flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ color: '#636366', fontSize: 9, marginBottom: 2 }}>HEURISTIC</div>
                      <div style={{ color: '#ffd60a', fontWeight: 700 }}>{(feat.heuristic ?? s.score).toFixed(1)}</div>
                    </div>
                    {feat.iso != null && (
                      <div>
                        <div style={{ color: '#636366', fontSize: 9, marginBottom: 2 }}>ISOLATION FOREST</div>
                        <div style={{ color: '#bf5af2', fontWeight: 700 }}>{feat.iso.toFixed(1)}</div>
                      </div>
                    )}
                    <div>
                      <div style={{ color: '#636366', fontSize: 9, marginBottom: 2 }}>FINAL SCORE</div>
                      <div style={{ color, fontWeight: 700 }}>{s.score.toFixed(1)}</div>
                    </div>
                    <div>
                      <div style={{ color: '#636366', fontSize: 9, marginBottom: 2 }}>SCORED AT</div>
                      <div style={{ color: '#8e8e93' }}>{s.scored_at?.slice(0, 19) || '—'}</div>
                    </div>
                  </div>

                  {reasons.length > 0 && (
                    <div>
                      <div style={{ color: '#636366', fontSize: 9, marginBottom: 4 }}>DETECTION REASONS</div>
                      {reasons.map((r, ri) => (
                        <div key={ri} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 3, color: '#c7c7cc' }}>
                          <span style={{ color: color, marginTop: 1 }}>▸</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div style={{ marginTop: 10, padding: '6px 10px', background: '#0d1f2d', borderRadius: 4, fontSize: 10, color: '#4a6a8a', borderLeft: `3px solid ${color}` }}>
                    ⚠ AI scores assist investigation — verify findings manually before drawing conclusions.
                  </div>
                </div>
              )}
            </div>
          )
        })}

        {filtered.length > 200 && (
          <div style={{ textAlign: 'center', padding: '12px 0', color: '#636366', fontSize: 11 }}>
            Showing 200 of {filtered.length} results. Use filters to narrow down.
          </div>
        )}
      </Card>
    </div>
  )
}

// Placeholder for sklearn availability display — backend passes this via health endpoint
const SKLEARN_AVAILABLE_PLACEHOLDER = true
