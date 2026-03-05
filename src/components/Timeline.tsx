import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/fctt-client'
import type { TimelineEvent } from '../api/fctt-client'
import { Card, SectionTitle, RiskBadge, Tag, Btn } from './shared'
import type { SharedProps } from '../App'

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff2d55', HIGH: '#ff9f0a', MEDIUM: '#ffd60a', LOW: '#30d158'
}
const SRC_COLOR: Record<string, string> = {
  PCAP: '#0a84ff', Disk: '#30d158', Memory: '#bf5af2',
  IOC: '#ff2d55', YARA: '#ff9f0a', Log: '#636366',
}

function riskLabel(score: number) {
  return score >= 90 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'
}
function riskColor(score: number) {
  return score >= 90 ? '#ff2d55' : score >= 70 ? '#ff9f0a' : score >= 40 ? '#ffd60a' : '#30d158'
}
function fmtTs(ts: string) {
  if (!ts) return '—'
  // unix float timestamp
  const n = parseFloat(ts)
  if (!isNaN(n) && n > 1000000000) {
    return new Date(n * 1000).toISOString().replace('T',' ').slice(0,19)
  }
  return ts.slice(0,19).replace('T',' ')
}

export default function Timeline({ selectedCase, setModule }: SharedProps) {
  const [events, setEvents]       = useState<TimelineEvent[]>([])
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState<string | null>(null)
  const [srcFilter, setSrcFilter] = useState('ALL')
  const [sevFilter, setSevFilter] = useState('ALL')
  const [search, setSearch]       = useState('')
  const [limit, setLimit]         = useState(2000)

  const load = useCallback(async () => {
    if (!selectedCase) return
    setLoading(true); setError(null)
    try {
      const data = await api.getTimeline(selectedCase.case_id, limit)
      setEvents(data || [])
    } catch (e: any) {
      setError(e?.message || 'Failed to load timeline')
    } finally { setLoading(false) }
  }, [selectedCase, limit])

  useEffect(() => { load() }, [load])

  // Sources and severity counts for filter chips
  const sources = ['ALL', ...Array.from(new Set(events.map(e => e.source).filter(Boolean)))]
  const sevCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const e of events) {
    const l = riskLabel(e.risk_score) as keyof typeof sevCounts
    sevCounts[l] = (sevCounts[l] || 0) + 1
  }

  const filtered = events.filter(e => {
    if (srcFilter !== 'ALL' && e.source !== srcFilter) return false
    if (sevFilter !== 'ALL' && riskLabel(e.risk_score) !== sevFilter) return false
    if (search && !e.description?.toLowerCase().includes(search.toLowerCase()) &&
        !e.event_type?.toLowerCase().includes(search.toLowerCase())) return false
    return true
  })

  if (!selectedCase) return (
    <div style={{ textAlign: 'center', padding: '80px 20px', color: '#636366' }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>📋</div>
      <div style={{ marginBottom: 16 }}>No case selected</div>
      <Btn onClick={() => setModule('cases')}>Select a Case →</Btn>
    </div>
  )

  return (
    <div style={{ fontFamily: "'Inter','Segoe UI',sans-serif" }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <SectionTitle icon="📋" title="Forensic Timeline"
          badge={filtered.length !== events.length ? `${filtered.length} / ${events.length}` : `${events.length} events`} />
        <div style={{ display: 'flex', gap: 8 }}>
          <Btn onClick={load} disabled={loading} color="#1e2d3d">↺ Refresh</Btn>
        </div>
      </div>

      {error && (
        <div style={{ background: '#2a0a0a', border: '1px solid #ff2d5533', borderRadius: 6,
          padding: '10px 16px', color: '#ff6b6b', fontSize: 12, marginBottom: 14 }}>
          ⚠ {error}
        </div>
      )}

      {/* Stats row */}
      {events.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 10, marginBottom: 14 }}>
          {([
            ['📋', 'Total',    events.length,          '#0a84ff'],
            ['🔴', 'Critical', sevCounts.CRITICAL,      '#ff2d55'],
            ['🟠', 'High',     sevCounts.HIGH,          '#ff9f0a'],
            ['🟡', 'Medium',   sevCounts.MEDIUM,        '#ffd60a'],
            ['🟢', 'Low',      sevCounts.LOW,           '#30d158'],
          ] as [string,string,number,string][]).map(([icon,label,val,color]) => (
            <Card key={label} style={{ textAlign:'center', padding:12,
              cursor: label !== 'Total' ? 'pointer' : 'default',
              borderColor: sevFilter === label.toUpperCase() ? color : '#1e2d3d' }}
              onClick={() => label !== 'Total' && setSevFilter(sevFilter === label.toUpperCase() ? 'ALL' : label.toUpperCase())}
            >
              <div style={{ fontSize:16, marginBottom:2 }}>{icon}</div>
              <div style={{ fontSize:18, fontWeight:800, color }}>{val}</div>
              <div style={{ fontSize:10, color:'#636366' }}>{label}</div>
            </Card>
          ))}
        </div>
      )}

      {/* Filters */}
      <div style={{ display:'flex', gap:8, marginBottom:14, flexWrap:'wrap', alignItems:'center' }}>
        {/* Source filter */}
        <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
          {sources.map(s => {
            const color = SRC_COLOR[s] || '#636366'
            return (
              <button key={s} onClick={() => setSrcFilter(s)} style={{
                background: srcFilter===s ? color+'22' : 'transparent',
                border: `1px solid ${srcFilter===s ? color : '#1e2d3d'}`,
                color: srcFilter===s ? color : '#636366',
                borderRadius: 99, padding:'3px 10px', fontSize:10, fontWeight:600, cursor:'pointer',
              }}>{s}</button>
            )
          })}
        </div>

        {/* Search */}
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search events…"
          style={{ marginLeft:'auto', background:'#0d1f2d', border:'1px solid #1e2d3d',
            color:'#e5e5ea', borderRadius:6, padding:'5px 10px', fontSize:11,
            outline:'none', width:200 }}
        />
      </div>

      {/* Timeline */}
      <Card>
        {loading ? (
          <div style={{ textAlign:'center', padding:'30px 0', color:'#636366' }}>⏳ Loading timeline…</div>
        ) : filtered.length === 0 ? (
          <div style={{ textAlign:'center', padding:'40px 20px', color:'#636366', fontSize:13 }}>
            <div style={{ fontSize:32, marginBottom:8 }}>📋</div>
            {events.length === 0
              ? 'No timeline events yet. Run triage or analyse a PCAP file to populate the timeline.'
              : 'No events match the current filters.'}
          </div>
        ) : (
          <div style={{ position:'relative', paddingLeft:22 }}>
            {/* Vertical line */}
            <div style={{ position:'absolute', left:4, top:0, bottom:0,
              width:2, background:'#1e2d3d' }} />

            {filtered.map((e, i) => {
              const color = riskColor(e.risk_score)
              const srcColor = SRC_COLOR[e.source] || '#636366'
              return (
                <div key={e.event_id || i} style={{ position:'relative', marginBottom:10 }}>
                  {/* Timeline dot */}
                  <div style={{
                    position:'absolute', left:-17, top:12,
                    width:10, height:10, borderRadius:'50%',
                    background:color, boxShadow:`0 0 6px ${color}88`,
                    border:`2px solid ${color}44`,
                  }} />

                  <div style={{ background:'#060f18', border:`1px solid #1e2d3d`,
                    borderLeft:`3px solid ${color}`, borderRadius:6, padding:'8px 12px',
                    transition:'border-color 0.2s' }}
                    onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.borderColor = color}
                    onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderLeftColor = color}
                  >
                    {/* Top row */}
                    <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:4, flexWrap:'wrap' }}>
                      <span style={{ color:'#4a6a8a', fontSize:10, fontFamily:'monospace', minWidth:120 }}>
                        {fmtTs(e.timestamp)}
                      </span>
                      {/* Event type tag */}
                      <span style={{ fontSize:9, padding:'1px 6px', borderRadius:3, fontWeight:700,
                        background:'#1e2d3d', color:'#8e8e93', textTransform:'uppercase',
                        letterSpacing:0.5 }}>
                        {e.event_type || 'EVENT'}
                      </span>
                      {/* Source tag */}
                      <span style={{ fontSize:9, padding:'1px 6px', borderRadius:3, fontWeight:700,
                        background:srcColor+'22', color:srcColor,
                        border:`1px solid ${srcColor}44` }}>
                        {e.source}
                      </span>
                      {/* Risk badge */}
                      <div style={{ marginLeft:'auto' }}>
                        <span style={{ fontSize:9, padding:'2px 7px', borderRadius:4, fontWeight:700,
                          background:color+'22', color, border:`1px solid ${color}44` }}>
                          {riskLabel(e.risk_score)}
                        </span>
                      </div>
                    </div>

                    {/* Description */}
                    <div style={{ fontSize:12, color:'#e5e5ea', lineHeight:1.5 }}>
                      {e.description}
                    </div>

                    {/* Related info */}
                    {(e.related_pid || e.related_file) && (
                      <div style={{ display:'flex', gap:10, marginTop:4, fontSize:10, color:'#636366' }}>
                        {e.related_pid  && <span>PID: <b style={{color:'#bf5af2'}}>{e.related_pid}</b></span>}
                        {e.related_file && (
                          <span style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', maxWidth:300 }}>
                            File: <b style={{color:'#30d158', fontFamily:'monospace'}}>{e.related_file.split(/[/\\]/).pop()}</b>
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}

            {/* Load more */}
            {events.length >= limit && (
              <div style={{ textAlign:'center', paddingTop:10 }}>
                <Btn onClick={() => setLimit(l => l + 500)} color="#1e2d3d">
                  Load more ({events.length} shown)
                </Btn>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
