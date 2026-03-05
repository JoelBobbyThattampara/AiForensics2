import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/fctt-client'
import type { PCAPSession, PCAPStats } from '../api/fctt-client'
import type { SharedProps } from '../App'

// ── helpers ──────────────────────────────────────────────────────────────────
function fmt(b: number) {
  if (b >= 1073741824) return (b/1073741824).toFixed(2)+' GB'
  if (b >= 1048576)    return (b/1048576).toFixed(2)+' MB'
  if (b >= 1024)       return (b/1024).toFixed(1)+' KB'
  return b+' B'
}
function riskColor(s: number) {
  return s>=90?'#ff2d55':s>=70?'#ff9f0a':s>=40?'#ffd60a':'#30d158'
}
function riskLabel(s: number) {
  return s>=90?'CRITICAL':s>=70?'HIGH':s>=40?'MEDIUM':'LOW'
}
function isPrivate(ip: string) {
  const p = ip.split('.').map(Number)
  if (p.length!==4) return false
  const n=(p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]
  return ((n&0xFFFF0000)===0xC0A80000)||((n&0xFFF00000)===0xAC100000)||
         ((n&0xFF000000)===0x0A000000)||((n&0xFF000000)===0x7F000000)
}

const PROTO_COLOR: Record<string,string> = {
  TCP:'#0a84ff',UDP:'#bf5af2',DNS:'#30d158',HTTP:'#ffd60a',
  HTTPS:'#ff9f0a',ICMP:'#636366',IPv6:'#5ac8fa',ICMPv6:'#636366',
}
const MITRE_COLORS: Record<string,string> = {
  'Initial Access':'#ff2d55','Execution':'#ff6b35','Persistence':'#ff9f0a',
  'Privilege Escalation':'#ffd60a','Defense Evasion':'#aeea00',
  'Credential Access':'#69f0ae','Discovery':'#40c4ff',
  'Lateral Movement':'#7c4dff','Collection':'#e040fb',
  'Command and Control':'#ff4081','Exfiltration':'#ff6d00','Impact':'#d50000',
}

// ── small UI components ───────────────────────────────────────────────────────
function Card({ children, style={} }: any) {
  return <div style={{background:'#060f18',border:'1px solid #1e2d3d',
    borderRadius:8,padding:16,...style}}>{children}</div>
}
function Chip({ label, color='#636366', active=false, onClick=()=>{} }: any) {
  return (
    <button onClick={onClick} style={{
      background:active?color+'22':'transparent',
      border:`1px solid ${active?color:'#1e2d3d'}`,
      color:active?color:'#636366', borderRadius:99,
      padding:'3px 12px', fontSize:10, fontWeight:600,
      cursor:'pointer', transition:'all 0.15s',
    }}>{label}</button>
  )
}
function Btn({ children, onClick, disabled=false, color='#0a84ff' }: any) {
  return (
    <button onClick={onClick} disabled={disabled} style={{
      background:disabled?'#1e2d3d':color+'22',
      border:`1px solid ${disabled?'#1e2d3d':color}`,
      color:disabled?'#636366':color, borderRadius:6,
      padding:'6px 14px', fontSize:11, fontWeight:600,
      cursor:disabled?'not-allowed':'pointer',
    }}>{children}</button>
  )
}
function StatCard({ icon, label, value, color='#e5e5ea', sub='' }: any) {
  return (
    <Card style={{textAlign:'center',padding:'12px 8px'}}>
      <div style={{fontSize:18,marginBottom:2}}>{icon}</div>
      <div style={{fontSize:20,fontWeight:800,color}}>{value}</div>
      <div style={{fontSize:9,color:'#636366',textTransform:'uppercase',letterSpacing:0.5}}>{label}</div>
      {sub && <div style={{fontSize:9,color:'#4a6a8a',marginTop:2}}>{sub}</div>}
    </Card>
  )
}
function RiskBadge({ score }: {score:number}) {
  const c=riskColor(score)
  return <span style={{background:c+'22',color:c,border:`1px solid ${c}44`,
    borderRadius:4,padding:'2px 7px',fontSize:9,fontWeight:700}}>{riskLabel(score)}</span>
}
function SevBadge({ sev }: {sev:string}) {
  const c=sev==='CRITICAL'?'#ff2d55':sev==='HIGH'?'#ff9f0a':sev==='MEDIUM'?'#ffd60a':'#30d158'
  return <span style={{background:c+'22',color:c,border:`1px solid ${c}44`,
    borderRadius:4,padding:'2px 7px',fontSize:9,fontWeight:700}}>{sev}</span>
}
function MitreBadge({ technique, tactic }: {technique?:string, tactic?:string}) {
  if (!technique) return null
  const c = MITRE_COLORS[tactic||''] || '#636366'
  return (
    <a href={`https://attack.mitre.org/techniques/${technique.replace('.','/')}/`}
       target="_blank" rel="noreferrer" style={{
         background:c+'18',color:c,border:`1px solid ${c}44`,
         borderRadius:4,padding:'2px 7px',fontSize:9,fontWeight:700,
         textDecoration:'none',
       }}>{technique}</a>
  )
}

// ── main component ────────────────────────────────────────────────────────────
type Tab = 'findings'|'sessions'|'iocs'|'external'|'mitre'

export default function PCAPAnalyser({ selectedCase }: SharedProps) {
  const [tab, setTab]           = useState<Tab>('findings')
  const [sessions, setSessions] = useState<PCAPSession[]>([])
  const [iocs, setIocs]         = useState<any[]>([])
  const [stats, setStats]       = useState<PCAPStats|null>(null)
  const [result, setResult]     = useState<any>(null)
  const [loading, setLoading]   = useState(false)
  const [analysing, setAnalysing] = useState(false)
  const [error, setError]       = useState<string|null>(null)
  const [expanded, setExpanded] = useState<string|null>(null)
  const [minRisk, setMinRisk]   = useState(0)
  const [iocType, setIocType]   = useState('ALL')
  const [findingSev, setFindingSev] = useState('ALL')

  const load = useCallback(async () => {
    if (!selectedCase) return
    setLoading(true); setError(null)
    try {
      const [s,i,st] = await Promise.all([
        api.getPCAPSessions(selectedCase.case_id, minRisk),
        api.getIOCs(selectedCase.case_id),
        api.getPCAPStats(selectedCase.case_id),
      ])
      setSessions(s||[]); setIocs(i||[]); setStats(st)
    } catch(e:any) { setError(e?.message||'Load failed') }
    finally { setLoading(false) }
  }, [selectedCase, minRisk])

  useEffect(() => { load() }, [load])

  const runAnalysis = async () => {
    if (!selectedCase) return
    setAnalysing(true); setError(null); setResult(null)
    try {
      const r = await api.analysePCAP(selectedCase.case_id)
      setResult(r)
      await load()
    } catch(e:any) { setError(e?.message||'Analysis failed') }
    finally { setAnalysing(false) }
  }

  // ── computed ────────────────────────────────────────────────────────────────
  const extMap: Record<string,{sessions:number,ports:Set<number>,bytes:number,maxRisk:number}> = {}
  for (const s of sessions) {
    if (!isPrivate(s.dst_ip)) {
      if (!extMap[s.dst_ip]) extMap[s.dst_ip]={sessions:0,ports:new Set(),bytes:0,maxRisk:0}
      extMap[s.dst_ip].sessions++
      extMap[s.dst_ip].ports.add(s.dst_port)
      extMap[s.dst_ip].bytes+=s.byte_count
      extMap[s.dst_ip].maxRisk=Math.max(extMap[s.dst_ip].maxRisk,s.risk_score)
    }
  }
  const extList = Object.entries(extMap).sort((a,b)=>b[1].maxRisk-a[1].maxRisk||b[1].bytes-a[1].bytes)

  const allFindings: any[] = result?.all_findings || []
  const filteredFindings = findingSev==='ALL' ? allFindings
    : allFindings.filter((f:any) => f.severity===findingSev)

  const iocTypes = ['ALL',...Array.from(new Set(iocs.map((i:any)=>i.ioc_type)))]
  const filteredIocs = iocType==='ALL' ? iocs : iocs.filter((i:any)=>i.ioc_type===iocType)

  const mitreCoverage: Record<string,string[]> = result?.mitre_coverage || {}

  if (!selectedCase) return (
    <div style={{textAlign:'center',padding:'80px 20px',color:'#636366'}}>
      <div style={{fontSize:40,marginBottom:12}}>🌐</div>
      Select a case to use PCAP Analyser.
    </div>
  )

  return (
    <div style={{fontFamily:"'Inter','Segoe UI',sans-serif",color:'#e5e5ea'}}>

      {/* Header */}
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16,flexWrap:'wrap',gap:8}}>
        <div>
          <h2 style={{fontWeight:700,fontSize:17,margin:0}}>🌐 PCAP Analyser</h2>
          <div style={{fontSize:11,color:'#636366',marginTop:2}}>
            TrafficAnalyzer · AnomalyDetector · AttackDetector · IOCChecker · MITRE ATT&CK
          </div>
        </div>
        <div style={{display:'flex',gap:8}}>
          <Btn onClick={load} disabled={loading} color="#1e2d3d">↺ Refresh</Btn>
          <Btn onClick={runAnalysis} disabled={analysing} color="#30d158">
            {analysing ? '⏳ Analysing…' : '▶ Analyse PCAP'}
          </Btn>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{background:'#2a0a0a',border:'1px solid #ff2d5533',borderRadius:6,
          padding:'10px 16px',color:'#ff6b6b',fontSize:12,marginBottom:14}}>
          ⚠ {error}
        </div>
      )}

      {/* Result banner */}
      {result && (
        <div style={{background:'#0a1a0a',border:'1px solid #30d15844',borderRadius:8,
          padding:'10px 18px',marginBottom:14,fontSize:11,display:'flex',gap:16,flexWrap:'wrap',alignItems:'center'}}>
          <span style={{color:'#30d158',fontWeight:700}}>✓ Analysis complete</span>
          <span style={{color:'#8e8e93'}}>{(result.packets||0).toLocaleString()} packets</span>
          <span style={{color:'#8e8e93'}}>{fmt(result.bytes||0)}</span>
          <span style={{color:'#8e8e93'}}>{result.sessions} sessions</span>
          <span style={{color:'#8e8e93'}}>{result.unique_ips} unique IPs</span>
          <span style={{color:'#ffd60a',fontWeight:600}}>{result.findings} findings</span>
          <span style={{color:'#0a84ff'}}>{result.iocs} IOCs</span>
          {result.severity?.CRITICAL>0 && <span style={{color:'#ff2d55',fontWeight:700}}>🔴 {result.severity.CRITICAL} CRITICAL</span>}
          {result.severity?.HIGH>0     && <span style={{color:'#ff9f0a',fontWeight:700}}>🟠 {result.severity.HIGH} HIGH</span>}
          <span style={{color:'#636366',fontSize:10}}>
            Traffic:{result.analyzers?.traffic?.findings} Anomaly:{result.analyzers?.anomaly?.findings} Attack:{result.analyzers?.attack?.findings}
          </span>
          {result.duration_secs && <span style={{color:'#636366',marginLeft:'auto'}}>⏱ {result.duration_secs}s</span>}
        </div>
      )}

      {/* Stats row */}
      {stats && (
        <div style={{display:'grid',gridTemplateColumns:'repeat(6,1fr)',gap:10,marginBottom:16}}>
          <StatCard icon="📦" label="Sessions" value={sessions.length} />
          <StatCard icon="📊" label="Data" value={fmt(stats.total_bytes||0)} color="#0a84ff" />
          <StatCard icon="🔴" label="Critical" value={stats.risk_counts?.CRITICAL||0} color="#ff2d55" />
          <StatCard icon="🟠" label="High" value={stats.risk_counts?.HIGH||0} color="#ff9f0a" />
          <StatCard icon="⚠️" label="IOC Matches" value={iocs.length} color="#ffd60a" />
          <StatCard icon="🔍" label="Ext. IPs" value={extList.length} color="#bf5af2"
            sub={`${result?.unique_ips||0} unique IPs total`} />
        </div>
      )}

      {/* Protocol bar + top talkers */}
      {stats && (
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16}}>
          <Card>
            <div style={{fontSize:11,color:'#636366',marginBottom:10,fontWeight:600}}>PROTOCOL DISTRIBUTION</div>
            {Object.entries(stats.protocols||{})
              .sort((a:any,b:any)=>b[1]-a[1]).slice(0,8).map(([p,c]:any) => {
                const total = Object.values(stats.protocols||{}).reduce((a:any,b:any)=>a+b,0) as number
                const pct   = total>0 ? c/total*100 : 0
                const col   = PROTO_COLOR[p]||'#636366'
                return (
                  <div key={p} style={{marginBottom:6}}>
                    <div style={{display:'flex',justifyContent:'space-between',fontSize:10,marginBottom:2}}>
                      <span style={{color:col,fontWeight:600}}>{p}</span>
                      <span style={{color:'#636366'}}>{pct.toFixed(1)}%</span>
                    </div>
                    <div style={{height:5,background:'#1e2d3d',borderRadius:3,overflow:'hidden'}}>
                      <div style={{height:'100%',width:`${pct}%`,background:col,borderRadius:3,transition:'width 0.5s'}}/>
                    </div>
                  </div>
                )
              })}
          </Card>
          <Card>
            <div style={{fontSize:11,color:'#636366',marginBottom:10,fontWeight:600}}>TOP TALKERS BY PACKETS</div>
            {(stats.top_talkers||[]).slice(0,7).map((t:any,i:number) => {
              const max=(stats.top_talkers?.[0]?.packets||1)
              return (
                <div key={t.ip} style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <span style={{color:'#636366',fontSize:9,minWidth:12}}>{i+1}</span>
                  <span style={{fontFamily:'monospace',fontSize:10,color:'#e5e5ea',minWidth:110}}>{t.ip}</span>
                  <div style={{flex:1,height:4,background:'#1e2d3d',borderRadius:3}}>
                    <div style={{height:'100%',width:`${t.packets/max*100}%`,
                      background:isPrivate(t.ip)?'#0a84ff':'#ff9f0a',borderRadius:3}}/>
                  </div>
                  <span style={{fontSize:9,color:'#636366',minWidth:40,textAlign:'right'}}>{t.packets.toLocaleString()}</span>
                </div>
              )
            })}
          </Card>
        </div>
      )}

      {/* Tabs */}
      <div style={{display:'flex',gap:4,marginBottom:14,borderBottom:'1px solid #1e2d3d',paddingBottom:8,flexWrap:'wrap'}}>
        {([
          ['findings', `🚨 Findings (${allFindings.length})`],
          ['sessions', `🔗 Sessions (${sessions.length})`],
          ['iocs',     `⚠️ IOCs (${iocs.length})`],
          ['external', `🌍 External IPs (${extList.length})`],
          ['mitre',    `🛡 MITRE ATT&CK`],
        ] as const).map(([t,label])=>(
          <button key={t} onClick={()=>setTab(t)} style={{
            background:tab===t?'#0a84ff22':'transparent',
            border:`1px solid ${tab===t?'#0a84ff':'#1e2d3d'}`,
            color:tab===t?'#0a84ff':'#636366',
            borderRadius:6,padding:'5px 12px',fontSize:11,fontWeight:600,cursor:'pointer',
          }}>{label}</button>
        ))}
      </div>

      {/* ══ FINDINGS ══════════════════════════════════════════════════════════ */}
      {tab==='findings' && (
        <div>
          {/* Severity filter chips */}
          <div style={{display:'flex',gap:6,marginBottom:12,flexWrap:'wrap'}}>
            {(['ALL','CRITICAL','HIGH','MEDIUM','LOW'] as const).map(sev=>{
              const c=sev==='CRITICAL'?'#ff2d55':sev==='HIGH'?'#ff9f0a':sev==='MEDIUM'?'#ffd60a':sev==='LOW'?'#30d158':'#0a84ff'
              const cnt=sev==='ALL'?allFindings.length:allFindings.filter((f:any)=>f.severity===sev).length
              return <Chip key={sev} label={`${sev} (${cnt})`} color={c} active={findingSev===sev} onClick={()=>setFindingSev(sev)}/>
            })}
          </div>
          {filteredFindings.length===0 ? (
            <Card style={{textAlign:'center',padding:'40px 20px',color:'#636366'}}>
              <div style={{fontSize:32,marginBottom:8}}>🚨</div>
              {allFindings.length===0
                ? 'Click ▶ Analyse PCAP to detect security findings.'
                : 'No findings match this severity filter.'}
            </Card>
          ) : (
            <div style={{display:'flex',flexDirection:'column',gap:8}}>
              {filteredFindings.map((f:any, i:number) => {
                const isExp = expanded===`f${i}`
                const c = f.severity==='CRITICAL'?'#ff2d55':f.severity==='HIGH'?'#ff9f0a':f.severity==='MEDIUM'?'#ffd60a':'#30d158'
                return (
                  <div key={i} style={{background:'#060f18',border:`1px solid #1e2d3d`,
                    borderLeft:`3px solid ${c}`,borderRadius:8,
                    cursor:'pointer',transition:'border-color 0.15s'}}
                    onClick={()=>setExpanded(isExp?null:`f${i}`)}>
                    <div style={{padding:'10px 14px'}}>
                      <div style={{display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
                        <SevBadge sev={f.severity}/>
                        <span style={{fontSize:12,fontWeight:600,color:'#e5e5ea',flex:1}}>{f.title}</span>
                        <span style={{fontSize:9,color:'#636366',background:'#1e2d3d',
                          padding:'2px 6px',borderRadius:3}}>{f.category}</span>
                        <MitreBadge technique={f.mitre_technique} tactic={f.mitre_tactic}/>
                        <span style={{color:'#636366',fontSize:12}}>{isExp?'▲':'▼'}</span>
                      </div>
                      <div style={{fontSize:11,color:'#8e8e93',marginTop:5,lineHeight:1.5}}>{f.description}</div>
                    </div>
                    {isExp && (
                      <div style={{borderTop:'1px solid #1e2d3d',padding:'10px 14px',
                        display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
                        {/* Evidence */}
                        {f.evidence?.length>0 && (
                          <div>
                            <div style={{fontSize:9,color:'#636366',fontWeight:700,marginBottom:6,letterSpacing:1}}>EVIDENCE</div>
                            {f.evidence.map((e:string,ei:number)=>(
                              <div key={ei} style={{fontSize:10,color:'#8e8e93',
                                background:'#0d1f2d',borderRadius:4,padding:'3px 8px',
                                marginBottom:3,fontFamily:'monospace'}}>• {e}</div>
                            ))}
                          </div>
                        )}
                        {/* Recommendations */}
                        {f.recommendations?.length>0 && (
                          <div>
                            <div style={{fontSize:9,color:'#636366',fontWeight:700,marginBottom:6,letterSpacing:1}}>RECOMMENDATIONS</div>
                            {f.recommendations.map((r:string,ri:number)=>(
                              <div key={ri} style={{fontSize:10,color:'#30d158',
                                background:'#0a1a0a',borderRadius:4,padding:'3px 8px',
                                marginBottom:3}}>→ {r}</div>
                            ))}
                          </div>
                        )}
                        {/* Source/dest */}
                        {(f.src_ip||f.dst_ip||f.mitre_technique) && (
                          <div style={{gridColumn:'1/-1',display:'flex',gap:12,flexWrap:'wrap',
                            paddingTop:8,borderTop:'1px solid #1e2d3d',fontSize:10,color:'#636366'}}>
                            {f.src_ip  && <span>SRC: <b style={{color:'#e5e5ea',fontFamily:'monospace'}}>{f.src_ip}</b></span>}
                            {f.dst_ip  && <span>DST: <b style={{color:'#e5e5ea',fontFamily:'monospace'}}>{f.dst_ip}</b></span>}
                            {f.mitre_technique && (
                              <span>MITRE: <b style={{color:'#bf5af2'}}>{f.mitre_technique}</b>
                                {f.mitre_tactic && <> — <span style={{color:MITRE_COLORS[f.mitre_tactic]||'#636366'}}>{f.mitre_tactic}</span></>}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}

      {/* ══ SESSIONS ══════════════════════════════════════════════════════════ */}
      {tab==='sessions' && (
        <div>
          <div style={{display:'flex',gap:6,marginBottom:12,flexWrap:'wrap',alignItems:'center'}}>
            <span style={{fontSize:10,color:'#636366'}}>Min risk:</span>
            {[['All',0],['Med+',35],['High+',60],['Crit',80]].map(([l,v])=>(
              <Chip key={l} label={l as string} color="#0a84ff" active={minRisk===v} onClick={()=>setMinRisk(v as number)}/>
            ))}
          </div>
          <Card style={{padding:0,overflow:'hidden'}}>
            <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
              <thead>
                <tr style={{background:'#0d1f2d'}}>
                  {['Risk','Source','Destination','Protocol','Packets','Data','Tags'].map(h=>(
                    <th key={h} style={{padding:'8px 10px',textAlign:'left',fontSize:9,
                      color:'#636366',fontWeight:700,letterSpacing:0.5,textTransform:'uppercase',
                      borderBottom:'1px solid #1e2d3d'}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sessions.map(s=>{
                  const isExp=expanded===s.session_id
                  return [
                    <tr key={s.session_id}
                      onClick={()=>setExpanded(isExp?null:s.session_id)}
                      style={{cursor:'pointer',borderBottom:'1px solid #1e2d3d',
                        background:isExp?'#0d1f2d':'transparent'}}>
                      <td style={{padding:'7px 10px'}}><RiskBadge score={s.risk_score}/></td>
                      <td style={{padding:'7px 10px',fontFamily:'monospace',fontSize:10}}>{s.src_ip}</td>
                      <td style={{padding:'7px 10px',fontFamily:'monospace',fontSize:10,
                        color:isPrivate(s.dst_ip)?'#e5e5ea':'#ff9f0a'}}>
                        {s.dst_ip}:{s.dst_port}
                      </td>
                      <td style={{padding:'7px 10px'}}>
                        <span style={{color:PROTO_COLOR[s.protocol]||'#636366',
                          background:(PROTO_COLOR[s.protocol]||'#636366')+'18',
                          padding:'1px 6px',borderRadius:3,fontSize:9}}>{s.protocol}</span>
                      </td>
                      <td style={{padding:'7px 10px',color:'#8e8e93'}}>{s.packet_count?.toLocaleString()}</td>
                      <td style={{padding:'7px 10px',color:'#8e8e93'}}>{fmt(s.byte_count)}</td>
                      <td style={{padding:'7px 10px'}}>
                        <div style={{display:'flex',gap:3,flexWrap:'wrap'}}>
                          {(s.tags||'').split(',').filter(Boolean).map(t=>(
                            <span key={t} style={{background:'#1e2d3d',color:'#8e8e93',
                              borderRadius:3,padding:'1px 5px',fontSize:8}}>{t}</span>
                          ))}
                        </div>
                      </td>
                    </tr>,
                    isExp && (
                      <tr key={s.session_id+'_exp'}>
                        <td colSpan={7} style={{background:'#0a1525',padding:'10px 16px',
                          borderBottom:'1px solid #1e2d3d'}}>
                          <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:10,fontSize:10}}>
                            <div><span style={{color:'#636366'}}>First seen: </span><span style={{fontFamily:'monospace'}}>{s.first_seen}</span></div>
                            <div><span style={{color:'#636366'}}>Last seen: </span><span style={{fontFamily:'monospace'}}>{s.last_seen}</span></div>
                            <div><span style={{color:'#636366'}}>Flags: </span><span style={{color:'#0a84ff',fontFamily:'monospace'}}>{s.flags||'—'}</span></div>
                            <div><span style={{color:'#636366'}}>Risk score: </span><span style={{color:riskColor(s.risk_score)}}>{s.risk_score.toFixed(0)}</span></div>
                          </div>
                          {s.payload_preview && (
                            <div style={{marginTop:8,fontFamily:'monospace',fontSize:9,
                              color:'#4a6a8a',background:'#060f18',borderRadius:4,
                              padding:8,wordBreak:'break-all',maxHeight:80,overflow:'auto'}}>
                              {s.payload_preview}
                            </div>
                          )}
                        </td>
                      </tr>
                    )
                  ]
                })}
              </tbody>
            </table>
            {sessions.length===0 && (
              <div style={{textAlign:'center',padding:'30px',color:'#636366',fontSize:12}}>
                No sessions. Run ▶ Analyse PCAP first.
              </div>
            )}
          </Card>
        </div>
      )}

      {/* ══ IOCs ═══════════════════════════════════════════════════════════════ */}
      {tab==='iocs' && (
        <div>
          <div style={{display:'flex',gap:6,marginBottom:12,flexWrap:'wrap'}}>
            {iocTypes.map(t=>{
              const cnt=t==='ALL'?iocs.length:iocs.filter((i:any)=>i.ioc_type===t).length
              const c=t==='IP'?'#ff2d55':t==='DOMAIN'?'#ffd60a':t==='URL'?'#0a84ff':t==='HASH'?'#ff9f0a':'#636366'
              return <Chip key={t} label={`${t} (${cnt})`} color={c} active={iocType===t} onClick={()=>setIocType(t)}/>
            })}
          </div>
          <Card style={{padding:0,overflow:'hidden'}}>
            <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
              <thead>
                <tr style={{background:'#0d1f2d'}}>
                  {['Type','Value','Rule','Confidence'].map(h=>(
                    <th key={h} style={{padding:'8px 10px',textAlign:'left',fontSize:9,
                      color:'#636366',fontWeight:700,letterSpacing:0.5,
                      borderBottom:'1px solid #1e2d3d'}}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredIocs.map((ioc:any,i:number)=>{
                  const c=ioc.ioc_type==='IP'?'#ff2d55':ioc.ioc_type==='DOMAIN'?'#ffd60a':
                          ioc.ioc_type==='URL'?'#0a84ff':'#ff9f0a'
                  const conf=parseFloat(ioc.confidence||0)
                  return (
                    <tr key={i} style={{borderBottom:'1px solid #1e2d3d'}}>
                      <td style={{padding:'7px 10px'}}>
                        <span style={{background:c+'22',color:c,border:`1px solid ${c}44`,
                          borderRadius:4,padding:'2px 6px',fontSize:9,fontWeight:700}}>{ioc.ioc_type}</span>
                      </td>
                      <td style={{padding:'7px 10px',fontFamily:'monospace',fontSize:10,
                        color:'#e5e5ea',maxWidth:280,overflow:'hidden',textOverflow:'ellipsis',
                        whiteSpace:'nowrap'}} title={ioc.value}>{ioc.value?.slice(0,70)}</td>
                      <td style={{padding:'7px 10px',color:'#8e8e93',fontSize:10}}>{ioc.rule_name}</td>
                      <td style={{padding:'7px 10px',minWidth:100}}>
                        <div style={{display:'flex',alignItems:'center',gap:6}}>
                          <div style={{flex:1,height:4,background:'#1e2d3d',borderRadius:2}}>
                            <div style={{height:'100%',width:`${conf}%`,
                              background:conf>=75?'#ff2d55':conf>=50?'#ff9f0a':'#30d158',borderRadius:2}}/>
                          </div>
                          <span style={{fontSize:9,color:'#636366',minWidth:24}}>{conf.toFixed(0)}%</span>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {filteredIocs.length===0 && (
              <div style={{textAlign:'center',padding:'30px',color:'#636366',fontSize:12}}>
                No IOCs. Run ▶ Analyse PCAP first.
              </div>
            )}
          </Card>
        </div>
      )}

      {/* ══ EXTERNAL IPs ═══════════════════════════════════════════════════════ */}
      {tab==='external' && (
        <Card style={{padding:0,overflow:'hidden'}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
            <thead>
              <tr style={{background:'#0d1f2d'}}>
                {['IP Address','Sessions','Ports','Data','Max Risk'].map(h=>(
                  <th key={h} style={{padding:'8px 10px',textAlign:'left',fontSize:9,
                    color:'#636366',fontWeight:700,letterSpacing:0.5,
                    borderBottom:'1px solid #1e2d3d'}}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {extList.map(([ip,d])=>(
                <tr key={ip} style={{borderBottom:'1px solid #1e2d3d'}}>
                  <td style={{padding:'7px 10px',fontFamily:'monospace',color:'#ff9f0a'}}>{ip}</td>
                  <td style={{padding:'7px 10px',color:'#8e8e93'}}>{d.sessions}</td>
                  <td style={{padding:'7px 10px'}}>
                    <div style={{display:'flex',gap:3,flexWrap:'wrap'}}>
                      {Array.from(d.ports).slice(0,5).map(p=>(
                        <span key={p} style={{background:'#1e2d3d',color:'#8e8e93',
                          borderRadius:3,padding:'1px 5px',fontSize:9}}>{p}</span>
                      ))}
                      {d.ports.size>5 && <span style={{color:'#636366',fontSize:9}}>+{d.ports.size-5}</span>}
                    </div>
                  </td>
                  <td style={{padding:'7px 10px',color:'#8e8e93'}}>{fmt(d.bytes)}</td>
                  <td style={{padding:'7px 10px'}}><RiskBadge score={d.maxRisk}/></td>
                </tr>
              ))}
              {extList.length===0 && (
                <tr><td colSpan={5} style={{textAlign:'center',padding:'30px',color:'#636366',fontSize:12}}>
                  No external IP sessions found.
                </td></tr>
              )}
            </tbody>
          </table>
        </Card>
      )}

      {/* ══ MITRE ATT&CK ═══════════════════════════════════════════════════════ */}
      {tab==='mitre' && (
        <div>
          {Object.keys(mitreCoverage).length===0 ? (
            <Card style={{textAlign:'center',padding:'40px 20px',color:'#636366'}}>
              <div style={{fontSize:32,marginBottom:8}}>🛡</div>
              Run ▶ Analyse PCAP to generate MITRE ATT&CK coverage.
            </Card>
          ) : (
            <div>
              <div style={{fontSize:11,color:'#636366',marginBottom:12}}>
                Techniques detected across {Object.keys(mitreCoverage).length} ATT&CK tactics
              </div>
              <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:10}}>
                {Object.entries(mitreCoverage).map(([tactic,techniques])=>{
                  const c=MITRE_COLORS[tactic]||'#636366'
                  return (
                    <Card key={tactic} style={{borderLeft:`3px solid ${c}`}}>
                      <div style={{fontSize:11,fontWeight:700,color:c,marginBottom:8}}>{tactic}</div>
                      {(techniques as string[]).map((tech:string)=>(
                        <div key={tech} style={{display:'flex',alignItems:'center',gap:8,
                          marginBottom:5,padding:'4px 8px',background:'#0d1f2d',borderRadius:4}}>
                          <MitreBadge technique={tech} tactic={tactic}/>
                          <span style={{fontSize:10,color:'#8e8e93'}}>
                            {allFindings.filter((f:any)=>f.mitre_technique===tech).length} findings
                          </span>
                        </div>
                      ))}
                    </Card>
                  )
                })}
              </div>
              {/* ATT&CK matrix preview - all tactics */}
              <div style={{marginTop:16}}>
                <div style={{fontSize:11,color:'#636366',marginBottom:8,fontWeight:600}}>ATT&CK COVERAGE MATRIX</div>
                <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
                  {['Initial Access','Execution','Persistence','Privilege Escalation',
                    'Defense Evasion','Credential Access','Discovery','Lateral Movement',
                    'Collection','Command and Control','Exfiltration','Impact'].map(tactic=>{
                    const covered=!!mitreCoverage[tactic]
                    const c=MITRE_COLORS[tactic]||'#636366'
                    const cnt=(mitreCoverage[tactic]||[]).length
                    return (
                      <div key={tactic} style={{
                        background:covered?c+'22':'#1e2d3d',
                        border:`1px solid ${covered?c:'#1e2d3d'}`,
                        borderRadius:6,padding:'6px 10px',minWidth:120,textAlign:'center',
                      }}>
                        <div style={{fontSize:9,color:covered?c:'#636366',fontWeight:covered?700:400,
                          lineHeight:1.3}}>{tactic}</div>
                        {covered && <div style={{fontSize:11,fontWeight:800,color:c,marginTop:2}}>{cnt}</div>}
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
