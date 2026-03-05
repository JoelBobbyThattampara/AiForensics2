import { useState, useEffect } from 'react'
import { api } from '../api/fctt-client'
import type { MemoryArtifact } from '../api/fctt-client'
import { Card, SectionTitle, RiskMeter, Tag, Btn, TH, TD } from './shared'
import type { SharedProps } from '../App'

export default function MemoryAnalysis({ selectedCase, setModule }: SharedProps) {
  const [processes, setProcesses] = useState<MemoryArtifact[]>([])
  const [network, setNetwork] = useState<MemoryArtifact[]>([])
  const [tab, setTab] = useState('process')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const load = async () => {
    if (!selectedCase) return
    setLoading(true); setError('')
    try {
      const [p, n] = await Promise.all([api.getProcesses(selectedCase.case_id), api.getNetwork(selectedCase.case_id)])
      setProcesses(p); setNetwork(n)
    } catch(e:any) { setError(e.message) }
    finally { setLoading(false) }
  }
  useEffect(()=>{ load() }, [selectedCase])

  if (!selectedCase) return (
    <div style={{textAlign:'center',padding:60}}>
      <div style={{fontSize:32,marginBottom:12}}>🧠</div>
      <div style={{color:'#636366',fontSize:14}}>No case selected.</div>
      <Btn style={{marginTop:16}} onClick={()=>setModule('cases')}>Go to Cases →</Btn>
    </div>
  )

  const all = [...processes, ...network]
  const malfind = all.filter(a=>a.plugin?.includes('malfind'))
  const injected = all.filter(a=>a.flags?.includes('CODE_INJECTION')||a.flags?.includes('PE_IN_RWX'))

  return (
    <div>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:18,alignItems:'center'}}>
        <div>
          <h2 style={{fontWeight:700,fontSize:17}}>Memory Analysis — Volatility Integration</h2>
          <div style={{color:'#636366',fontSize:12}}>{selectedCase.case_id}</div>
        </div>
        <Btn color="#1e2d3d" onClick={load}>↻ Refresh</Btn>
      </div>
      {error && <div style={{background:'#ff2d5511',border:'1px solid #ff2d5544',borderRadius:6,padding:10,marginBottom:14}}><span style={{color:'#ff2d55',fontSize:12}}>⚠ {error}</span></div>}

      <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:14,marginBottom:14}}>
        {[['Total Artifacts',all.length,'#0a84ff'],['Malfind Hits',malfind.length,'#ff2d55'],['Injected Regions',injected.length,'#ff9f0a']].map(([l,v,c])=>(
          <Card key={l as string} style={{textAlign:'center',padding:16}}>
            <div style={{fontSize:28,fontWeight:800,color:c as string}}>{v as number}</div>
            <div style={{color:'#636366',fontSize:11,marginTop:3}}>{l as string}</div>
          </Card>
        ))}
      </div>

      <div style={{display:'flex',gap:8,marginBottom:14}}>
        {(['process','network','malfind'] as const).map(t=>(
          <Btn key={t} color={tab===t?'#0a84ff':'#0d1f2d'} onClick={()=>setTab(t)} style={{textTransform:'capitalize'}}>{t}</Btn>
        ))}
      </div>

      <Card>
        {tab==='process' && <>
          <SectionTitle icon="💻" title="Process Artifacts" badge={processes.length}/>
          {loading ? <div style={{color:'#636366',fontSize:12,padding:20,textAlign:'center'}}>Loading...</div>
          : processes.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No process artifacts. Run triage with Volatility to populate.</div>
          : <div style={{overflowX:'auto'}}>
              <table style={{width:'100%',borderCollapse:'collapse'}}>
                <thead><tr><TH>PID</TH><TH>Process</TH><TH>PPID</TH><TH>Plugin</TH><TH>Flags</TH><TH>Risk</TH></tr></thead>
                <tbody>{processes.map(p=>(
                  <tr key={p.artifact_id}>
                    <TD><span style={{fontFamily:'monospace',color:'#0a84ff'}}>{p.pid}</span></TD>
                    <TD><span style={{fontWeight:600}}>{p.process_name}</span></TD>
                    <TD><span style={{fontFamily:'monospace'}}>{p.ppid}</span></TD>
                    <TD><Tag label={p.plugin.split('.').pop()||p.plugin} color="#bf5af2"/></TD>
                    <TD><div style={{display:'flex',gap:4}}>{p.flags?.split(',').filter(Boolean).map(f=><Tag key={f} label={f} color="#ff2d55"/>)}</div></TD>
                    <TD><RiskMeter score={Math.round(p.risk_score)}/></TD>
                  </tr>
                ))}</tbody>
              </table>
            </div>}
        </>}
        {tab==='network' && <>
          <SectionTitle icon="🌐" title="Network Artifacts" badge={network.length}/>
          {network.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No network artifacts. Run triage with netscan plugin.</div>
          : <div style={{overflowX:'auto'}}>
              <table style={{width:'100%',borderCollapse:'collapse'}}>
                <thead><tr><TH>PID</TH><TH>Process</TH><TH>Plugin</TH><TH>Raw Data</TH><TH>Risk</TH></tr></thead>
                <tbody>{network.map(n=>(
                  <tr key={n.artifact_id}>
                    <TD><span style={{fontFamily:'monospace',color:'#0a84ff'}}>{n.pid}</span></TD>
                    <TD>{n.process_name}</TD>
                    <TD><Tag label={n.plugin.split('.').pop()||n.plugin} color="#0a84ff"/></TD>
                    <TD><span style={{fontFamily:'monospace',fontSize:10,color:'#636366'}}>{n.raw_data?.slice(0,60)}</span></TD>
                    <TD><RiskMeter score={Math.round(n.risk_score)}/></TD>
                  </tr>
                ))}</tbody>
              </table>
            </div>}
        </>}
        {tab==='malfind' && <>
          <SectionTitle icon="🚨" title="Malfind — Injected Regions" badge={malfind.length}/>
          {malfind.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No malfind results. Run triage with windows.malfind plugin.</div>
          : malfind.map(m=>(
            <div key={m.artifact_id} style={{background:'#060f18',borderRadius:6,padding:12,marginBottom:10,border:'1px solid #ff2d5522'}}>
              <div style={{display:'flex',gap:8,marginBottom:6,flexWrap:'wrap'}}>
                <Tag label={`PID ${m.pid}`} color="#0a84ff"/>
                <span style={{fontWeight:700,color:'#e5e5ea'}}>{m.process_name}</span>
                {m.flags?.split(',').filter(Boolean).map(f=><Tag key={f} label={f} color="#ff2d55"/>)}
              </div>
              {m.raw_data && <div style={{fontFamily:'monospace',fontSize:10,color:'#8e8e93',background:'#080e18',borderRadius:4,padding:8}}>{m.raw_data.slice(0,300)}</div>}
            </div>
          ))}
        </>}
      </Card>
    </div>
  )
}