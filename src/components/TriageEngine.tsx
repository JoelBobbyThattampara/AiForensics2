import { useState, useEffect, useCallback } from 'react'
import { api } from '../api/fctt-client'
import type { MemoryArtifact, ExtractedFile, EvidenceRecord } from '../api/fctt-client'
import { Card, SectionTitle, RiskBadge, RiskMeter, Tag, Btn, TH, TD, ProgressBar } from './shared'
import type { SharedProps } from '../App'

export default function TriageEngine({ selectedCase, notify, setModule }: SharedProps) {
  const [tab, setTab] = useState('process')
  const [evidence, setEvidence] = useState<EvidenceRecord[]>([])
  const [selEvId, setSelEvId] = useState('')
  const [processes, setProcesses] = useState<MemoryArtifact[]>([])
  const [network, setNetwork] = useState<MemoryArtifact[]>([])
  const [files, setFiles] = useState<ExtractedFile[]>([])
  const [taskId, setTaskId] = useState<string|null>(null)
  const [taskStatus, setTaskStatus] = useState<any>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!selectedCase) return
    api.listEvidence(selectedCase.case_id).then(d=>{ setEvidence(d); if(d.length>0) setSelEvId(d[0].evidence_id) }).catch(()=>{})
    loadResults()
  }, [selectedCase])

  useEffect(() => {
    if (!taskId) return
    const iv = setInterval(async()=>{
      try {
        const s = await api.pollTask(taskId)
        setTaskStatus(s)
        if (s.status==='done'||s.status==='error') {
          clearInterval(iv); setRunning(false)
          if (s.status==='done') { notify('Triage complete!','success'); loadResults() }
          else { setError(s.message); notify('Triage failed: '+s.message,'error') }
        }
      } catch { clearInterval(iv) }
    }, 1200)
    return ()=>clearInterval(iv)
  }, [taskId])

  const loadResults = useCallback(async()=>{
    if (!selectedCase) return
    try {
      const [p,n,f] = await Promise.all([api.getProcesses(selectedCase.case_id), api.getNetwork(selectedCase.case_id), api.getFiles(selectedCase.case_id)])
      setProcesses(p); setNetwork(n); setFiles(f)
    } catch {}
  }, [selectedCase])

  const runTriage = async()=>{
    if (!selectedCase) { setError('No case selected'); return }
    if (!selEvId) { setError('No evidence found — ingest evidence first'); return }
    setRunning(true); setError(''); setTaskStatus(null)
    try {
      const res = await api.runTriage(selectedCase.case_id, selEvId)
      setTaskId(res.task_id)
      notify('Triage pipeline started...','info')
    } catch(e:any) { setRunning(false); setError(e.message) }
  }

  if (!selectedCase) return (
    <div style={{textAlign:'center',padding:60}}>
      <div style={{fontSize:32,marginBottom:12}}>🗂️</div>
      <div style={{color:'#636366',fontSize:14}}>No case selected.</div>
      <Btn style={{marginTop:16}} onClick={()=>setModule('cases')}>Go to Cases →</Btn>
    </div>
  )

  return (
    <div>
      <div style={{display:'flex',justifyContent:'space-between',marginBottom:18,alignItems:'flex-start'}}>
        <div>
          <h2 style={{fontWeight:700,fontSize:17}}>Deep Triage Engine</h2>
          <div style={{color:'#636366',fontSize:12,marginTop:2}}>{selectedCase.case_id} — {selectedCase.case_name}</div>
        </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          {evidence.length>0 && (
            <select value={selEvId} onChange={e=>setSelEvId(e.target.value)} style={{background:'#0d1f2d',border:'1px solid #1e2d3d',color:'#e5e5ea',padding:'7px 12px',borderRadius:6,fontSize:12,outline:'none'}}>
              {evidence.map(ev=><option key={ev.evidence_id} value={ev.evidence_id}>{ev.filename} ({(ev.file_size/1024/1024).toFixed(1)} MB)</option>)}
            </select>
          )}
          <Btn onClick={runTriage} disabled={running||evidence.length===0}>{running?'⏳ Running...':'▶ Run Full Triage'}</Btn>
        </div>
      </div>

      {evidence.length===0 && (
        <div style={{background:'#ff9f0a11',border:'1px solid #ff9f0a44',borderRadius:6,padding:'10px 14px',marginBottom:16,fontSize:12,color:'#ff9f0a'}}>
          ⚠ No evidence for this case.
          <Btn color="#ff9f0a" style={{marginLeft:12,fontSize:11,padding:'4px 10px'}} onClick={()=>setModule('ingestion')}>Ingest Evidence →</Btn>
        </div>
      )}

      {taskStatus && (
        <Card style={{marginBottom:16}}>
          <SectionTitle icon="⚙️" title="Pipeline Progress"/>
          <div style={{color:taskStatus.status==='done'?'#30d158':taskStatus.status==='error'?'#ff2d55':'#0a84ff',fontSize:12,marginBottom:8}}>{taskStatus.message}</div>
          <ProgressBar progress={taskStatus.progress} color={taskStatus.status==='done'?'#30d158':taskStatus.status==='error'?'#ff2d55':'#0a84ff'} height={8}/>
          <div style={{fontSize:11,color:'#636366',marginTop:6}}>{Math.round(taskStatus.progress)}% · {taskStatus.status}</div>
          {taskStatus.result && (
            <div style={{display:'flex',gap:10,marginTop:10,flexWrap:'wrap'}}>
              {Object.entries(taskStatus.result).map(([k,v])=>(
                <div key={k} style={{background:'#060f18',borderRadius:6,padding:'5px 10px',fontSize:11}}>
                  <span style={{color:'#636366'}}>{k}: </span><span style={{color:'#0a84ff',fontWeight:700}}>{String(v)}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {error && <div style={{background:'#ff2d5511',border:'1px solid #ff2d5544',borderRadius:6,padding:10,marginBottom:14}}><span style={{color:'#ff2d55',fontSize:12}}>⚠ {error}</span></div>}

      <div style={{display:'flex',gap:8,marginBottom:14}}>
        {(['process','files','network'] as const).map(t=>(
          <Btn key={t} color={tab===t?'#0a84ff':'#0d1f2d'} onClick={()=>setTab(t)}>
            {t.toUpperCase()} ({t==='process'?processes.length:t==='files'?files.length:network.length})
          </Btn>
        ))}
        <Btn color="#1e2d3d" style={{marginLeft:'auto'}} onClick={loadResults}>↻ Refresh</Btn>
      </div>

      {tab==='process' && (
        <Card>
          <SectionTitle icon="💻" title="Process Artifacts" badge={processes.length}/>
          {processes.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No process artifacts. Run triage to populate.</div> : (
            <div style={{overflowX:'auto'}}>
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
            </div>
          )}
        </Card>
      )}

      {tab==='files' && (
        <Card>
          <SectionTitle icon="📄" title="Extracted Files" badge={files.length}/>
          {files.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No files extracted. Run triage to populate.</div> : (
            <div style={{overflowX:'auto'}}>
              <table style={{width:'100%',borderCollapse:'collapse'}}>
                <thead><tr><TH>Name</TH><TH>Path</TH><TH>Size</TH><TH>Type</TH><TH>Status</TH><TH>Modified</TH></tr></thead>
                <tbody>{files.slice(0,200).map(f=>(
                  <tr key={f.file_id}>
                    <TD><span style={{color:'#ff9f0a',fontWeight:600}}>{f.name}</span></TD>
                    <TD><span style={{fontFamily:'monospace',fontSize:10,color:'#636366'}}>{f.full_path?.slice(0,50)}</span></TD>
                    <TD>{f.size?(f.size/1024).toFixed(1)+' KB':'—'}</TD>
                    <TD><Tag label={f.file_type||'FILE'} color="#bf5af2"/></TD>
                    <TD><Tag label={f.allocated?'Allocated':'Deleted'} color={f.allocated?'#30d158':'#ff2d55'}/></TD>
                    <TD><span style={{fontSize:10,color:'#636366'}}>{f.modified_ts?.slice(0,19)||'—'}</span></TD>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </Card>
      )}

      {tab==='network' && (
        <Card>
          <SectionTitle icon="🌐" title="Network Artifacts" badge={network.length}/>
          {network.length===0 ? <div style={{color:'#636366',fontSize:12,padding:30,textAlign:'center'}}>No network artifacts. Run triage to populate.</div> : (
            <div style={{overflowX:'auto'}}>
              <table style={{width:'100%',borderCollapse:'collapse'}}>
                <thead><tr><TH>PID</TH><TH>Process</TH><TH>Plugin</TH><TH>Data</TH><TH>Risk</TH></tr></thead>
                <tbody>{network.map(n=>(
                  <tr key={n.artifact_id}>
                    <TD><span style={{fontFamily:'monospace',color:'#0a84ff'}}>{n.pid}</span></TD>
                    <TD>{n.process_name}</TD>
                    <TD><Tag label={n.plugin.split('.').pop()||n.plugin} color="#0a84ff"/></TD>
                    <TD><span style={{fontFamily:'monospace',fontSize:10,color:'#636366'}}>{n.raw_data?.slice(0,60)}</span></TD>
                    <TD><RiskBadge score={Math.round(n.risk_score)}/></TD>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}