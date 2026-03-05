import { useState, useEffect } from 'react'
import { api } from '../api/fctt-client'
import type { TimelineEvent, IOCMatch } from '../api/fctt-client'
import { Card, SectionTitle, RiskBadge, Btn, TH, TD } from './shared'
import type { SharedProps } from '../App'

export default function Dashboard({ selectedCase, cases, setSelectedCase, setModule, loadCases }: SharedProps) {
  const [recentEvents, setRecentEvents] = useState<TimelineEvent[]>([])
  const [recentIOCs, setRecentIOCs] = useState<IOCMatch[]>([])

  useEffect(()=>{
    loadCases()
    if (selectedCase) {
      api.getTimeline(selectedCase.case_id, 10).then(setRecentEvents).catch(()=>{})
      api.getIOCs(selectedCase.case_id).then(d=>setRecentIOCs(d.slice(0,5))).catch(()=>{})
    }
  }, [selectedCase])

  const riskColor = (s:number) => s>=90?'#ff2d55':s>=70?'#ff9f0a':s>=40?'#ffd60a':'#30d158'
  const typeColor = (t:string) => ({FILE:'#30d158',PROCESS:'#bf5af2',NETWORK:'#0a84ff',IOC:'#ff2d55',YARA:'#ff9f0a'}[t]||'#636366')

  return (
    <div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:14,marginBottom:20}}>
        {[
          ['Total Cases', cases.length, '#0a84ff', '📁'],
          ['Active Cases', cases.filter(c=>c.status==='Active'||!c.status).length, '#30d158', '✅'],
          ['IOC Matches', recentIOCs.length, '#ff2d55', '⚠️'],
          ['Timeline Events', recentEvents.length, '#ff9f0a', '📋'],
        ].map(([l,v,c,ic])=>(
          <Card key={l as string} style={{textAlign:'center'}}>
            <div style={{fontSize:22,marginBottom:6}}>{ic as string}</div>
            <div style={{fontSize:34,fontWeight:800,color:c as string}}>{v as number}</div>
            <div style={{color:'#636366',fontSize:11,marginTop:3}}>{l as string}</div>
          </Card>
        ))}
      </div>

      {!selectedCase && (
        <div style={{background:'#0a84ff11',border:'1px solid #0a84ff33',borderRadius:8,padding:'18px 20px',marginBottom:18,textAlign:'center'}}>
          <div style={{fontSize:24,marginBottom:8}}>🛡</div>
          <div style={{color:'#e5e5ea',fontWeight:700,fontSize:14,marginBottom:6}}>Welcome to FCTT</div>
          <div style={{color:'#8e8e93',fontSize:12,marginBottom:14}}>Create a case and ingest evidence to get started.</div>
          <Btn onClick={()=>setModule('cases')}>＋ Create First Case</Btn>
        </div>
      )}

      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:14,marginBottom:14}}>
        <Card>
          <SectionTitle icon="📋" title="Recent Timeline Events"/>
          {recentEvents.length===0 ? (
            <div style={{color:'#636366',fontSize:12,padding:20,textAlign:'center'}}>
              {selectedCase?'No events yet — run triage to populate.':'Select a case to see events.'}
            </div>
          ) : recentEvents.map((e,i)=>(
            <div key={e.event_id||i} style={{display:'flex',gap:8,alignItems:'flex-start',padding:'7px 0',borderBottom:i<recentEvents.length-1?'1px solid #0d1f2d':'none'}}>
              <span style={{background:typeColor(e.event_type)+'22',color:typeColor(e.event_type),border:`1px solid ${typeColor(e.event_type)}44`,padding:'1px 5px',borderRadius:3,fontSize:10,fontWeight:600,flexShrink:0}}>{e.event_type||'EVENT'}</span>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:11,color:'#c7c7cc',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.description}</div>
                <div style={{fontSize:10,color:'#636366',marginTop:1}}>{e.timestamp?.slice(0,19)}</div>
              </div>
              <RiskBadge score={Math.round(e.risk_score||0)}/>
            </div>
          ))}
        </Card>

        <Card>
          <SectionTitle icon="⚠️" title="Recent IOC Matches"/>
          {recentIOCs.length===0 ? (
            <div style={{color:'#636366',fontSize:12,padding:20,textAlign:'center'}}>
              {selectedCase?'No IOCs detected yet.':'Select a case to see IOCs.'}
            </div>
          ) : recentIOCs.map((ioc,i)=>(
            <div key={ioc.ioc_id||i} style={{display:'flex',gap:8,alignItems:'center',padding:'7px 0',borderBottom:i<recentIOCs.length-1?'1px solid #0d1f2d':'none'}}>
              <span style={{background:'#ff2d5522',color:'#ff2d55',border:'1px solid #ff2d5544',padding:'1px 5px',borderRadius:3,fontSize:10,fontWeight:600,flexShrink:0}}>{ioc.ioc_type}</span>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:11,color:'#ff9f0a',fontFamily:'monospace',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{ioc.indicator}</div>
                <div style={{fontSize:10,color:'#636366'}}>{ioc.rule_name}</div>
              </div>
              <span style={{color:'#ff2d55',fontSize:11,fontWeight:700}}>{Math.round(ioc.confidence)}%</span>
            </div>
          ))}
        </Card>
      </div>

      <Card>
        <SectionTitle icon="🗂️" title="All Cases"/>
        {cases.length===0 ? (
          <div style={{color:'#636366',fontSize:12,padding:20,textAlign:'center'}}>No cases yet. <span style={{color:'#0a84ff',cursor:'pointer'}} onClick={()=>setModule('cases')}>Create one →</span></div>
        ) : (
          <table style={{width:'100%',borderCollapse:'collapse'}}>
            <thead><tr><TH>Case ID</TH><TH>Name</TH><TH>Number</TH><TH>Status</TH><TH>Created</TH><TH>Action</TH></tr></thead>
            <tbody>{cases.map(c=>(
              <tr key={c.case_id}>
                <TD><span style={{color:'#0a84ff',fontFamily:'monospace',fontSize:11}}>{c.case_id}</span></TD>
                <TD><span style={{fontWeight:600}}>{c.case_name}</span></TD>
                <TD><span style={{color:'#636366'}}>#{c.case_number}</span></TD>
                <TD><span style={{background:'#30d15822',color:'#30d158',border:'1px solid #30d15844',padding:'2px 6px',borderRadius:3,fontSize:10,fontWeight:600}}>{c.status||'Active'}</span></TD>
                <TD><span style={{color:'#636366',fontSize:11}}>{c.created_at?.slice(0,10)}</span></TD>
                <TD>
                  <Btn style={{fontSize:11,padding:'4px 10px'}} onClick={()=>{ setSelectedCase(c); setModule('triage') }}>
                    {selectedCase?.case_id===c.case_id?'● Active':'Select'}
                  </Btn>
                </TD>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  )
}