import { useState } from 'react'
import { api } from '../api/fctt-client'
import { Card, SectionTitle, Btn, Select } from './shared'
import type { SharedProps } from '../App'

export default function ReportGenerator({ selectedCase, notify, setModule }: SharedProps) {
  const [reportType, setReportType] = useState('full')
  const [fmt, setFmt] = useState('json')
  const [generating, setGenerating] = useState(false)
  const [report, setReport] = useState<any>(null)
  const [error, setError] = useState('')

  const generate = async () => {
    if (!selectedCase) { setError('No case selected'); return }
    setGenerating(true); setError(''); setReport(null)
    try {
      const data = await api.generateReport(selectedCase.case_id, reportType, fmt)
      setReport(data)
      notify('Forensic report generated and hash-signed.', 'success')
    } catch(e:any) {
      setError(e.message?.includes('fetch')?'Cannot reach backend — run: python main.py':e.message)
    } finally { setGenerating(false) }
  }

  const downloadReport = () => {
    if (!report) return
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `FCTT_Report_${selectedCase?.case_id}_${new Date().toISOString().slice(0,10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (!selectedCase) return (
    <div style={{textAlign:'center',padding:60}}>
      <div style={{fontSize:32,marginBottom:12}}>📄</div>
      <div style={{color:'#636366',fontSize:14}}>No case selected.</div>
      <Btn style={{marginTop:16}} onClick={()=>setModule('cases')}>Go to Cases →</Btn>
    </div>
  )

  return (
    <div>
      <h2 style={{fontWeight:700,fontSize:17,marginBottom:18}}>Forensic Report Generator</h2>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:18}}>
        <Card>
          <SectionTitle icon="⚙️" title="Report Configuration"/>
          <div style={{marginBottom:12}}>
            <label style={{color:'#636366',fontSize:10,display:'block',marginBottom:4}}>REPORT TYPE</label>
            <Select value={reportType} onChange={e=>setReportType(e.target.value)}>
              <option value="full">Full Forensic Report</option>
              <option value="executive">Executive Summary</option>
              <option value="ioc">IOC Export</option>
              <option value="timeline">Timeline Only</option>
            </Select>
          </div>
          <div style={{marginBottom:16}}>
            <label style={{color:'#636366',fontSize:10,display:'block',marginBottom:4}}>OUTPUT FORMAT</label>
            <Select value={fmt} onChange={e=>setFmt(e.target.value)}>
              <option value="json">JSON</option>
              <option value="pdf">PDF (requires fpdf2)</option>
            </Select>
          </div>
          <div style={{background:'#060f18',borderRadius:6,padding:12,marginBottom:14,fontSize:11,color:'#8e8e93'}}>
            <div style={{marginBottom:4,color:'#0a84ff',fontWeight:600}}>Report will include:</div>
            <div>✓ Case metadata & investigator info</div>
            <div>✓ All evidence items with SHA-256 hashes</div>
            <div>✓ Chain of custody log (append-only)</div>
            <div>✓ IOC matches & YARA hits</div>
            <div>✓ Forensic timeline events</div>
            <div>✓ AI risk scores & classifications</div>
            <div>✓ Memory analysis artifacts</div>
            <div>✓ Report integrity SHA-256 signature</div>
          </div>
          {error && <div style={{background:'#ff2d5511',border:'1px solid #ff2d5544',borderRadius:6,padding:10,marginBottom:10}}><span style={{color:'#ff2d55',fontSize:11}}>⚠ {error}</span></div>}
          <Btn color="#30d158" style={{width:'100%'}} onClick={generate} disabled={generating}>
            {generating?'⏳ Generating Report...':'📄 Generate Signed Forensic Report'}
          </Btn>
        </Card>

        <Card>
          <SectionTitle icon="🛡️" title="Report Preview"/>
          {!report && !generating && (
            <div style={{color:'#636366',fontSize:12,textAlign:'center',padding:40}}>
              Configure options and click Generate to produce a hash-signed forensic report.
            </div>
          )}
          {generating && (
            <div style={{color:'#0a84ff',fontSize:12,textAlign:'center',padding:40}}>
              ⏳ Compiling evidence, hashes, IOCs, timeline, AI scores...
            </div>
          )}
          {report && (
            <div>
              <div style={{background:'#060f18',borderRadius:6,padding:14,fontSize:11,fontFamily:'monospace',marginBottom:12}}>
                <div style={{textAlign:'center',marginBottom:10,paddingBottom:8,borderBottom:'1px solid #1e2d3d'}}>
                  <div style={{color:'#0a84ff',fontSize:12,fontWeight:700}}>FORENSIC CYBER TRIAGE TOOL</div>
                  <div style={{color:'#636366'}}>FORENSIC INVESTIGATION REPORT</div>
                  <div style={{color:'#e5e5ea',marginTop:2}}>{report.case_summary?.case_name||selectedCase.case_name}</div>
                  <div style={{color:'#636366'}}>{selectedCase.case_id}</div>
                </div>
                {[
                  ['Tool Version', report.report_metadata?.tool],
                  ['Generated At', report.report_metadata?.generated_at?.slice(0,19)],
                  ['Case Number', report.case_summary?.case_number],
                  ['Evidence Items', report.statistics?.evidence_count],
                  ['IOC Findings', report.statistics?.ioc_count],
                  ['Timeline Events', report.statistics?.timeline_events],
                  ['COC Entries', report.chain_of_custody?.length],
                  ['Report SHA-256', report.report_metadata?.report_sha256?.slice(0,20)+'...'],
                ].map(([k,v])=>(
                  <div key={k as string} style={{display:'flex',justifyContent:'space-between',padding:'4px 0',borderBottom:'1px solid #0d1f2d'}}>
                    <span style={{color:'#636366'}}>{k as string}:</span>
                    <span style={{color:'#c7c7cc'}}>{String(v??'—')}</span>
                  </div>
                ))}
              </div>
              <div style={{background:'#30d15811',border:'1px solid #30d15844',borderRadius:6,padding:10,marginBottom:10}}>
                <div style={{color:'#30d158',fontWeight:700,fontSize:12}}>✓ Report generated & hash-signed</div>
                <div style={{color:'#636366',fontSize:10,marginTop:2}}>SHA-256: {report.report_metadata?.report_sha256?.slice(0,32)}...</div>
              </div>
              <Btn color="#0a84ff" style={{width:'100%'}} onClick={downloadReport}>
                ⬇ Download Report JSON
              </Btn>
            </div>
          )}
        </Card>
      </div>

      {report?.chain_of_custody?.length>0 && (
        <Card style={{marginTop:14}}>
          <SectionTitle icon="🔗" title="Chain of Custody" badge={report.chain_of_custody.length}/>
          <div style={{overflowX:'auto'}}>
            <table style={{width:'100%',borderCollapse:'collapse'}}>
              <thead><tr>
                {['Timestamp','Action','Actor','Target','Notes','Hash After'].map(h=>(
                  <th key={h} style={{color:'#636366',padding:'8px 12px',textAlign:'left',borderBottom:'1px solid #1e2d3d',fontWeight:600,fontSize:10}}>{h}</th>
                ))}
              </tr></thead>
              <tbody>{report.chain_of_custody.map((e:any)=>(
                <tr key={e.entry_id}>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',color:'#636366',fontSize:10,fontFamily:'monospace'}}>{e.ts?.slice(0,19)}</td>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',fontSize:11}}><span style={{background:'#0a84ff22',color:'#0a84ff',border:'1px solid #0a84ff44',padding:'1px 6px',borderRadius:3,fontSize:10}}>{e.action}</span></td>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',color:'#c7c7cc',fontSize:11}}>{e.actor}</td>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',color:'#8e8e93',fontSize:10,maxWidth:180}}><div style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.target}</div></td>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',color:'#636366',fontSize:10}}>{e.notes?.slice(0,50)}</td>
                  <td style={{padding:'8px 12px',borderBottom:'1px solid #0d1f2d',color:'#30d158',fontSize:10,fontFamily:'monospace'}}>{e.hash_after?.slice(0,16)}{e.hash_after?'...':''}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  )
}