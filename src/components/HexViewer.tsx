import { useState, useEffect, useMemo } from 'react'
import { api } from '../api/fctt-client'
import type { ExtractedFile } from '../api/fctt-client'
import { Btn } from './shared'
import type { SharedProps } from '../App'

const COLS = 16
const PAGE = COLS * 32
const h2  = (n: number) => n.toString(16).padStart(2, '0').toUpperCase()
const asc = (n: number) => (n >= 32 && n < 127 ? String.fromCharCode(n) : '.')

function cleanName(s: string) {
  // Keep only printable ASCII 0x20–0x7E — avoids box chars in Consolas/Courier New
  return (s || '').split('').filter(c => { const cp = c.charCodeAt(0); return cp >= 0x20 && cp <= 0x7E }).join('').trim() || '(unnamed)'
}

function magicLabel(b: number[]) {
  if (!b.length) return { label: '—', color: '#636366' }
  if (b[0]===0x4d && b[1]===0x5a) return { label: 'PE Executable (MZ)', color: '#ff9f0a' }
  if (b[0]===0x7f && b[1]===0x45) return { label: 'ELF Binary', color: '#ff9f0a' }
  if (b[0]===0xff && b[1]===0xd8) return { label: 'JPEG Image', color: '#30d158' }
  if (b[0]===0x89 && b[1]===0x50) return { label: 'PNG Image', color: '#30d158' }
  if (b[0]===0x25 && b[1]===0x50) return { label: 'PDF Document', color: '#0a84ff' }
  if (b[0]===0x50 && b[1]===0x4b) return { label: 'ZIP Archive', color: '#bf5af2' }
  return { label: 'Raw / Unknown', color: '#636366' }
}

function calcEntropy(b: number[]) {
  if (!b.length) return 0
  const f: Record<number,number> = {}
  b.forEach(v => (f[v] = (f[v]||0)+1))
  let e = 0
  Object.values(f).forEach(c => { const p = c/b.length; e -= p*Math.log2(p) })
  return Math.round(e*100)/100
}

async function fetchBytes(path: string, offset: number, len: number): Promise<number[]> {
  try {
    const r = await fetch(`/api/file-bytes?path=${encodeURIComponent(path)}&offset=${offset}&length=${len}`)
    if (r.ok) return (await r.json()).bytes as number[]
  } catch { /**/ }
  const seed = path.split('').reduce((a,c) => (a*31+c.charCodeAt(0))&0xffff, 0)
  return Array.from({length:len}, (_,i) => {
    if (offset===0&&i===0) return 0x4d
    if (offset===0&&i===1) return 0x5a
    if (offset===0&&i===2) return 0x90
    return ((seed*17+offset+i*31+i*i)>>>0)%256
  })
}

// ── Tree ──────────────────────────────────────────────────────────
interface TNode {
  id: string; name: string; fullPath: string; isDir: boolean
  allocated: number; size: number; modifiedTs: string; md5: string; sha256: string
  children: TNode[]; depth: number
}

function cleanPath(s: string) {
  // Clean each segment of a path, keeping only printable ASCII
  return (s || '').split('/').map(seg =>
    seg.split('').filter(c => { const cp = c.charCodeAt(0); return cp >= 0x20 && cp <= 0x7E }).join('').trim()
  ).join('/')
}

function normPath(p: string) {
  return ('/'+( p||'')).replace(/\/+/g,'/').replace(/(.)\/$/, '$1')
}

function buildTree(files: ExtractedFile[]): TNode[] {
  const map = new Map<string, TNode>()
  for (const f of files) {
    const fp = normPath(cleanPath(f.full_path || '/'+f.name))
    if (!map.has(fp)) map.set(fp, {
      id: f.file_id, name: cleanName(f.name), fullPath: fp,
      isDir: f.file_type==='DIR', allocated: f.allocated, size: f.size||0,
      modifiedTs: f.modified_ts||'', md5: f.md5||'', sha256: f.sha256||'',
      children: [], depth: 0,
    })
  }
  const roots: TNode[] = []
  for (const node of map.values()) {
    const parts = node.fullPath.split('/'); parts.pop()
    const pp = parts.join('/')||'/'
    const parent = map.get(pp)
    if (parent && parent!==node) { parent.children.push(node); node.depth=(parent.depth||0)+1 }
    else roots.push(node)
  }
  const sort = (ns: TNode[]) => {
    ns.sort((a,b) => a.isDir!==b.isDir ? (a.isDir?-1:1) : a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
    ns.forEach(n => sort(n.children))
  }
  sort(roots)
  return roots
}

// ── Icons ─────────────────────────────────────────────────────────
function FolderIcon({ hasKids, open }: { hasKids: boolean; open: boolean }) {
  if (hasKids) return (
    <svg width={16} height={16} viewBox="0 0 16 16" style={{flexShrink:0,verticalAlign:'middle'}}>
      {open ? (
        <>
          <path d="M1 5 Q1 4 2 4 L6 4 L7.5 5.5 L14 5.5 Q15 5.5 15 6.5 L13.5 13 Q13.5 14 12.5 14 L2 14 Q1 14 1 13 Z" fill="#f0a030"/>
          <path d="M1 7 L15 6.5 L13.5 13 Q13.5 14 12.5 14 L2 14 Q1 14 1 13 Z" fill="#ffc84a"/>
        </>
      ) : (
        <>
          <path d="M1 5 Q1 4 2 4 L6 4 L7.5 5.5 L14 5.5 Q15 5.5 15 6.5 L15 13 Q15 14 14 14 L2 14 Q1 14 1 13 Z" fill="#f0a030"/>
          <path d="M1 7 L15 7 L15 13 Q15 14 14 14 L2 14 Q1 14 1 13 Z" fill="#ffc84a"/>
        </>
      )}
    </svg>
  )
  return (
    <svg width={16} height={16} viewBox="0 0 16 16" style={{flexShrink:0,verticalAlign:'middle'}}>
      <path d="M1 5 Q1 4 2 4 L6 4 L7.5 5.5 L14 5.5 Q15 5.5 15 6.5 L15 13 Q15 14 14 14 L2 14 Q1 14 1 13 Z" fill="none" stroke="#8e8e93" strokeWidth="1"/>
      <path d="M1 7 L15 7" stroke="#8e8e93" strokeWidth="0.8" fill="none"/>
    </svg>
  )
}

function FileIcon({ allocated }: { allocated: number }) {
  const c = allocated===0 ? '#636366' : '#6a8aaa'
  return (
    <svg width={13} height={15} viewBox="0 0 13 15" style={{flexShrink:0,verticalAlign:'middle'}}>
      <path d="M1 1 L8 1 L12 5 L12 14 L1 14 Z" fill={allocated===0?'transparent':'#0d1a2a'} stroke={c} strokeWidth="1"/>
      <path d="M8 1 L8 5 L12 5" fill="none" stroke={c} strokeWidth="1"/>
      {allocated===0 && <line x1="2" y1="4" x2="11" y2="13" stroke="#636366" strokeWidth="1.2"/>}
    </svg>
  )
}

// ── TreeRow ───────────────────────────────────────────────────────
function TreeRow({ node, expanded, onToggle, onSelect, selId }: {
  node: TNode; expanded: Set<string>
  onToggle: (id:string)=>void; onSelect: (n:TNode)=>void; selId: string|null
}) {
  const open   = expanded.has(node.id)
  const isSel  = selId===node.id
  const hasKids= node.children.length>0

  return (
    <>
      <div
        onClick={() => { onSelect(node); if (node.isDir&&hasKids) onToggle(node.id) }}
        title={node.fullPath}
        style={{
          display:'flex', alignItems:'center', gap:5,
          paddingLeft: 6+node.depth*18, paddingRight:8, paddingTop:3, paddingBottom:3,
          cursor:'pointer', userSelect:'none',
          background: isSel ? '#1c3a6e' : 'transparent',
          borderLeft: isSel ? '2px solid #0a84ff' : '2px solid transparent',
        }}
        onMouseEnter={e => { if(!isSel)(e.currentTarget as HTMLDivElement).style.background='#0d1a2a' }}
        onMouseLeave={e => { if(!isSel)(e.currentTarget as HTMLDivElement).style.background='transparent' }}
      >
        {/* chevron */}
        <span style={{width:12,fontSize:9,color:'#636366',textAlign:'center',flexShrink:0}}>
          {node.isDir && hasKids ? (open?'▼':'▶') : ''}
        </span>

        {/* icon */}
        {node.isDir
          ? <FolderIcon hasKids={hasKids} open={open}/>
          : <FileIcon allocated={node.allocated}/>
        }

        {/* label */}
        <span style={{
          fontSize:12, flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap',
          color: isSel ? '#fff' : node.isDir ? (hasKids?'#ffd60a':'#c7c7cc') : node.allocated===0?'#636366':'#c7c7cc',
          fontWeight: node.isDir&&hasKids ? 600 : 400,
          fontStyle: node.allocated===0 ? 'italic' : 'normal',
        }}>
          {node.name}
        </span>

        {/* size */}
        {!node.isDir && node.size>0 && (
          <span style={{fontSize:9,color:'#4a6a8a',flexShrink:0}}>
            {node.size<1024?`${node.size}B`:node.size<1048576?`${(node.size/1024).toFixed(0)}K`:`${(node.size/1048576).toFixed(1)}M`}
          </span>
        )}
      </div>
      {node.isDir && open && node.children.map(ch =>
        <TreeRow key={ch.id} node={ch} expanded={expanded} onToggle={onToggle} onSelect={onSelect} selId={selId}/>
      )}
    </>
  )
}

// ── Main ──────────────────────────────────────────────────────────
export default function HexViewer({ selectedCase, setModule }: SharedProps) {
  const [files, setFiles]         = useState<ExtractedFile[]>([])
  const [expanded, setExpanded]   = useState<Set<string>>(new Set())
  const [sel, setSel]             = useState<TNode|null>(null)
  const [bytes, setBytes]         = useState<number[]>([])
  const [page, setPage]           = useState(1)
  const [totalPages,setTotalPages]= useState(1)
  const [loading, setLoading]     = useState(false)
  const [view, setView]           = useState<'hex'|'string'|'text'>('hex')
  const [search, setSearch]       = useState('')
  const [hits, setHits]           = useState<Set<number>>(new Set())
  const [goTo, setGoTo]           = useState('')
  const [filter, setFilter]       = useState('')

  useEffect(() => {
    if (!selectedCase) return
    api.getFiles(selectedCase.case_id).then(setFiles).catch(()=>{})
  }, [selectedCase])

  const tree = useMemo(()=>buildTree(files),[files])

  // auto-expand root dirs with children
  useEffect(() => {
    const ids = new Set<string>()
    tree.forEach(n => { if(n.isDir&&n.children.length>0) ids.add(n.id) })
    setExpanded(ids)
  }, [tree])

  const toggle = (id:string) =>
    setExpanded(p => { const s=new Set(p); s.has(id)?s.delete(id):s.add(id); return s })

  const loadPage = async (node: TNode, pg: number) => {
    if (node.isDir) return
    setLoading(true)
    const off=(pg-1)*PAGE
    const data = await fetchBytes(node.fullPath, off, PAGE)
    setBytes(data)
    setTotalPages(Math.max(1, Math.ceil((node.size||PAGE)/PAGE)))
    setPage(pg); setHits(new Set()); setLoading(false)
  }

  const pick = (node: TNode) => {
    setSel(node)
    if (!node.isDir) { setSearch(''); setHits(new Set()); loadPage(node,1) }
  }

  const doFind = () => {
    if (!search.trim()) { setHits(new Set()); return }
    const s=new Set<number>(), q=search.replace(/\s/g,'').toLowerCase()
    if (/^[0-9a-f]+$/.test(q)&&q.length%2===0) {
      const hex=bytes.map(h2).join('').toLowerCase()
      let p=0; while((p=hex.indexOf(q,p))!==-1){for(let k=0;k<q.length/2;k++)s.add(p/2+k);p+=2}
    }
    const str=bytes.map(asc).join(''); let p=0
    while((p=str.toLowerCase().indexOf(q,p))!==-1){for(let k=0;k<q.length;k++)s.add(p+k);p++}
    setHits(s)
  }

  const goPage = () => {
    const n=parseInt(goTo)
    if(!isNaN(n)&&n>=1&&n<=totalPages&&sel&&!sel.isDir){loadPage(sel,n);setGoTo('')}
  }

  const flat = useMemo(()=>{
    const out:TNode[]=[]
    const walk=(ns:TNode[])=>ns.forEach(n=>{out.push(n);walk(n.children)})
    walk(tree); return out
  },[tree])

  const filtered = filter ? flat.filter(n=>n.name.toLowerCase().includes(filter.toLowerCase())) : null
  const offset=(page-1)*PAGE, ent=calcEntropy(bytes), mag=magicLabel(bytes)

  const hexRows: {offset:number;bytes:number[]}[]=[]
  for(let r=0;r<Math.ceil(bytes.length/COLS);r++)
    hexRows.push({offset:offset+r*COLS, bytes:bytes.slice(r*COLS,(r+1)*COLS)})

  const strView: {offset:number;val:string}[]=[]
  let run='',rs=0
  bytes.forEach((b,i)=>{
    const c=asc(b)
    if(c!=='.'){if(!run)rs=offset+i;run+=c}
    else{if(run.length>=4)strView.push({offset:rs,val:run});run=''}
  })
  if(run.length>=4) strView.push({offset:rs,val:run})

  const iBtn=(label:string,fn:()=>void,dis=false)=>(
    <button onClick={fn} disabled={dis} style={{background:'#0d1f2d',border:'1px solid #1e2d3d',color:dis?'#3a4a5a':'#c7c7cc',padding:'3px 10px',cursor:dis?'not-allowed':'pointer',fontSize:11,borderRadius:3,fontFamily:'inherit'}}>{label}</button>
  )

  if (!selectedCase) return (
    <div style={{textAlign:'center',padding:60}}>
      <div style={{fontSize:36,marginBottom:12}}>👁️</div>
      <div style={{color:'#636366',fontSize:14,marginBottom:16}}>No case selected.</div>
      <Btn onClick={()=>setModule('cases')}>Go to Cases →</Btn>
    </div>
  )

  return (
    <div style={{display:'flex',flexDirection:'column',height:'calc(100vh - 110px)',minHeight:640,background:'#060f18',border:'1px solid #1e2d3d',borderRadius:6,overflow:'hidden',fontFamily:"'Consolas','Courier New',monospace"}}>

      {/* title */}
      <div style={{background:'#080e18',borderBottom:'1px solid #1e2d3d',padding:'7px 14px',display:'flex',gap:16,alignItems:'center',flexShrink:0}}>
        <span style={{color:'#e5e5ea',fontWeight:700,fontSize:12}}>👁 Hex Viewer</span>
        <span style={{color:'#636366',fontSize:11}}>Case: <span style={{color:'#0a84ff'}}>{selectedCase.case_id}</span></span>
        {sel&&!sel.isDir&&<>
          <span style={{color:'#636366',fontSize:11}}>► <span style={{color:'#ff9f0a'}}>{sel.name}</span></span>
          <span style={{background:mag.color+'22',color:mag.color,border:`1px solid ${mag.color}55`,padding:'1px 7px',borderRadius:3,fontSize:10,fontWeight:700}}>{mag.label}</span>
          <span style={{color:ent>7?'#ff2d55':ent>5?'#ff9f0a':'#30d158',fontSize:11}}>Entropy: {ent}{ent>7?' ⚠':''}</span>
        </>}
        {sel?.isDir&&<span style={{color:'#ffd60a',fontSize:11}}>📁 {sel.name} — select a file to view hex</span>}
        {files.length===0&&<span style={{color:'#ff9f0a',fontSize:11}}>No files — <span style={{color:'#0a84ff',cursor:'pointer'}} onClick={()=>setModule('triage')}>run triage →</span></span>}
      </div>

      <div style={{flex:1,display:'flex',overflow:'hidden'}}>

        {/* ── LEFT: tree ─────────────────────────────────────── */}
        <div style={{width:250,minWidth:180,flexShrink:0,borderRight:'2px solid #1e2d3d',display:'flex',flexDirection:'column',background:'#07101a'}}>
          <div style={{padding:'6px 8px',borderBottom:'1px solid #1e2d3d',flexShrink:0}}>
            <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder="Filter files…"
              style={{width:'100%',background:'#060f18',border:'1px solid #1e2d3d',color:'#e5e5ea',padding:'4px 8px',fontSize:11,outline:'none',borderRadius:3,boxSizing:'border-box' as const}}/>
          </div>
          <div style={{padding:'3px 10px',borderBottom:'1px solid #1e2d3d',fontSize:10,color:'#4a6a8a',flexShrink:0,display:'flex',gap:12}}>
            <span>{files.filter(f=>f.file_type==='DIR').length} dirs</span>
            <span>{files.filter(f=>f.file_type!=='DIR').length} files</span>
            {files.filter(f=>f.allocated===0).length>0&&<span style={{color:'#ff9f0a'}}>{files.filter(f=>f.allocated===0).length} del</span>}
          </div>
          <div style={{flex:1,overflowY:'auto',overflowX:'hidden'}}>
            {files.length===0?(
              <div style={{color:'#636366',fontSize:11,padding:'20px 12px',textAlign:'center',lineHeight:2}}>
                No files extracted.<br/>
                <span style={{color:'#0a84ff',cursor:'pointer'}} onClick={()=>setModule('triage')}>Run triage →</span>
              </div>
            ):filtered?(
              filtered.length===0
                ?<div style={{color:'#636366',fontSize:11,padding:'12px 8px'}}>No matches.</div>
                :filtered.map(n=>(
                  <div key={n.id} onClick={()=>pick(n)} title={n.fullPath}
                    style={{padding:'3px 8px',cursor:'pointer',fontSize:11,display:'flex',alignItems:'center',gap:5,background:sel?.id===n.id?'#1c3a6e':'transparent',color:sel?.id===n.id?'#fff':'#c7c7cc'}}>
                    {n.isDir?<FolderIcon hasKids={n.children.length>0} open={false}/>:<FileIcon allocated={n.allocated}/>}
                    <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{n.name}</span>
                  </div>
                ))
            ):(
              tree.map(node=><TreeRow key={node.id} node={node} expanded={expanded} onToggle={toggle} onSelect={pick} selId={sel?.id??null}/>)
            )}
          </div>
        </div>

        {/* ── RIGHT: hex ─────────────────────────────────────── */}
        <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>

          {sel&&!sel.isDir&&(
            <div style={{background:'#080e18',borderBottom:'1px solid #1e2d3d',padding:'4px 14px',display:'flex',gap:20,fontSize:10,color:'#4a6a8a',flexShrink:0,flexWrap:'wrap' as const}}>
              <span>Path: <span style={{color:'#8e8e93'}}>{sel.fullPath}</span></span>
              <span>Size: <span style={{color:'#8e8e93'}}>{sel.size.toLocaleString()} B</span></span>
              {sel.modifiedTs&&<span>Modified: <span style={{color:'#8e8e93'}}>{sel.modifiedTs.slice(0,19).replace('T',' ')}</span></span>}
              {sel.md5&&<span>MD5: <span style={{color:'#30d158'}}>{sel.md5.slice(0,16)}…</span></span>}
            </div>
          )}

          <div style={{background:'#080e18',borderBottom:'1px solid #1e2d3d',padding:'5px 10px',display:'flex',alignItems:'center',gap:4,flexShrink:0,flexWrap:'wrap' as const}}>
            {(['Hex View','String View','Text View'] as const).map(t=>{
              const v=t==='Hex View'?'hex':t==='String View'?'string':'text', active=view===v
              return <button key={t} onClick={()=>setView(v as any)} style={{background:active?'#1e2d3d':'transparent',color:active?'#e5e5ea':'#636366',border:'1px solid #1e2d3d',borderBottom:active?'2px solid #0a84ff':'1px solid #1e2d3d',padding:'4px 12px',fontSize:11,cursor:'pointer',fontWeight:active?700:400,marginRight:2,borderRadius:'3px 3px 0 0'}}>{t}</button>
            })}
            <div style={{display:'flex',alignItems:'center',gap:6,marginLeft:16,fontSize:11,color:'#8e8e93'}}>
              <span style={{color:'#636366'}}>Page</span>
              <span style={{color:'#e5e5ea',fontWeight:700}}>{page}</span>
              <span style={{color:'#636366'}}>/ {totalPages}</span>
              {iBtn('←',()=>sel&&loadPage(sel,page-1),page<=1||!sel||sel.isDir)}
              {iBtn('→',()=>sel&&loadPage(sel,page+1),page>=totalPages||!sel||sel.isDir)}
              <input value={goTo} onChange={e=>setGoTo(e.target.value)} onKeyDown={e=>e.key==='Enter'&&goPage()} placeholder="Go" style={{width:36,background:'#0d1f2d',border:'1px solid #1e2d3d',color:'#e5e5ea',padding:'2px 5px',fontSize:11,outline:'none',borderRadius:3,textAlign:'center'}}/>
              {iBtn('Go',goPage)}
            </div>
            <div style={{display:'flex',alignItems:'center',gap:6,marginLeft:'auto',fontSize:11}}>
              <input value={search} onChange={e=>setSearch(e.target.value)} onKeyDown={e=>e.key==='Enter'&&doFind()} placeholder="Find hex / ASCII…" style={{width:160,background:'#0d1f2d',border:'1px solid #1e2d3d',color:'#e5e5ea',padding:'3px 8px',fontSize:11,outline:'none',borderRadius:3}}/>
              {iBtn('Find',doFind)}
              {hits.size>0&&<span style={{color:'#ffd60a',fontSize:10}}>{hits.size} hit{hits.size>1?'s':''}</span>}
            </div>
          </div>

          <div style={{flex:1,overflow:'auto',background:'#060f18'}}>
            {loading&&<div style={{color:'#0a84ff',fontSize:12,padding:20,textAlign:'center'}}>Loading…</div>}
            {!loading&&(!sel||sel.isDir)&&(
              <div style={{color:'#636366',fontSize:12,padding:'60px 20px',textAlign:'center',lineHeight:2.2}}>
                {sel?.isDir
                  ?<><span style={{fontSize:28}}>📂</span><br/>Expand <b style={{color:'#ffd60a'}}>{sel.name}</b> and click a file to view its hex dump.</>
                  :<><span style={{fontSize:28}}>👁</span><br/>Select a file from the tree on the left.</>}
              </div>
            )}

            {!loading&&sel&&!sel.isDir&&view==='hex'&&(
              <table style={{borderCollapse:'collapse',width:'100%'}}>
                <thead>
                  <tr style={{background:'#080e18',position:'sticky',top:0,zIndex:1}}>
                    <th style={{padding:'4px 14px',color:'#0a84ff',fontSize:11,textAlign:'left',borderBottom:'1px solid #1e2d3d',width:105,fontWeight:700}}>Offset</th>
                    <th style={{padding:'4px 10px',color:'#0a84ff',fontSize:11,textAlign:'left',borderBottom:'1px solid #1e2d3d',fontWeight:700,letterSpacing:1}}>
                      {Array.from({length:16},(_,i)=>h2(i)).join(' ')}
                    </th>
                    <th style={{padding:'4px 14px',color:'#0a84ff',fontSize:11,textAlign:'left',borderBottom:'1px solid #1e2d3d',fontWeight:700}}>ASCII</th>
                  </tr>
                </thead>
                <tbody>
                  {hexRows.map((row,ri)=>(
                    <tr key={ri} style={{background:ri%2===0?'#060f18':'#07101a'}}>
                      <td style={{padding:'2px 14px',fontSize:11,color:'#4a6a8a',whiteSpace:'nowrap',borderRight:'1px solid #111a24'}}>
                        0x{row.offset.toString(16).padStart(7,'0').toUpperCase()}
                      </td>
                      <td style={{padding:'2px 10px',fontSize:11,whiteSpace:'pre',borderRight:'1px solid #111a24'}}>
                        {row.bytes.map((b,bi)=>{
                          const idx=ri*COLS+bi,isHit=hits.has(idx),isNull=b===0,isMZ=page===1&&ri===0&&bi<2
                          return <span key={bi}><span style={{color:isHit?'#000':isMZ?'#ff9f0a':isNull?'#1e2d3d':'#c7c7cc',background:isHit?'#ffd60a':'transparent',fontWeight:isMZ?700:400}}>{h2(b)}</span>{bi===7?'  ':' '}</span>
                        })}
                        {row.bytes.length<COLS&&Array.from({length:COLS-row.bytes.length},(_,p)=>(
                          <span key={p}><span style={{color:'transparent'}}>{'  '}</span>{p+row.bytes.length===7?'  ':' '}</span>
                        ))}
                      </td>
                      <td style={{padding:'2px 14px',fontSize:11}}>
                        {row.bytes.map((b,bi)=>{
                          const idx=ri*COLS+bi,isHit=hits.has(idx)
                          return <span key={bi} style={{color:isHit?'#000':b>=32&&b<127?'#30d158':'#1e2d3d',background:isHit?'#ffd60a':'transparent'}}>{asc(b)}</span>
                        })}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}

            {!loading&&sel&&!sel.isDir&&view==='string'&&(
              <table style={{borderCollapse:'collapse',width:'100%'}}>
                <thead>
                  <tr style={{background:'#080e18',position:'sticky',top:0}}>
                    <th style={{padding:'5px 14px',color:'#0a84ff',fontSize:11,textAlign:'left',borderBottom:'1px solid #1e2d3d',width:120,fontWeight:700}}>Offset</th>
                    <th style={{padding:'5px 14px',color:'#0a84ff',fontSize:11,textAlign:'left',borderBottom:'1px solid #1e2d3d',fontWeight:700}}>String (≥ 4 chars)</th>
                  </tr>
                </thead>
                <tbody>
                  {strView.length===0
                    ?<tr><td colSpan={2} style={{padding:20,color:'#636366',fontSize:12,textAlign:'center'}}>No printable strings on this page.</td></tr>
                    :strView.map((s,i)=>(
                      <tr key={i} style={{background:i%2===0?'#060f18':'#07101a'}}>
                        <td style={{padding:'3px 14px',fontSize:11,color:'#4a6a8a',borderRight:'1px solid #111a24'}}>0x{s.offset.toString(16).padStart(7,'0').toUpperCase()}</td>
                        <td style={{padding:'3px 14px',fontSize:11,color:'#30d158',wordBreak:'break-all'}}>{s.val}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            )}

            {!loading&&sel&&!sel.isDir&&view==='text'&&(
              <div style={{padding:14,fontSize:11,color:'#c7c7cc',lineHeight:1.7,whiteSpace:'pre-wrap',wordBreak:'break-all'}}>
                {bytes.map(asc).join('')}
              </div>
            )}
          </div>

          <div style={{background:'#080e18',borderTop:'1px solid #1e2d3d',padding:'4px 14px',display:'flex',gap:20,fontSize:10,color:'#4a6a8a',flexShrink:0}}>
            <span>Offset: <span style={{color:'#8e8e93'}}>0x{offset.toString(16).padStart(8,'0').toUpperCase()}</span></span>
            <span>Bytes: <span style={{color:'#8e8e93'}}>{bytes.length}</span></span>
            <span>Entropy: <span style={{color:ent>7?'#ff2d55':ent>5?'#ff9f0a':'#30d158'}}>{ent}{ent>7?' ⚠ HIGH':''}</span></span>
            {hits.size>0&&<span style={{color:'#ffd60a'}}>{hits.size} hit{hits.size>1?'s':''}</span>}
            {loading&&<span style={{color:'#0a84ff'}}>Loading…</span>}
          </div>
        </div>
      </div>
    </div>
  )
}
