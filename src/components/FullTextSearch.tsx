import { useState, useEffect, useRef, useCallback } from 'react'
import { api } from '../api/fctt-client'
import { Card, SectionTitle, Btn } from './shared'
import type { SharedProps } from '../App'

type ResultRow = { file_id: string; name: string; full_path: string; source: string; snippet: string }

function highlight(text: string, query: string) {
  if (!query.trim() || !text) return <>{text}</>
  const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const re = new RegExp(`(${escaped})`, 'gi')
  return <>{text.split(re).map((p, i) =>
    re.test(p)
      ? <mark key={i} style={{ background: '#ffd60a33', color: '#ffd60a', borderRadius: 2, padding: '0 1px' }}>{p}</mark>
      : <span key={i}>{p}</span>
  )}</>
}

function srcMeta(source: string) {
  const m: Record<string, [string, string]> = {
    disk:    ['💾', '#0a84ff'],
    memory:  ['🧠', '#bf5af2'],
    yara:    ['🎯', '#ff9f0a'],
    ioc:     ['⚠️',  '#ff2d55'],
    log:     ['📋', '#30d158'],
    network: ['🌐', '#64d2ff'],
  }
  return m[source] ?? ['📄', '#636366']
}

export default function FullTextSearch({ selectedCase, setModule }: SharedProps) {
  const [inputVal, setInputVal]   = useState('')
  const [q, setQ]                 = useState('')
  const [results, setResults]     = useState<ResultRow[]>([])
  const [total, setTotal]         = useState(0)
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState<string | null>(null)
  const [searched, setSearched]   = useState(false)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const inputRef    = useRef<HTMLInputElement>(null)

  useEffect(() => { inputRef.current?.focus() }, [])

  const doSearch = useCallback(async (query: string) => {
    if (!selectedCase) { setError('No case selected.'); return }
    if (!query.trim()) { setResults([]); setTotal(0); setSearched(false); return }
    setLoading(true); setError(null)
    try {
      const data = await api.search(selectedCase.case_id, query.trim())
      setResults(data.results || [])
      setTotal(data.count ?? data.results?.length ?? 0)
      setSearched(true)
    } catch (e: any) {
      setError(e?.message || 'Search failed. Ensure triage has been run for this case.')
      setResults([]); setTotal(0)
    } finally {
      setLoading(false)
    }
  }, [selectedCase])

  const handleInput = (val: string) => {
    setInputVal(val)
    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (!val.trim()) { setResults([]); setTotal(0); setSearched(false); setQ(''); return }
    debounceRef.current = setTimeout(() => { setQ(val); doSearch(val) }, 400)
  }

  const handleSubmit = () => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    setQ(inputVal); doSearch(inputVal)
  }

  // Group by source
  const grouped = results.reduce((acc, r) => {
    const k = r.source || 'disk'
    if (!acc[k]) acc[k] = []
    acc[k].push(r); return acc
  }, {} as Record<string, ResultRow[]>)

  const srcOrder = ['disk', 'memory', 'yara', 'ioc', 'log', 'network']
  const groups = Object.keys(grouped).sort((a, b) => srcOrder.indexOf(a) - srcOrder.indexOf(b))

  return (
    <div style={{ fontFamily: "'Inter','Segoe UI',sans-serif" }}>
      <SectionTitle icon="🔍" title="Keyword Search" badge={searched ? `${total} results` : undefined} />

      <Card>
        {/* search bar */}
        <div style={{ display: 'flex', gap: 10, marginBottom: 12 }}>
          <div style={{ flex: 1, position: 'relative' }}>
            <span style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', fontSize: 14, pointerEvents: 'none' }}>🔍</span>
            <input
              ref={inputRef}
              value={inputVal}
              onChange={e => handleInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="Search filenames, paths, file contents, YARA hits…"
              style={{ width: '100%', boxSizing: 'border-box', background: '#060f18', border: '1px solid #1e2d3d', color: '#e5e5ea', borderRadius: 6, padding: '11px 36px', fontSize: 14, outline: 'none', fontFamily: 'inherit' }}
            />
            {inputVal && (
              <span onClick={() => { setInputVal(''); setQ(''); setResults([]); setTotal(0); setSearched(false); inputRef.current?.focus() }}
                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', cursor: 'pointer', color: '#636366', fontSize: 16 }}>✕</span>
            )}
          </div>
          <Btn onClick={handleSubmit} disabled={loading || !inputVal.trim()} style={{ padding: '11px 22px', fontSize: 13, whiteSpace: 'nowrap' }}>
            {loading ? '…' : 'Search'}
          </Btn>
        </div>

        {/* source filter chips */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 16 }}>
          {(['disk', 'memory', 'yara', 'ioc', 'log'] as const).map(src => {
            const [icon, color] = srcMeta(src)
            const count = grouped[src]?.length
            return (
              <span key={src} style={{ fontSize: 10, padding: '3px 10px', borderRadius: 99, background: count ? '#1e2d3d' : '#0d1f2d', color: count ? color : '#4a6a8a', border: `1px solid ${count ? color + '44' : '#1e2d3d'}`, fontWeight: count ? 600 : 400, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                {icon} {src}{count ? ` · ${count}` : ''}
              </span>
            )
          })}
        </div>

        {/* states */}
        {!selectedCase && (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#636366' }}>
            <div style={{ fontSize: 32, marginBottom: 10 }}>🔍</div>
            <div style={{ marginBottom: 12 }}>No case selected</div>
            <Btn onClick={() => setModule('cases')}>Select a Case →</Btn>
          </div>
        )}

        {selectedCase && !loading && !searched && !error && (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#636366', fontSize: 13, lineHeight: 2.2 }}>
            <div style={{ fontSize: 36, marginBottom: 10 }}>🗂</div>
            Search across <b style={{ color: '#e5e5ea' }}>file names</b> · <b style={{ color: '#e5e5ea' }}>paths</b> · <b style={{ color: '#e5e5ea' }}>file contents</b><br />
            <b style={{ color: '#e5e5ea' }}>YARA hits</b> · <b style={{ color: '#e5e5ea' }}>memory artifacts</b><br />
            <span style={{ fontSize: 11, color: '#4a6a8a', marginTop: 4, display: 'block' }}>
              Powered by SQLite FTS5 · Run triage first to build the index
            </span>
          </div>
        )}

        {loading && (
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#0a84ff', fontSize: 14 }}>
            <div style={{ fontSize: 32, marginBottom: 10, animation: 'spin 1s linear infinite' }}>⏳</div>
            Searching…
          </div>
        )}

        {error && (
          <div style={{ background: '#2a0a0a', border: '1px solid #ff2d5533', borderRadius: 6, padding: '12px 16px', color: '#ff6b6b', fontSize: 12, marginBottom: 12 }}>
            ⚠ {error}
          </div>
        )}

        {searched && !loading && results.length === 0 && !error && (
          <div style={{ textAlign: 'center', padding: '30px 20px', color: '#636366', fontSize: 13 }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>🤷</div>
            No results for <span style={{ color: '#ffd60a' }}>"{q}"</span>
            <div style={{ fontSize: 11, marginTop: 8, color: '#4a6a8a' }}>
              Try a shorter term · check that triage has been run · the index covers filenames, paths, and text file contents
            </div>
          </div>
        )}

        {/* results grouped by source */}
        {searched && results.length > 0 && (
          <>
            <div style={{ fontSize: 11, color: '#636366', marginBottom: 14 }}>
              <span style={{ color: '#e5e5ea', fontWeight: 600 }}>{total}</span> results for{' '}
              <span style={{ color: '#ffd60a' }}>"{q}"</span>
            </div>

            {groups.map(src => {
              const [icon, color] = srcMeta(src)
              const items = grouped[src]
              return (
                <div key={src} style={{ marginBottom: 20 }}>
                  {/* group header */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8, paddingBottom: 5, borderBottom: '1px solid #1e2d3d' }}>
                    <span style={{ fontSize: 14 }}>{icon}</span>
                    <span style={{ fontSize: 11, fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: 1 }}>{src}</span>
                    <span style={{ fontSize: 10, color: '#4a6a8a', marginLeft: 'auto' }}>{items.length} match{items.length !== 1 ? 'es' : ''}</span>
                  </div>

                  {items.map((r, i) => (
                    <div key={r.file_id || i}
                      style={{ background: '#060f18', borderRadius: 5, padding: '9px 12px', marginBottom: 6, border: '1px solid #1a2a3a', display: 'flex', gap: 10, alignItems: 'flex-start' }}
                      onMouseEnter={e => (e.currentTarget as HTMLDivElement).style.borderColor = color + '55'}
                      onMouseLeave={e => (e.currentTarget as HTMLDivElement).style.borderColor = '#1a2a3a'}
                    >
                      {/* icon */}
                      <span style={{ fontSize: 15, flexShrink: 0, marginTop: 1 }}>
                        {src === 'disk' ? (r.full_path?.endsWith('/') ? '📁' : '📄') : icon}
                      </span>

                      <div style={{ flex: 1, minWidth: 0 }}>
                        {/* filename */}
                        <div style={{ fontSize: 12, color: '#e5e5ea', fontWeight: 600, fontFamily: "'Consolas','Courier New',monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {highlight(r.name || r.full_path || '(unnamed)', q)}
                        </div>

                        {/* full path */}
                        {r.full_path && r.full_path !== r.name && (
                          <div style={{ fontSize: 10, color: '#4a6a8a', fontFamily: "'Consolas','Courier New',monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>
                            {r.full_path}
                          </div>
                        )}

                        {/* content snippet */}
                        {r.snippet && (
                          <div style={{ fontSize: 11, color: '#8e8e93', marginTop: 4, fontFamily: "'Consolas','Courier New',monospace", lineHeight: 1.5, wordBreak: 'break-all' }}
                            dangerouslySetInnerHTML={{ __html: r.snippet.replace(/<b>/g, '<b style="color:#ffd60a;background:#ffd60a22">').replace(/<\/b>/g, '</b>') }}
                          />
                        )}
                      </div>

                      {/* source badge */}
                      <span style={{ fontSize: 9, color, background: color + '18', border: `1px solid ${color}33`, borderRadius: 3, padding: '2px 6px', flexShrink: 0, alignSelf: 'flex-start', marginTop: 2, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                        {src}
                      </span>
                    </div>
                  ))}
                </div>
              )
            })}
          </>
        )}
      </Card>
    </div>
  )
}
