import { useState, useEffect } from 'react'
import { api } from '../api/fctt-client'
import type { CaseRecord } from '../api/fctt-client'
import { Card, SectionTitle, StatusDot, Tag, Btn, Input } from './shared'
import type { SharedProps } from '../App'

export default function CaseManager({ selectedCase, setSelectedCase, setModule, notify, cases, setCases, loadCases }: SharedProps) {
  const [showNew, setShowNew]       = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<CaseRecord | null>(null)
  const [deleting, setDeleting]     = useState<string | null>(null)
  const [creating, setCreating]     = useState(false)
  const [form, setForm]             = useState({ number: '', name: '', investigator: '', desc: '' })
  const [formError, setFormError]   = useState('')

  useEffect(() => { loadCases() }, [])

  const createCase = async () => {
    if (!form.name.trim()) { setFormError('Case name is required.'); return }
    if (!form.number.trim()) { setFormError('Case number is required.'); return }
    setFormError(''); setCreating(true)
    try {
      await api.createCase({
        case_number: form.number.trim(),
        case_name: form.name.trim(),
        description: form.desc.trim(),
        investigators: form.investigator ? [form.investigator.trim()] : [],
      })
      await loadCases()
      setShowNew(false)
      setForm({ number: '', name: '', investigator: '', desc: '' })
      notify('Case created successfully.', 'success')
    } catch (e: any) {
      setFormError(e?.message || 'Failed to create case.')
    } finally {
      setCreating(false)
    }
  }

  const deleteCase = async (c: CaseRecord) => {
    setDeleting(c.case_id)
    try {
      await api.deleteCase(c.case_id)
      if (selectedCase?.case_id === c.case_id) setSelectedCase(null)
      await loadCases()
      notify(`Case ${c.case_id} deleted.`, 'success')
    } catch (e: any) {
      notify(e?.message || 'Failed to delete case.', 'error')
    } finally {
      setDeleting(null)
      setConfirmDelete(null)
    }
  }

  const statusColor = (s: string) =>
    s === 'Active' ? '#30d158' : s === 'Closed' ? '#636366' : '#ffd60a'

  return (
    <div style={{ fontFamily: "'Inter','Segoe UI',sans-serif" }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <SectionTitle icon="🗂️" title="Case Management" badge={cases.length > 0 ? `${cases.length} cases` : undefined} />
        <Btn onClick={() => { setShowNew(p => !p); setFormError('') }}>＋ New Case</Btn>
      </div>

      {/* ── New case form ── */}
      {showNew && (
        <Card style={{ marginBottom: 18, borderColor: '#0a84ff44' }}>
          <SectionTitle icon="📁" title="New Case" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 12 }}>
            {([
              ['Case Number', 'number', 'FCT-2024-001'],
              ['Case Name',   'name',   'Investigation Title'],
              ['Lead Investigator', 'investigator', 'Your Name'],
              ['Description', 'desc', 'Brief description…'],
            ] as const).map(([label, key, ph]) => (
              <div key={key}>
                <label style={{ color: '#636366', fontSize: 10, display: 'block', marginBottom: 4, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</label>
                <Input placeholder={ph} value={(form as any)[key]} onChange={e => setForm(p => ({ ...p, [key]: e.target.value }))} />
              </div>
            ))}
          </div>
          {formError && (
            <div style={{ color: '#ff6b6b', fontSize: 12, marginBottom: 10 }}>⚠ {formError}</div>
          )}
          <div style={{ display: 'flex', gap: 10 }}>
            <Btn onClick={createCase} disabled={creating}>{creating ? 'Creating…' : 'Create Case'}</Btn>
            <Btn color="#1e2d3d" onClick={() => { setShowNew(false); setFormError('') }}>Cancel</Btn>
          </div>
        </Card>
      )}

      {/* ── Delete confirmation modal ── */}
      {confirmDelete && (
        <div style={{ position: 'fixed', inset: 0, background: '#000000cc', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ background: '#0d1f2d', border: '1px solid #ff2d5566', borderRadius: 10, padding: 28, maxWidth: 400, width: '90%' }}>
            <div style={{ fontSize: 28, marginBottom: 12, textAlign: 'center' }}>🗑️</div>
            <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 8, textAlign: 'center' }}>Delete Case?</div>
            <div style={{ color: '#8e8e93', fontSize: 13, marginBottom: 6, textAlign: 'center' }}>
              This will permanently delete
            </div>
            <div style={{ color: '#0a84ff', fontFamily: 'monospace', fontSize: 13, marginBottom: 6, textAlign: 'center', fontWeight: 700 }}>
              {confirmDelete.case_id}
            </div>
            <div style={{ color: '#e5e5ea', fontSize: 13, marginBottom: 20, textAlign: 'center' }}>
              "{confirmDelete.case_name}"
            </div>
            <div style={{ color: '#ff6b6b', fontSize: 11, marginBottom: 20, textAlign: 'center', background: '#ff2d5511', border: '1px solid #ff2d5533', borderRadius: 6, padding: '8px 12px' }}>
              ⚠ All evidence, triage data, files, YARA hits, and timeline events will be permanently lost. This cannot be undone.
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button
                onClick={() => deleteCase(confirmDelete)}
                disabled={deleting === confirmDelete.case_id}
                style={{ flex: 1, background: '#ff2d55', border: 'none', color: '#fff', borderRadius: 6, padding: '10px 0', fontSize: 13, fontWeight: 700, cursor: 'pointer' }}
              >
                {deleting === confirmDelete.case_id ? 'Deleting…' : 'Yes, Delete Permanently'}
              </button>
              <button
                onClick={() => setConfirmDelete(null)}
                style={{ flex: 1, background: '#1e2d3d', border: '1px solid #2a3d4d', color: '#c7c7cc', borderRadius: 6, padding: '10px 0', fontSize: 13, cursor: 'pointer' }}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Case list ── */}
      {cases.length === 0 ? (
        <Card>
          <div style={{ textAlign: 'center', padding: '40px 20px', color: '#636366' }}>
            <div style={{ fontSize: 36, marginBottom: 12 }}>🗂️</div>
            <div style={{ marginBottom: 16 }}>No cases yet. Create your first case to get started.</div>
            <Btn onClick={() => setShowNew(true)}>＋ Create First Case</Btn>
          </div>
        </Card>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 14 }}>
          {cases.map(c => {
            const isSelected = selectedCase?.case_id === c.case_id
            const isDeleting = deleting === c.case_id
            return (
              <Card
                key={c.case_id}
                style={{
                  cursor: 'pointer',
                  borderColor: isSelected ? '#0a84ff88' : '#1e2d3d',
                  opacity: isDeleting ? 0.5 : 1,
                  transition: 'border-color 0.15s',
                  position: 'relative',
                }}
                onClick={() => !isDeleting && setSelectedCase(c)}
              >
                {/* selected indicator */}
                {isSelected && (
                  <div style={{ position: 'absolute', top: 0, left: 0, width: 3, height: '100%', background: '#0a84ff', borderRadius: '6px 0 0 6px' }} />
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <span style={{ color: '#0a84ff', fontFamily: 'monospace', fontSize: 11, fontWeight: 700 }}>{c.case_id}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <StatusDot status={c.status} />
                    {/* delete button */}
                    <button
                      onClick={e => { e.stopPropagation(); setConfirmDelete(c) }}
                      disabled={isDeleting}
                      title="Delete case"
                      style={{ background: 'transparent', border: 'none', color: '#636366', cursor: 'pointer', fontSize: 14, padding: '2px 4px', borderRadius: 4, lineHeight: 1 }}
                      onMouseEnter={e => (e.currentTarget as HTMLButtonElement).style.color = '#ff2d55'}
                      onMouseLeave={e => (e.currentTarget as HTMLButtonElement).style.color = '#636366'}
                    >
                      🗑
                    </button>
                  </div>
                </div>

                <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4, color: '#e5e5ea' }}>{c.case_name}</div>
                <div style={{ color: '#636366', fontSize: 11, marginBottom: 4 }}>#{c.case_number}</div>
                {c.description && (
                  <div style={{ color: '#8e8e93', fontSize: 11, marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.description}</div>
                )}
                <div style={{ color: '#4a6a8a', fontSize: 10, marginBottom: 10 }}>
                  Created: {c.created_at ? c.created_at.slice(0, 10) : '—'}
                </div>

                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  <Tag label={c.status} color={statusColor(c.status)} />
                  {isSelected && <Tag label="Active" color="#0a84ff" />}
                </div>

                {/* go to triage shortcut */}
                {isSelected && (
                  <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid #1e2d3d', display: 'flex', gap: 8 }}>
                    <button
                      onClick={e => { e.stopPropagation(); setModule('ingestion') }}
                      style={{ flex: 1, background: '#0a84ff22', border: '1px solid #0a84ff44', color: '#0a84ff', borderRadius: 5, padding: '6px 0', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
                    >
                      + Add Evidence
                    </button>
                    <button
                      onClick={e => { e.stopPropagation(); setModule('triage') }}
                      style={{ flex: 1, background: '#30d15822', border: '1px solid #30d15844', color: '#30d158', borderRadius: 5, padding: '6px 0', fontSize: 11, cursor: 'pointer', fontWeight: 600 }}
                    >
                      ▶ Run Triage
                    </button>
                  </div>
                )}
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
