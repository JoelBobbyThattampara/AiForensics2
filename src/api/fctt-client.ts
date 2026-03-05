const BASE = '/api'

async function request<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...opts.headers },
    ...opts,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${text}`)
  }
  return res.json()
}

export const api = {
  health: () => request<HealthStatus>('/health'),
  listCases: () => request<CaseRecord[]>('/cases'),
  getCase: (id: string) => request<CaseRecord>(`/cases/${id}`),
  createCase: (data: CreateCasePayload) =>
    request<CaseRecord>('/cases', { method: 'POST', body: JSON.stringify(data) }),
  listEvidence: (caseId: string) =>
    request<EvidenceRecord[]>(`/cases/${caseId}/evidence`),
  ingestEvidence: (caseId: string, file: File, investigator = 'analyst') => {
    const fd = new FormData()
    fd.append('file', file)
    return fetch(`${BASE}/cases/${caseId}/evidence?investigator=${encodeURIComponent(investigator)}`, {
      method: 'POST', body: fd,
    }).then(async r => {
      if (!r.ok) throw new Error(`API ${r.status}: ${await r.text()}`)
      return r.json() as Promise<EvidenceRecord>
    })
  },
  runTriage: (caseId: string, evidenceId: string) =>
    request<{ task_id: string }>(`/cases/${caseId}/triage`, {
      method: 'POST',
      body: JSON.stringify({
        case_id: caseId, evidence_id: evidenceId,
        enable_ai: true, enable_carving: true,
        plugins: ['windows.pslist','windows.netscan','windows.malfind','windows.dlllist'],
      }),
    }),
  pollTask: (taskId: string) =>
    request<TaskStatus>(`/tasks/${taskId}`),
  getProcesses: (caseId: string) =>
    request<MemoryArtifact[]>(`/cases/${caseId}/processes`),
  getNetwork: (caseId: string) =>
    request<MemoryArtifact[]>(`/cases/${caseId}/network`),
  getFiles: (caseId: string) =>
    request<ExtractedFile[]>(`/cases/${caseId}/files`),
  getIOCs: (caseId: string, iocType = '') =>
    request<IOCMatch[]>(`/cases/${caseId}/iocs${iocType ? `?ioc_type=${iocType}` : ''}`),
  // PCAP
  analysePCAP: (caseId: string, evidenceId = '') =>
    request<{packets:number;bytes:number;sessions:number;iocs:number;protocols:Record<string,number>;top_talkers:any[];errors:number}>(
      `/cases/${caseId}/pcap/analyse${evidenceId ? `?evidence_id=${evidenceId}` : ''}`, {method:'POST'}),
  getPCAPSessions: (caseId: string, minRisk = 0) =>
    request<PCAPSession[]>(`/cases/${caseId}/pcap/sessions?min_risk=${minRisk}`),
  getPCAPStats: (caseId: string) =>
    request<PCAPStats>(`/cases/${caseId}/pcap/stats`),
  listYaraRules: () =>
    request<YaraRule[]>('/yara/rules'),
  saveYaraRule: (name: string, content: string) =>
    request<{saved:boolean;name:string}>(`/yara/rules?rule_name=${encodeURIComponent(name)}&content=${encodeURIComponent(content)}`, {method:'POST'}),
  deleteYaraRule: (name: string) =>
    request<{deleted:boolean}>(`/yara/rules/${encodeURIComponent(name)}`, {method:'DELETE'}),
  runYaraScan: (caseId: string) =>
    request<{scanned:boolean;hits:number;matches:Array<{rule:string;tags:string;confidence:number}>}>(`/cases/${caseId}/yara/scan`, {method:'POST'}),
  getTimeline: (caseId: string, limit = 2000, offset = 0) =>
    request<TimelineEvent[]>(`/cases/${caseId}/timeline?limit=${limit}&offset=${offset}`),
  getAIScores: (caseId: string) =>
    request<AIScore[]>(`/cases/${caseId}/ai-scores`),
  runAIScoring: (caseId: string) =>
    request<{scored:number;flagged:number;critical:number;high:number}>(`/cases/${caseId}/ai-scores/run`, {method:'POST'}),
  getCOC: (caseId: string) =>
    request<COCEntry[]>(`/cases/${caseId}/coc`),
  deleteCase: (caseId: string) =>
    request<{ deleted: boolean; case_id: string }>(`/cases/${caseId}`, { method: 'DELETE' }),
  search: (caseId: string, q: string) =>
    request<SearchResult>(`/cases/${caseId}/search?q=${encodeURIComponent(q)}`),
  generateReport: (caseId: string, reportType = 'full', fmt = 'json') =>
    request<any>(`/cases/${caseId}/report?report_type=${reportType}&fmt=${fmt}`, { method: 'POST' }),
}

export interface CaseRecord {
  case_id: string; case_number: string; case_name: string
  description?: string; created_at: string; status: string
}
export interface CreateCasePayload {
  case_number: string; case_name: string; description?: string; investigators: string[]
}
export interface EvidenceRecord {
  evidence_id: string; case_id: string; filename: string; file_size: number
  md5: string; sha256: string; acquisition_ts: string; mount_mode: string; evidence_type: string
}
export interface MemoryArtifact {
  artifact_id: string; plugin: string; pid: number; process_name: string
  ppid: number; risk_score: number; flags: string; raw_data: string; extracted_at: string
}
export interface ExtractedFile {
  file_id: string; name: string; full_path: string; size: number
  md5: string; sha256: string; modified_ts: string; allocated: number; file_type: string
}
export interface IOCMatch {
  ioc_id: string; ioc_type: string; indicator: string; rule_name: string
  confidence: number; tags: string; matched_at: string; source_artifact: string
}
export interface YaraRule {
  name: string; filename: string; size: number
  rule_count: number; content: string; valid: boolean; error?: string
}
export interface PCAPSession {
  session_id: string; case_id: string; evidence_id: string
  src_ip: string; dst_ip: string; src_port: number; dst_port: number
  protocol: string; packet_count: number; byte_count: number
  first_seen: string; last_seen: string; flags: string
  payload_preview: string; risk_score: number; tags: string
}
export interface PCAPStats {
  sessions: number; total_bytes: number; total_packets: number
  protocols: Record<string,number>
  top_talkers: Array<{ip:string;packets:number}>
  risk_counts: Record<string,number>
}
export interface TimelineEvent {
  event_id: string; timestamp: string; event_type: string; source: string
  description: string; risk_score: number; related_pid?: number; related_file?: string
}
export interface AIScore {
  score_id: string; case_id: string; artifact_ref: string
  model_name: string; score: number; classification: string
  scored_at: string
  features?: {
    name?: string; full_path?: string; size?: number
    reasons?: string[]; heuristic?: number; iso?: number
  }
}
export interface COCEntry {
  entry_id: string; action: string; actor: string; target: string
  hash_before: string; hash_after: string; notes: string; ts: string
}
export interface TaskStatus {
  task_id: string; status: 'queued'|'running'|'done'|'error'
  progress: number; message: string; result?: Record<string,unknown>
}
export interface SearchResult {
  query: string; count: number
  results: Array<{
    file_id: string; name: string; full_path: string
    source: string; snippet: string
    file_type?: string; size?: number; allocated?: number
  }>
}
export interface HealthStatus {
  status: string; version: string; engines: Record<string,boolean>; timestamp: string
}
