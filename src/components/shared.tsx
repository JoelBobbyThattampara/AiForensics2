// ─── Shared UI Components for FCTT ───────────────────────────────────────────

import { ReactNode } from 'react'

export const RiskBadge = ({ score }: { score: number }) => {
  const color = score >= 90 ? '#ff2d55' : score >= 70 ? '#ff9f0a' : score >= 40 ? '#ffd60a' : '#30d158'
  const label = score >= 90 ? 'CRITICAL' : score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : 'LOW'
  return (
    <span style={{ background: color + '22', color, border: `1px solid ${color}55`, padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>
      {label}
    </span>
  )
}

export const RiskMeter = ({ score }: { score: number }) => {
  const color = score >= 90 ? '#ff2d55' : score >= 70 ? '#ff9f0a' : score >= 40 ? '#ffd60a' : '#30d158'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 5, background: '#1e2d3d', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.8s ease' }} />
      </div>
      <span style={{ color, fontSize: 11, fontWeight: 700, minWidth: 26 }}>{score}</span>
    </div>
  )
}

export const StatusDot = ({ status }: { status: string }) => {
  const colors: Record<string, string> = { Active: '#30d158', Review: '#ffd60a', Closed: '#636366', Running: '#0a84ff' }
  const c = colors[status] || '#636366'
  return <span style={{ display: 'inline-block', width: 7, height: 7, borderRadius: '50%', background: c, marginRight: 5, boxShadow: `0 0 5px ${c}` }} />
}

export const Tag = ({ label, color = '#0a84ff' }: { label: string; color?: string }) => (
  <span style={{ background: color + '22', color, border: `1px solid ${color}44`, padding: '1px 6px', borderRadius: 3, fontSize: 10, fontWeight: 600 }}>
    {label}
  </span>
)

export const TypeTag = ({ type }: { type: string }) => {
  const colors: Record<string, string> = {
    PROCESS: '#bf5af2', NETWORK: '#0a84ff', FILE: '#30d158',
    REGISTRY: '#ffd60a', LOG: '#636366', Memory: '#bf5af2',
    Disk: '#30d158', PCAP: '#0a84ff', EventLog: '#ff9f0a',
    IP: '#ff2d55', HASH: '#ff9f0a', DOMAIN: '#ffd60a', YARA: '#bf5af2',
  }
  return <Tag label={type} color={colors[type] || '#636366'} />
}

export const Card = ({ children, style = {} }: { children: ReactNode; style?: React.CSSProperties }) => (
  <div style={{ background: '#0d1f2d', border: '1px solid #1e2d3d', borderRadius: 8, padding: 16, ...style }}>
    {children}
  </div>
)

export const SectionTitle = ({ icon, title, badge }: { icon: string; title: string; badge?: string | number }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
    <span style={{ color: '#0a84ff', fontSize: 14 }}>{icon}</span>
    <span style={{ color: '#e5e5ea', fontWeight: 700, fontSize: 13 }}>{title}</span>
    {badge !== undefined && (
      <span style={{ background: '#ff2d5522', color: '#ff2d55', border: '1px solid #ff2d5544', padding: '1px 8px', borderRadius: 10, fontSize: 10, fontWeight: 700 }}>
        {badge}
      </span>
    )}
  </div>
)

export const TH = ({ children }: { children: ReactNode }) => (
  <th style={{ color: '#636366', padding: '8px 12px', textAlign: 'left', borderBottom: '1px solid #1e2d3d', fontWeight: 600, fontSize: 10, letterSpacing: 0.5 }}>
    {children}
  </th>
)

export const TD = ({ children, style = {} }: { children: ReactNode; style?: React.CSSProperties }) => (
  <td style={{ padding: '9px 12px', borderBottom: '1px solid #0d1f2d', color: '#c7c7cc', fontSize: 12, ...style }}>
    {children}
  </td>
)

export const Btn = ({ children, onClick, color = '#0a84ff', disabled = false, style = {} }: {
  children: ReactNode; onClick?: () => void; color?: string; disabled?: boolean; style?: React.CSSProperties
}) => (
  <button onClick={onClick} disabled={disabled} style={{
    background: disabled ? '#1e2d3d' : color,
    color: disabled ? '#636366' : '#fff',
    border: 'none', padding: '8px 16px', borderRadius: 6,
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontSize: 12, fontWeight: 700, ...style
  }}>
    {children}
  </button>
)

export const Input = ({ style = {}, ...props }: React.InputHTMLAttributes<HTMLInputElement>) => (
  <input style={{ background: '#0d1f2d', border: '1px solid #1e2d3d', color: '#e5e5ea', padding: '8px 12px', borderRadius: 6, fontSize: 13, width: '100%', outline: 'none', ...style }} {...props} />
)

export const Select = ({ children, style = {}, ...props }: React.SelectHTMLAttributes<HTMLSelectElement> & { children: ReactNode }) => (
  <select style={{ background: '#0d1f2d', border: '1px solid #1e2d3d', color: '#e5e5ea', padding: '8px 12px', borderRadius: 6, fontSize: 13, width: '100%', outline: 'none', ...style }} {...props}>
    {children}
  </select>
)

export const AIGauge = ({ score }: { score: number }) => {
  const r = 52, cx = 64, cy = 64, c = 2 * Math.PI * r
  const color = score >= 90 ? '#ff2d55' : score >= 70 ? '#ff9f0a' : score >= 40 ? '#ffd60a' : '#30d158'
  return (
    <div style={{ position: 'relative', width: 128, height: 128, margin: '0 auto' }}>
      <svg width="128" height="128" viewBox="0 0 128 128">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d3d" strokeWidth="10" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="10"
          strokeDasharray={`${(score / 100) * c} ${c}`} strokeLinecap="round"
          transform="rotate(-90 64 64)" style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dasharray 1.5s ease' }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span style={{ color, fontSize: 26, fontWeight: 800 }}>{score}</span>
        <span style={{ color: '#636366', fontSize: 9, letterSpacing: 2 }}>AI RISK</span>
      </div>
    </div>
  )
}

export const HexViewer = () => {
  const bytes = Array.from({ length: 256 }, (_, i) => i)
  return (
    <div style={{ fontFamily: 'monospace', fontSize: 11, color: '#98989d', lineHeight: 1.8, background: '#060f18', borderRadius: 6, padding: 12, overflow: 'auto' }}>
      <div style={{ display: 'flex', gap: 16, color: '#0a84ff', fontSize: 10, paddingBottom: 4, borderBottom: '1px solid #1e2d3d', marginBottom: 4 }}>
        <span style={{ width: 70 }}>OFFSET</span>
        <span style={{ flex: 1 }}>00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</span>
        <span>ASCII</span>
      </div>
      {Array.from({ length: 16 }, (_, row) => {
        const rb = bytes.slice(row * 16, (row + 1) * 16)
        return (
          <div key={row} style={{ display: 'flex', gap: 16 }}>
            <span style={{ color: '#636366', width: 70 }}>{(row * 16).toString(16).padStart(8, '0').toUpperCase()}</span>
            <span style={{ flex: 1, color: '#e5e5ea' }}>{rb.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ')}</span>
            <span style={{ color: '#30d158' }}>{rb.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('')}</span>
          </div>
        )
      })}
    </div>
  )
}

export const ProgressBar = ({ progress, color = '#0a84ff', height = 6 }: { progress: number; color?: string; height?: number }) => (
  <div style={{ height, background: '#1e2d3d', borderRadius: height / 2, overflow: 'hidden' }}>
    <div style={{ height: '100%', width: `${progress}%`, background: color, borderRadius: height / 2, transition: 'width 0.2s ease' }} />
  </div>
)

// Mock data exported for use across components
export const MOCK_CASES = []

export const MOCK_PROCESSES = []

export const MOCK_NETWORK = [
  { pid: 3412, process: 'powershell.exe', proto: 'TCP', local: '192.168.1.105:49823', remote: '185.234.219.43:443', state: 'ESTABLISHED', country: 'RU', risk: 91 },
  { pid: 688, process: 'svchost.exe', proto: 'TCP', local: '0.0.0.0:135', remote: '*:*', state: 'LISTENING', country: '-', risk: 3 },
  { pid: 3520, process: 'mimikatz.exe', proto: 'TCP', local: '192.168.1.105:49901', remote: '91.108.4.22:8443', state: 'ESTABLISHED', country: 'NL', risk: 97 },
]

export const MOCK_TIMELINE = [
  { ts: '2024-03-15 02:14:33', type: 'PROCESS', src: 'Memory', event: 'mimikatz.exe spawned by powershell.exe (PID 3412)', risk: 'Critical' },
  { ts: '2024-03-15 02:14:35', type: 'NETWORK', src: 'PCAP', event: 'Outbound C2 connection to 185.234.219.43:443 established', risk: 'Critical' },
  { ts: '2024-03-15 02:13:11', type: 'FILE', src: 'Disk', event: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\p0wn.exe written', risk: 'High' },
  { ts: '2024-03-15 02:11:44', type: 'REGISTRY', src: 'Disk', event: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run modified', risk: 'High' },
  { ts: '2024-03-15 01:58:02', type: 'LOG', src: 'EventLog', event: '4624 - Logon Type 3 from 192.168.1.200 as CORP\\jsmith', risk: 'Medium' },
  { ts: '2024-03-15 01:55:17', type: 'FILE', src: 'Disk', event: 'C:\\Windows\\System32\\drivers\\unknown_drv.sys created', risk: 'High' },
  { ts: '2024-03-15 01:48:30', type: 'PROCESS', src: 'Memory', event: 'cmd.exe spawned by explorer.exe with encoded args', risk: 'Medium' },
  { ts: '2024-03-14 23:30:11', type: 'LOG', src: 'EventLog', event: '4625 - Failed logon attempts x47 for CORP\\jsmith', risk: 'Medium' },
]

export const MOCK_IOCS = [
  { type: 'IP', value: '185.234.219.43', confidence: 97, rule: 'APT29_C2_Infrastructure', tags: ['APT29', 'C2', 'RU'] },
  { type: 'HASH', value: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', confidence: 100, rule: 'Mimikatz_Gen', tags: ['Credential Dumping'] },
  { type: 'DOMAIN', value: 'update-service-patch.net', confidence: 83, rule: 'Phishing_Domain_Pattern', tags: ['Phishing', 'Lookalike'] },
  { type: 'YARA', value: 'Suspicious_PS_Encoded_CMD', confidence: 76, rule: 'Encoded_Powershell_Execution', tags: ['Obfuscation'] },
]

export const MOCK_FILES = [
  { name: 'p0wn.exe', path: 'C:\\Users\\jsmith\\AppData\\Local\\Temp\\', size: '284 KB', type: 'PE32', sha256: 'a1b2c3d4...', status: 'Deleted', risk: 99 },
  { name: 'unknown_drv.sys', path: 'C:\\Windows\\System32\\drivers\\', size: '48 KB', type: 'PE32 driver', sha256: 'b2c3d4e5...', status: 'Allocated', risk: 95 },
  { name: 'lsass.dmp', path: 'C:\\Windows\\Temp\\', size: '38 MB', type: 'Dump', sha256: 'd4e5f6a1...', status: 'Deleted', risk: 88 },
]
