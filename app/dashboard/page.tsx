'use client'

import { useState, useEffect } from 'react'
import { Shield, Search, Clock, Trash2, ExternalLink, ChevronRight, Globe, Hash, Server, Link } from 'lucide-react'
import { TIResult, InputType } from '@/lib/types'

interface HistoryItem {
  id: string
  input: string
  input_type: InputType
  created_at: string
  result: TIResult
}

const TYPE_ICONS: Record<InputType, React.ReactNode> = {
  ip: <Server size={12} />,
  domain: <Globe size={12} />,
  url: <Link size={12} />,
  hash: <Hash size={12} />,
  unknown: <Search size={12} />,
}

const TYPE_COLORS: Record<InputType, string> = {
  ip: '#60a5fa',
  domain: '#34d399',
  url: '#a78bfa',
  hash: '#f59e0b',
  unknown: '#6b7280',
}

function ScoreBadge({ score, label }: { score: number; label?: string }) {
  const color = score >= 70 ? '#dc2626' : score >= 30 ? '#d97706' : '#16a34a'
  const bg = score >= 70 ? '#fef2f2' : score >= 30 ? '#fffbeb' : '#f0fdf4'
  return (
    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 500, background: bg, color }}>
      {label ?? score}
    </span>
  )
}

function VTBadge({ malicious, total }: { malicious: number; total: number }) {
  const color = malicious > 0 ? '#dc2626' : '#16a34a'
  const bg = malicious > 0 ? '#fef2f2' : '#f0fdf4'
  return (
    <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 500, background: bg, color }}>
      {malicious}/{total} engines
    </span>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, borderBottom: '0.5px solid var(--color-border-tertiary)', paddingBottom: 6 }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '5px 0', borderBottom: '0.5px solid var(--color-border-tertiary)', gap: 12 }}>
      <span style={{ fontSize: 11, color: 'var(--color-text-secondary)', flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, fontFamily: mono ? 'var(--font-mono)' : 'inherit', color: 'var(--color-text-primary)', textAlign: 'right', wordBreak: 'break-all' }}>{value}</span>
    </div>
  )
}

export default function Dashboard() {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<TIResult | null>(null)
  const [error, setError] = useState('')
  const [history, setHistory] = useState<HistoryItem[]>([])
  const [activeTab, setActiveTab] = useState<'result' | 'history'>('result')

  useEffect(() => { fetchHistory() }, [])

  const fetchHistory = async () => {
    const res = await fetch('/api/history')
    const json = await res.json()
    setHistory(Array.isArray(json) ? json : [])
  }

  const lookup = async (q?: string) => {
    const query = q ?? input
    if (!query.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    setActiveTab('result')

    const res = await fetch('/api/lookup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input: query }),
    })
    const json = await res.json()

    if (json.error) setError(json.error)
    else { setResult(json); fetchHistory() }
    setLoading(false)
  }

  const clearHistory = async () => {
    await fetch('/api/history', { method: 'DELETE' })
    setHistory([])
  }

  const sslDaysColor = (days: number) =>
    days < 7 ? '#dc2626' : days < 30 ? '#d97706' : '#16a34a'

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--color-background-tertiary)', fontFamily: 'var(--font-mono)', overflow: 'hidden' }}>

      {/* Sidebar */}
      <aside style={{ width: 260, background: 'var(--color-background-primary)', borderRight: '0.5px solid var(--color-border-tertiary)', display: 'flex', flexDirection: 'column', flexShrink: 0, overflow: 'hidden' }}>
        <div style={{ padding: '1.25rem 1rem', borderBottom: '0.5px solid var(--color-border-tertiary)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <Shield size={18} style={{ color: '#dc2626' }} />
          <span style={{ fontWeight: 500, fontSize: 14 }}>TI Aggregator</span>
        </div>

        {/* Search box */}
        <div style={{ padding: '1rem' }}>
          <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Lookup</div>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); lookup() } }}
            placeholder={'IP, domain, URL\nor file hash...'}
            rows={3}
            style={{ width: '100%', fontSize: 12, padding: '8px', border: '0.5px solid var(--color-border-secondary)', borderRadius: 6, background: 'var(--color-background-secondary)', color: 'var(--color-text-primary)', fontFamily: 'inherit', resize: 'none', boxSizing: 'border-box', outline: 'none' }}
          />
          <button onClick={() => lookup()} disabled={loading}
            style={{ marginTop: 6, width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, padding: '7px', fontSize: 12, border: '0.5px solid var(--color-border-secondary)', borderRadius: 6, background: loading ? 'var(--color-background-secondary)' : 'transparent', cursor: 'pointer', color: 'var(--color-text-primary)', fontFamily: 'inherit' }}>
            <Search size={13} />
            {loading ? 'Querying sources...' : 'Investigate'}
          </button>
          <p style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginTop: 6, marginBottom: 0 }}>
            Supports: IPv4, IPv6, domain, URL, MD5/SHA1/SHA256
          </p>
        </div>

        {/* History */}
        <div style={{ flex: 1, overflowY: 'auto', borderTop: '0.5px solid var(--color-border-tertiary)' }}>
          <div style={{ padding: '0.75rem 1rem 0.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 10, color: 'var(--color-text-tertiary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Recent</span>
            {history.length > 0 && (
              <button onClick={clearHistory} style={{ border: 'none', background: 'none', cursor: 'pointer', color: 'var(--color-text-tertiary)', display: 'flex', padding: 0 }}>
                <Trash2 size={11} />
              </button>
            )}
          </div>
          {history.length === 0 ? (
            <p style={{ fontSize: 11, color: 'var(--color-text-tertiary)', padding: '0.5rem 1rem' }}>No lookups yet</p>
          ) : (
            history.map(item => (
              <button key={item.id} onClick={() => { setResult(item.result); setInput(item.input); setActiveTab('result') }}
                style={{ width: '100%', textAlign: 'left', padding: '7px 1rem', border: 'none', borderBottom: '0.5px solid var(--color-border-tertiary)', background: result?.input === item.input ? 'var(--color-background-secondary)' : 'transparent', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: TYPE_COLORS[item.input_type], flexShrink: 0 }}>{TYPE_ICONS[item.input_type]}</span>
                <span style={{ fontSize: 11, color: 'var(--color-text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{item.input}</span>
                <ChevronRight size={10} style={{ color: 'var(--color-text-tertiary)', flexShrink: 0 }} />
              </button>
            ))
          )}
        </div>
      </aside>

      {/* Main content */}
      <main style={{ flex: 1, overflowY: 'auto', padding: '1.5rem' }}>

        {!result && !loading && !error && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 12 }}>
            <Shield size={32} style={{ color: 'var(--color-text-tertiary)' }} />
            <p style={{ fontSize: 13, color: 'var(--color-text-tertiary)', textAlign: 'center', lineHeight: 1.7 }}>
              Enter an IP, domain, URL, or file hash<br />to start an investigation
            </p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'center' }}>
              {['8.8.8.8', 'google.com', 'https://example.com'].map(ex => (
                <button key={ex} onClick={() => { setInput(ex); lookup(ex) }}
                  style={{ fontSize: 11, padding: '4px 10px', border: '0.5px solid var(--color-border-secondary)', borderRadius: 6, background: 'transparent', cursor: 'pointer', color: 'var(--color-text-secondary)', fontFamily: 'inherit' }}>
                  {ex}
                </button>
              ))}
            </div>
          </div>
        )}

        {loading && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%', gap: 16 }}>
            <div style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>Querying all sources in parallel...</div>
            <div style={{ display: 'flex', gap: 8 }}>
              {['VirusTotal', 'AbuseIPDB', 'URLScan', 'DNS', 'SSL', 'Whois'].map(s => (
                <span key={s} style={{ fontSize: 10, padding: '3px 8px', border: '0.5px solid var(--color-border-secondary)', borderRadius: 4, color: 'var(--color-text-tertiary)', animation: 'pulse 1.5s ease-in-out infinite' }}>{s}</span>
              ))}
            </div>
          </div>
        )}

        {error && (
          <div style={{ padding: '1rem', background: '#fef2f2', border: '0.5px solid #dc2626', borderRadius: 8, color: '#dc2626', fontSize: 13 }}>
            {error}
          </div>
        )}

        {result && !loading && (
          <div style={{ maxWidth: 900 }}>
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: '1.5rem' }}>
              <span style={{ color: TYPE_COLORS[result.inputType] }}>{TYPE_ICONS[result.inputType]}</span>
              <h1 style={{ fontSize: 18, fontWeight: 500, margin: 0, wordBreak: 'break-all' }}>{result.input}</h1>
              <span style={{ fontSize: 10, padding: '2px 8px', border: `0.5px solid ${TYPE_COLORS[result.inputType]}`, borderRadius: 4, color: TYPE_COLORS[result.inputType] }}>
                {result.inputType.toUpperCase()}
              </span>
              <span style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginLeft: 'auto' }}>
                {new Date(result.timestamp).toLocaleString()}
              </span>
            </div>

            {/* Summary bar */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10, marginBottom: '1.5rem' }}>
              {result.virustotal && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '0.75rem' }}>
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 6 }}>VIRUSTOTAL</div>
                  <VTBadge malicious={result.virustotal.malicious} total={result.virustotal.total} />
                  {result.virustotal.reputation !== 0 && (
                    <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginTop: 4 }}>rep: {result.virustotal.reputation}</div>
                  )}
                </div>
              )}
              {result.abuseipdb && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '0.75rem' }}>
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 6 }}>ABUSEIPDB</div>
                  <ScoreBadge score={result.abuseipdb.abuseConfidenceScore} label={`${result.abuseipdb.abuseConfidenceScore}% abuse`} />
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginTop: 4 }}>{result.abuseipdb.totalReports} reports</div>
                </div>
              )}
              {result.ssl && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '0.75rem' }}>
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 6 }}>SSL CERT</div>
                  <span style={{ fontSize: 11, fontWeight: 500, color: sslDaysColor(result.ssl.daysUntilExpiry) }}>
                    {result.ssl.daysUntilExpiry > 0 ? `${result.ssl.daysUntilExpiry}d remaining` : 'EXPIRED'}
                  </span>
                </div>
              )}
              {result.urlscan && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '0.75rem' }}>
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 6 }}>URLSCAN</div>
                  <span style={{ fontSize: 11, fontWeight: 500, color: result.urlscan.verdicts.overall.malicious ? '#dc2626' : '#16a34a' }}>
                    {result.urlscan.verdicts.overall.malicious ? 'MALICIOUS' : 'CLEAN'}
                  </span>
                  <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginTop: 4 }}>score: {result.urlscan.verdicts.overall.score}</div>
                </div>
              )}
            </div>

            {/* Detail grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

              {/* VirusTotal detail */}
              {result.virustotal && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="VirusTotal">
                    <Row label="Malicious" value={<span style={{ color: result.virustotal.malicious > 0 ? '#dc2626' : '#16a34a' }}>{result.virustotal.malicious}</span>} />
                    <Row label="Suspicious" value={result.virustotal.suspicious} />
                    <Row label="Harmless" value={result.virustotal.harmless} />
                    <Row label="Undetected" value={result.virustotal.undetected} />
                    <Row label="Reputation" value={result.virustotal.reputation} />
                    {result.virustotal.tags.length > 0 && (
                      <Row label="Tags" value={result.virustotal.tags.join(', ')} />
                    )}
                    {result.virustotal.lastAnalysisDate && (
                      <Row label="Last scan" value={new Date(result.virustotal.lastAnalysisDate).toLocaleDateString()} />
                    )}
                  </Section>
                  {result.virustotal.engines && (
                    <div style={{ marginTop: 8 }}>
                      <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 6 }}>Flagged engines</div>
                      {Object.entries(result.virustotal.engines)
                        .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
                        .slice(0, 8)
                        .map(([engine, v]) => (
                          <div key={engine} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '0.5px solid var(--color-border-tertiary)', fontSize: 11 }}>
                            <span style={{ color: 'var(--color-text-secondary)' }}>{engine}</span>
                            <span style={{ color: v.category === 'malicious' ? '#dc2626' : '#d97706' }}>{v.result}</span>
                          </div>
                        ))}
                    </div>
                  )}
                </div>
              )}

              {/* AbuseIPDB detail */}
              {result.abuseipdb && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="AbuseIPDB">
                    <Row label="Confidence" value={`${result.abuseipdb.abuseConfidenceScore}%`} />
                    <Row label="Total reports" value={result.abuseipdb.totalReports} />
                    <Row label="Distinct users" value={result.abuseipdb.numDistinctUsers} />
                    <Row label="Country" value={result.abuseipdb.countryCode} />
                    <Row label="ISP" value={result.abuseipdb.isp} />
                    <Row label="Domain" value={result.abuseipdb.domain} />
                    <Row label="Tor" value={result.abuseipdb.isTor ? '✓ Yes' : 'No'} />
                    <Row label="Proxy/VPN" value={result.abuseipdb.isProxy || result.abuseipdb.isVpn ? '✓ Yes' : 'No'} />
                    {result.abuseipdb.lastReportedAt && (
                      <Row label="Last report" value={new Date(result.abuseipdb.lastReportedAt).toLocaleDateString()} />
                    )}
                  </Section>
                </div>
              )}

              {/* DNS */}
              {result.dns && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="DNS Records">
                    {result.dns.a.length > 0 && <Row label="A" value={result.dns.a.join(', ')} mono />}
                    {result.dns.mx.length > 0 && <Row label="MX" value={result.dns.mx.slice(0, 3).join(', ')} mono />}
                    {result.dns.ns.length > 0 && <Row label="NS" value={result.dns.ns.slice(0, 3).join(', ')} mono />}
                    {result.dns.cname.length > 0 && <Row label="CNAME" value={result.dns.cname.join(', ')} mono />}
                    {result.dns.txt.length > 0 && (
                      <div style={{ marginTop: 8 }}>
                        <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 4 }}>TXT Records</div>
                        {result.dns.txt.slice(0, 4).map((t, i) => (
                          <div key={i} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', padding: '3px 0', borderBottom: '0.5px solid var(--color-border-tertiary)', wordBreak: 'break-all' }}>{t}</div>
                        ))}
                      </div>
                    )}
                  </Section>
                </div>
              )}

              {/* SSL */}
              {result.ssl && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="SSL Certificate">
                    <Row label="Issuer" value={result.ssl.issuer} />
                    <Row label="Subject" value={result.ssl.subject} mono />
                    <Row label="Valid from" value={new Date(result.ssl.validFrom).toLocaleDateString()} />
                    <Row label="Valid to" value={new Date(result.ssl.validTo).toLocaleDateString()} />
                    <Row label="Days left" value={<span style={{ color: sslDaysColor(result.ssl.daysUntilExpiry) }}>{result.ssl.daysUntilExpiry}</span>} />
                    <Row label="Protocol" value={result.ssl.protocol} />
                  </Section>
                  {result.ssl.sans.length > 0 && (
                    <div>
                      <div style={{ fontSize: 10, color: 'var(--color-text-tertiary)', marginBottom: 4 }}>SANs</div>
                      {result.ssl.sans.slice(0, 6).map((san, i) => (
                        <div key={i} style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)', padding: '2px 0' }}>{san}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Whois */}
              {result.whois && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="WHOIS">
                    <Row label="Domain" value={result.whois.domainName} mono />
                    <Row label="Registrar" value={result.whois.registrar} />
                    <Row label="Created" value={result.whois.createdDate ? new Date(result.whois.createdDate).toLocaleDateString() : 'Unknown'} />
                    <Row label="Updated" value={result.whois.updatedDate ? new Date(result.whois.updatedDate).toLocaleDateString() : 'Unknown'} />
                    <Row label="Expires" value={result.whois.expiresDate ? new Date(result.whois.expiresDate).toLocaleDateString() : 'Unknown'} />
                    {result.whois.nameservers.length > 0 && (
                      <Row label="Nameservers" value={result.whois.nameservers.slice(0, 3).join(', ')} mono />
                    )}
                  </Section>
                </div>
              )}

              {/* URLScan */}
              {result.urlscan && (
                <div style={{ background: 'var(--color-background-primary)', border: '0.5px solid var(--color-border-tertiary)', borderRadius: 8, padding: '1rem' }}>
                  <Section title="URLScan">
                    <Row label="Domain" value={result.urlscan.page.domain} mono />
                    <Row label="IP" value={result.urlscan.page.ip} mono />
                    <Row label="Country" value={result.urlscan.page.country} />
                    <Row label="Server" value={result.urlscan.page.server} />
                    <Row label="Title" value={result.urlscan.page.title} />
                    <Row label="Verdict" value={
                      <span style={{ color: result.urlscan.verdicts.overall.malicious ? '#dc2626' : '#16a34a' }}>
                        {result.urlscan.verdicts.overall.malicious ? 'MALICIOUS' : 'CLEAN'}
                      </span>
                    } />
                  </Section>
                  <div style={{ display: 'flex', gap: 8 }}>
                    {result.urlscan.screenshotUrl && (
                      <a href={result.urlscan.screenshotUrl} target="_blank" rel="noopener noreferrer"
                        style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--color-text-secondary)', textDecoration: 'none' }}>
                        <ExternalLink size={10} /> Screenshot
                      </a>
                    )}
                    <a href={result.urlscan.reportUrl} target="_blank" rel="noopener noreferrer"
                      style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 4, color: 'var(--color-text-secondary)', textDecoration: 'none' }}>
                      <ExternalLink size={10} /> Full report
                    </a>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      <style>{`
        @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }
      `}</style>
    </div>
  )
}
