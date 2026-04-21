import { VTResult, AbuseResult, URLScanResult, DNSResult, SSLResult, WhoisResult } from './types'

// ── VirusTotal ──────────────────────────────────────────────────────────────

export async function fetchVirusTotal(input: string, type: string, apiKey: string): Promise<VTResult> {
  let endpoint = ''
  if (type === 'ip') endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${input}`
  else if (type === 'domain') endpoint = `https://www.virustotal.com/api/v3/domains/${input}`
  else if (type === 'url') {
    const id = Buffer.from(input).toString('base64').replace(/=/g, '')
    endpoint = `https://www.virustotal.com/api/v3/urls/${id}`
  } else if (type === 'hash') endpoint = `https://www.virustotal.com/api/v3/files/${input}`

  const res = await fetch(endpoint, { headers: { 'x-apikey': apiKey } })
  if (!res.ok) throw new Error(`VT error: ${res.status}`)
  const json = await res.json()
  const attr = json.data.attributes
  const stats = attr.last_analysis_stats ?? {}

  return {
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    total: Object.values(stats).reduce((a: number, b) => a + (b as number), 0),
    reputation: attr.reputation ?? 0,
    tags: attr.tags ?? [],
    lastAnalysisDate: attr.last_analysis_date
      ? new Date(attr.last_analysis_date * 1000).toISOString()
      : undefined,
    engines: attr.last_analysis_results,
  }
}

// ── AbuseIPDB ───────────────────────────────────────────────────────────────

export async function fetchAbuseIPDB(ip: string, apiKey: string): Promise<AbuseResult> {
  const res = await fetch(
    `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose`,
    { headers: { Key: apiKey, Accept: 'application/json' } }
  )
  if (!res.ok) throw new Error(`AbuseIPDB error: ${res.status}`)
  const json = await res.json()
  const d = json.data

  return {
    abuseConfidenceScore: d.abuseConfidenceScore,
    totalReports: d.totalReports,
    numDistinctUsers: d.numDistinctUsers,
    lastReportedAt: d.lastReportedAt,
    countryCode: d.countryCode,
    isp: d.isp,
    domain: d.domain,
    isTor: d.isTor,
    isProxy: d.isProxy ?? false,
    isVpn: d.isVpn ?? false,
  }
}

// ── URLScan ─────────────────────────────────────────────────────────────────

export async function fetchURLScan(url: string, apiKey: string): Promise<URLScanResult> {
  // Submit scan
  const submit = await fetch('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: { 'API-Key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, visibility: 'private' }),
  })
  if (!submit.ok) throw new Error(`URLScan submit error: ${submit.status}`)
  const { uuid } = await submit.json()

  // Poll for result (max 30s)
  for (let i = 0; i < 10; i++) {
    await new Promise(r => setTimeout(r, 3000))
    const result = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`)
    if (result.status === 404) continue
    if (!result.ok) throw new Error(`URLScan result error: ${result.status}`)
    const json = await result.json()

    return {
      scanId: uuid,
      screenshotUrl: `https://urlscan.io/screenshots/${uuid}.png`,
      reportUrl: `https://urlscan.io/result/${uuid}/`,
      verdicts: json.verdicts,
      page: {
        domain: json.page?.domain ?? '',
        ip: json.page?.ip ?? '',
        country: json.page?.country ?? '',
        server: json.page?.server ?? '',
        title: json.page?.title ?? '',
      },
      stats: {
        malicious: json.stats?.malicious ?? 0,
        undetected: json.stats?.undetected ?? 0,
        benign: json.stats?.benign ?? 0,
      },
    }
  }
  throw new Error('URLScan timed out')
}

export async function searchURLScan(domain: string, apiKey: string): Promise<URLScanResult | null> {
  const res = await fetch(
    `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=1`,
    { headers: { 'API-Key': apiKey } }
  )
  if (!res.ok) return null
  const json = await res.json()
  const r = json.results?.[0]
  if (!r) return null

  return {
    scanId: r.task?.uuid ?? '',
    screenshotUrl: r.screenshot ?? '',
    reportUrl: r.result ?? '',
    verdicts: r.verdicts ?? { overall: { score: 0, malicious: false } },
    page: {
      domain: r.page?.domain ?? '',
      ip: r.page?.ip ?? '',
      country: r.page?.country ?? '',
      server: r.page?.server ?? '',
      title: r.page?.title ?? '',
    },
    stats: { malicious: 0, undetected: 0, benign: 0 },
  }
}

// ── DNS ─────────────────────────────────────────────────────────────────────

export async function fetchDNS(domain: string): Promise<DNSResult> {
  const types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
  const results: DNSResult = { a: [], mx: [], ns: [], txt: [], cname: [] }

  await Promise.all(types.map(async type => {
    try {
      const res = await fetch(
        `https://dns.google/resolve?name=${domain}&type=${type}`,
        { headers: { Accept: 'application/json' } }
      )
      const json = await res.json()
      const answers = json.Answer ?? []

      if (type === 'A') results.a = answers.map((a: { data: string }) => a.data)
      if (type === 'MX') results.mx = answers.map((a: { data: string }) => a.data)
      if (type === 'NS') results.ns = answers.map((a: { data: string }) => a.data)
      if (type === 'TXT') results.txt = answers.map((a: { data: string }) => a.data.replace(/"/g, ''))
      if (type === 'CNAME') results.cname = answers.map((a: { data: string }) => a.data)
    } catch { /* skip on error */ }
  }))

  return results
}

// ── SSL ─────────────────────────────────────────────────────────────────────

export async function fetchSSL(domain: string): Promise<SSLResult> {
  const res = await fetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=false&expand=dns_names&expand=issuer&expand=cert`, {
    headers: { Authorization: '' }
  })

  // Fallback to crt.sh if certspotter fails
  if (!res.ok) {
    const crt = await fetch(`https://crt.sh/?q=${domain}&output=json`)
    if (!crt.ok) throw new Error('SSL fetch failed')
    const certs = await crt.json()
    const latest = certs[0]
    return {
      issuer: latest?.issuer_name ?? 'Unknown',
      subject: latest?.common_name ?? domain,
      validFrom: latest?.not_before ?? '',
      validTo: latest?.not_after ?? '',
      daysUntilExpiry: latest?.not_after
        ? Math.floor((new Date(latest.not_after).getTime() - Date.now()) / 86400000)
        : -1,
      sans: certs.slice(0, 10).map((c: { name_value: string }) => c.name_value),
      protocol: 'TLS',
    }
  }

  const certs = await res.json()
  const latest = certs[0]
  if (!latest) throw new Error('No SSL certs found')

  const notAfter = latest.cert?.validity?.end ?? ''
  return {
    issuer: latest.issuer?.friendly_name ?? 'Unknown',
    subject: domain,
    validFrom: latest.cert?.validity?.start ?? '',
    validTo: notAfter,
    daysUntilExpiry: notAfter
      ? Math.floor((new Date(notAfter).getTime() - Date.now()) / 86400000)
      : -1,
    sans: latest.dns_names ?? [],
    protocol: 'TLS',
  }
}

// ── Whois ───────────────────────────────────────────────────────────────────

export async function fetchWhois(domain: string): Promise<WhoisResult> {
  const res = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`)

  // Fallback to rdap
  if (!res.ok || !process.env.WHOIS_API_KEY) {
    const rdap = await fetch(`https://rdap.org/domain/${domain}`)
    if (!rdap.ok) throw new Error('Whois fetch failed')
    const json = await rdap.json()

    const getEvent = (type: string) =>
      json.events?.find((e: { eventAction: string; eventDate: string }) => e.eventAction === type)?.eventDate ?? ''

    return {
      domainName: json.ldhName ?? domain,
      registrar: json.entities?.[0]?.vcardArray?.[1]?.find((v: string[]) => v[0] === 'fn')?.[3] ?? 'Unknown',
      createdDate: getEvent('registration'),
      updatedDate: getEvent('last changed'),
      expiresDate: getEvent('expiration'),
      nameservers: json.nameservers?.map((ns: { ldhName: string }) => ns.ldhName) ?? [],
      status: json.status ?? [],
    }
  }

  const json = await res.json()
  const r = json.WhoisRecord

  return {
    domainName: r.domainName ?? domain,
    registrar: r.registrarName ?? 'Unknown',
    createdDate: r.createdDate ?? '',
    updatedDate: r.updatedDate ?? '',
    expiresDate: r.expiresDate ?? '',
    nameservers: r.nameServers?.hostNames ?? [],
    status: Array.isArray(r.status) ? r.status : [r.status ?? ''],
  }
}
