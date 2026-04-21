export type InputType = 'ip' | 'domain' | 'url' | 'hash' | 'unknown'

export interface TIResult {
  input: string
  inputType: InputType
  timestamp: string
  virustotal?: VTResult
  abuseipdb?: AbuseResult
  urlscan?: URLScanResult
  dns?: DNSResult
  ssl?: SSLResult
  whois?: WhoisResult
  error?: string
}

export interface VTResult {
  malicious: number
  suspicious: number
  harmless: number
  undetected: number
  total: number
  reputation: number
  tags: string[]
  lastAnalysisDate?: string
  engines?: Record<string, { category: string; result: string }>
}

export interface AbuseResult {
  abuseConfidenceScore: number
  totalReports: number
  numDistinctUsers: number
  lastReportedAt: string | null
  countryCode: string
  isp: string
  domain: string
  isTor: boolean
  isProxy: boolean
  isVpn: boolean
}

export interface URLScanResult {
  scanId: string
  screenshotUrl: string
  reportUrl: string
  verdicts: {
    overall: { score: number; malicious: boolean }
  }
  page: {
    domain: string
    ip: string
    country: string
    server: string
    title: string
  }
  stats: {
    malicious: number
    undetected: number
    benign: number
  }
}

export interface DNSResult {
  a: string[]
  mx: string[]
  ns: string[]
  txt: string[]
  cname: string[]
}

export interface SSLResult {
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  daysUntilExpiry: number
  sans: string[]
  protocol: string
}

export interface WhoisResult {
  domainName: string
  registrar: string
  createdDate: string
  updatedDate: string
  expiresDate: string
  nameservers: string[]
  status: string[]
}

export function detectInputType(input: string): InputType {
  const trimmed = input.trim()

  // MD5, SHA1, SHA256
  if (/^[a-fA-F0-9]{32}$/.test(trimmed)) return 'hash'
  if (/^[a-fA-F0-9]{40}$/.test(trimmed)) return 'hash'
  if (/^[a-fA-F0-9]{64}$/.test(trimmed)) return 'hash'

  // IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(trimmed)) return 'ip'

  // IPv6
  if (/^[a-fA-F0-9:]+:[a-fA-F0-9:]+$/.test(trimmed)) return 'ip'

  // URL
  if (/^https?:\/\//i.test(trimmed)) return 'url'

  // Domain
  if (/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/.test(trimmed)) return 'domain'

  return 'unknown'
}

export function extractDomain(input: string, type: InputType): string {
  if (type === 'url') {
    try {
      return new URL(input).hostname
    } catch {
      return input
    }
  }
  return input
}
