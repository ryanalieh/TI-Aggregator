import { NextRequest, NextResponse } from 'next/server'
import { detectInputType, extractDomain, TIResult } from '@/lib/types'
import {
  fetchVirusTotal, fetchAbuseIPDB, fetchURLScan,
  searchURLScan, fetchDNS, fetchSSL, fetchWhois
} from '@/lib/sources'
import { supabaseAdmin } from '@/lib/supabase'

export const runtime = 'nodejs'
export const maxDuration = 60

export async function POST(req: NextRequest) {
  const { input } = await req.json()
  if (!input) return NextResponse.json({ error: 'No input provided' }, { status: 400 })

  const trimmed = input.trim()
  const inputType = detectInputType(trimmed)
  if (inputType === 'unknown') return NextResponse.json({ error: 'Unrecognised input type' }, { status: 400 })

  const vtKey = process.env.VIRUSTOTAL_API_KEY ?? ''
  const abuseKey = process.env.ABUSEIPDB_API_KEY ?? ''
  const urlscanKey = process.env.URLSCAN_API_KEY ?? ''

  const result: TIResult = {
    input: trimmed,
    inputType,
    timestamp: new Date().toISOString(),
  }

  const domain = extractDomain(trimmed, inputType)

  // Run all applicable sources in parallel
  const tasks: Promise<void>[] = []

  // VirusTotal — works for all types
  if (vtKey) {
    tasks.push(
      fetchVirusTotal(trimmed, inputType, vtKey)
        .then(r => { result.virustotal = r })
        .catch(e => { console.error('VT error:', e.message) })
    )
  }

  // AbuseIPDB — IPs only
  if (inputType === 'ip' && abuseKey) {
    tasks.push(
      fetchAbuseIPDB(trimmed, abuseKey)
        .then(r => { result.abuseipdb = r })
        .catch(e => { console.error('AbuseIPDB error:', e.message) })
    )
  }

  // URLScan — domains and URLs
  if ((inputType === 'domain' || inputType === 'url') && urlscanKey) {
    const fn = inputType === 'url'
      ? fetchURLScan(trimmed, urlscanKey)
      : searchURLScan(domain, urlscanKey)
    tasks.push(
      fn.then(r => { if (r) result.urlscan = r })
        .catch(e => { console.error('URLScan error:', e.message) })
    )
  }

  // DNS — domains and URLs
  if (inputType === 'domain' || inputType === 'url') {
    tasks.push(
      fetchDNS(domain)
        .then(r => { result.dns = r })
        .catch(e => { console.error('DNS error:', e.message) })
    )
  }

  // SSL — domains and URLs
  if (inputType === 'domain' || inputType === 'url') {
    tasks.push(
      fetchSSL(domain)
        .then(r => { result.ssl = r })
        .catch(e => { console.error('SSL error:', e.message) })
    )
  }

  // Whois — domains only
  if (inputType === 'domain' || inputType === 'url') {
    tasks.push(
      fetchWhois(domain)
        .then(r => { result.whois = r })
        .catch(e => { console.error('Whois error:', e.message) })
    )
  }

  await Promise.all(tasks)

  // Save to Supabase
  await supabaseAdmin.from('lookups').insert({
    input: trimmed,
    input_type: inputType,
    result: result,
    created_at: result.timestamp,
  })

  return NextResponse.json(result)
}
