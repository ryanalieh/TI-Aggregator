import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'TI Aggregator',
  description: 'Threat Intelligence Aggregator',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
