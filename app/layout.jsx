import './globals.css';
import Link from 'next/link';

export const metadata = {
  title: 'TRACE - Advanced Digital Forensics System',
  description: 'Metadata Tampering Detection in Media Files Using Cryptographic Hash Verification and EXIF Differential Analysis',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>
        {/* Top Forensic Navigation Bar */}
        <header style={{
          position: 'sticky',
          top: 0,
          zIndex: 100,
          background: 'rgba(7, 11, 20, 0.85)',
          backdropFilter: 'blur(16px)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          padding: '12px 24px',
        }}>
          <div style={{
            maxWidth: '1400px',
            margin: '0 auto',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '16px',
          }}>
            {/* Logo */}
            <Link href="/" style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              textDecoration: 'none',
              color: 'inherit',
            }}>
              <div style={{
                width: '36px',
                height: '36px',
                borderRadius: '8px',
                background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.15) 0%, rgba(59, 130, 246, 0.2) 100%)',
                border: '1px solid rgba(0, 240, 255, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: '#00F0FF',
                fontWeight: '800',
                fontSize: '18px',
                boxShadow: '0 0 12px rgba(0, 240, 255, 0.3)',
              }}>
                ⌖
              </div>
              <div>
                <div style={{
                  fontSize: '18px',
                  fontWeight: '800',
                  letterSpacing: '0.05em',
                  fontFamily: 'var(--font-heading)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}>
                  TRACE <span style={{ fontSize: '11px', color: '#00F0FF', fontWeight: '600', padding: '2px 6px', background: 'rgba(0, 240, 255, 0.1)', borderRadius: '4px', border: '1px solid rgba(0, 240, 255, 0.3)' }}>v2.4 PRO</span>
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', letterSpacing: '0.02em' }}>
                  DIGITAL FORENSICS WORKBENCH
                </div>
              </div>
            </Link>

            {/* Nav Links */}
            <nav style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}>
              <Link href="/dashboard" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Dashboard
              </Link>
              <Link href="/inspect" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Inspect File
              </Link>
              <Link href="/compare" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Compare Dual
              </Link>
              <Link href="/batch-analysis" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Batch Matrix
              </Link>
              <Link href="/sanitize" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Sanitizer
              </Link>
              <Link href="/evidence" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
                Custody Chain
              </Link>
            </nav>

            {/* Quick Actions & Auth */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span className="badge badge-emerald">
                ● LAB ONLINE
              </span>
              <Link href="/dashboard" className="btn btn-cyber" style={{ padding: '6px 14px', fontSize: '13px' }}>
                Open Hub →
              </Link>
            </div>
          </div>
        </header>

        {/* Main Content Area */}
        <main style={{ minHeight: 'calc(100vh - 160px)', padding: '24px' }}>
          <div style={{ maxWidth: '1400px', margin: '0 auto' }}>
            {children}
          </div>
        </main>

        {/* Global Footer */}
        <footer style={{
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          background: 'rgba(13, 21, 39, 0.6)',
          backdropFilter: 'blur(12px)',
          padding: '24px',
          marginTop: '48px',
          fontSize: '13px',
          color: 'var(--text-dim)',
        }}>
          <div style={{
            maxWidth: '1400px',
            margin: '0 auto',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
          }}>
            <div>
              <strong style={{ color: 'var(--text-muted)' }}>TRACE Digital Forensics</strong> — Metadata Tampering Detection in Media Files Using ExifTool
            </div>
            <div style={{ display: 'flex', gap: '16px' }}>
              <span>ExifTool Subprocess</span>
              <span>•</span>
              <span>SHA-256 Hasher</span>
              <span>•</span>
              <span>Hex Inspector</span>
              <span>•</span>
              <span>Next.js Fullstack Engine</span>
            </div>
          </div>
        </footer>
      </body>
    </html>
  );
}
