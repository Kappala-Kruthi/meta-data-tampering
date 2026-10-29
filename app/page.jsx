'use client';

import Link from 'next/link';
import { useState } from 'react';

export default function HomePage() {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '56px', padding: '24px 0' }}>
      {/* Hero Section */}
      <section style={{
        position: 'relative',
        padding: '64px 32px',
        borderRadius: 'var(--radius-xl)',
        background: 'linear-gradient(135deg, rgba(13, 21, 39, 0.8) 0%, rgba(10, 16, 30, 0.95) 100%)',
        border: '1px solid rgba(0, 240, 255, 0.2)',
        boxShadow: '0 24px 64px -12px rgba(0, 0, 0, 0.8), 0 0 32px -4px rgba(0, 240, 255, 0.15)',
        textAlign: 'center',
        overflow: 'hidden',
      }}>
        {/* Subtle background cyber grid */}
        <div style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: 'radial-gradient(rgba(0, 240, 255, 0.1) 1px, transparent 1px)',
          backgroundSize: '24px 24px',
          opacity: 0.35,
          pointerEvents: 'none',
        }} />

        <div style={{ position: 'relative', zIndex: 1, maxWidth: '880px', margin: '0 auto' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '6px 16px', borderRadius: '9999px', background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.3)', marginBottom: '24px' }}>
            <span style={{ display: 'inline-block', width: '8px', height: '8px', borderRadius: '50%', background: '#00F0FF', boxShadow: '0 0 8px #00F0FF' }} />
            <span style={{ fontSize: '13px', fontWeight: '700', color: '#00F0FF', letterSpacing: '0.05em', fontFamily: 'var(--font-mono)' }}>
              TRACE FORENSIC ENGINE • CYBERSECURITY & INTELLIGENCE
            </span>
          </div>

          <h1 style={{
            fontSize: '48px',
            lineHeight: 1.15,
            marginBottom: '20px',
            fontFamily: 'var(--font-heading)',
          }}>
            Digital Forensics &amp; <span className="gradient-text">Metadata Tampering Detection</span>
          </h1>

          <p style={{
            fontSize: '18px',
            color: 'var(--text-muted)',
            lineHeight: 1.6,
            marginBottom: '36px',
            maxWidth: '720px',
            margin: '0 auto 36px auto',
          }}>
            Academic digital forensics workbench powered by Phil Harvey's ExifTool, SHA-256 cryptographic hashing, hex container steganography scanning, and automated chain-of-custody verification.
          </p>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <Link href="/dashboard" className="btn btn-primary" style={{ padding: '14px 28px', fontSize: '16px' }}>
              Launch Forensics Hub →
            </Link>
            <Link href="/inspect" className="btn btn-cyber" style={{ padding: '14px 28px', fontSize: '16px' }}>
              Inspect Single File
            </Link>
            <Link href="/compare" className="btn btn-secondary" style={{ padding: '14px 28px', fontSize: '16px' }}>
              Side-by-Side Tampering Compare
            </Link>
          </div>
        </div>

        {/* Live Forensic Metrics Bar */}
        <div style={{
          position: 'relative',
          zIndex: 1,
          marginTop: '56px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '16px',
          padding: '20px',
          borderRadius: 'var(--radius-lg)',
          background: 'rgba(7, 11, 20, 0.7)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
        }}>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '800', color: '#00F0FF', fontFamily: 'var(--font-mono)' }}>100%</div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Read-Only Subprocess Safety</div>
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '800', color: '#34D399', fontFamily: 'var(--font-mono)' }}>SHA-256</div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Cryptographic Hash Verification</div>
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '800', color: '#A855F7', fontFamily: 'var(--font-mono)' }}>8+ Families</div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>EXIF • IPTC • XMP • MakerNotes</div>
          </div>
          <div>
            <div style={{ fontSize: '28px', fontWeight: '800', color: '#FBBF24', fontFamily: 'var(--font-mono)' }}>ISO 27037</div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Digital Evidence Standard</div>
          </div>
        </div>
      </section>

      {/* Forensic Capabilities Grid */}
      <section>
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <h2 style={{ fontSize: '32px', marginBottom: '12px' }}>Core Forensic Capabilities</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '16px', maxWidth: '640px', margin: '0 auto' }}>
            Comprehensive analysis tools built specifically for digital investigators, cyber defense labs, and forensic research.
          </p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
          gap: '24px',
        }}>
          {/* Card 1 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(0, 240, 255, 0.1)', border: '1px solid rgba(0, 240, 255, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#00F0FF', fontSize: '20px' }}>
                🔍
              </div>
              <span className="badge badge-cyan">DEEP INSPECTION</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>Single Image Analysis</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Extracts 100+ metadata fields across EXIF, IPTC, XMP, and camera MakerNotes without altering the original binary file.
            </p>
            <Link href="/inspect" style={{ color: '#00F0FF', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              Open Inspector →
            </Link>
          </div>

          {/* Card 2 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#F43F5E', fontSize: '20px' }}>
                ⚖️
              </div>
              <span className="badge badge-rose">TAMPER DETECTOR</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>Differential Metadata Comparison</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Compares an original reference file against a questioned file to pinpoint modified software tags, stripped timestamps, and altered dimensions.
            </p>
            <Link href="/compare" style={{ color: '#F43F5E', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              Compare Dual Files →
            </Link>
          </div>

          {/* Card 3 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(168, 85, 247, 0.1)', border: '1px solid rgba(168, 85, 247, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#A855F7', fontSize: '20px' }}>
                🧩
              </div>
              <span className="badge badge-amber">STEGANOGRAPHY SCAN</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>Hex &amp; Post-EOF Scanner</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Parses magic bytes (SOI, APP1, DQT, EOI) and scans for hidden payload appended past the JPEG End-Of-Image marker (FF D9).
            </p>
            <Link href="/inspect" style={{ color: '#A855F7', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              Analyze Hex Map →
            </Link>
          </div>

          {/* Card 4 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#10B981', fontSize: '20px' }}>
                📍
              </div>
              <span className="badge badge-emerald">GEOLOCATION</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>GPS Map &amp; Clock Sync</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Decodes GPS latitude/longitude, altitude, and correlates satellite atomic timestamps against camera internal clocks.
            </p>
            <Link href="/inspect" style={{ color: '#10B981', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              View Geolocation →
            </Link>
          </div>

          {/* Card 5 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(59, 130, 246, 0.1)', border: '1px solid rgba(59, 130, 246, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#3B82F6', fontSize: '20px' }}>
                🛡️
              </div>
              <span className="badge badge-cyan">PRIVACY DEFENSE</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>Privacy Sanitizer &amp; Scrubber</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Removes sensitive geolocation, camera serial numbers, and author identification while generating a byte-differential ledger.
            </p>
            <Link href="/sanitize" style={{ color: '#3B82F6', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              Scrub Metadata →
            </Link>
          </div>

          {/* Card 6 */}
          <div className="glass-panel" style={{ padding: '28px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '16px' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: 'rgba(245, 158, 11, 0.1)', border: '1px solid rgba(245, 158, 11, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#F59E0B', fontSize: '20px' }}>
                📜
              </div>
              <span className="badge badge-amber">CHAIN OF CUSTODY</span>
            </div>
            <h3 style={{ fontSize: '20px', marginBottom: '10px' }}>Legal Custody Certificate</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px', lineHeight: 1.6, marginBottom: '20px' }}>
              Generates cryptographic chain-of-custody certificates (TRACE-COC-...) compliant with digital evidence acquisition guidelines.
            </p>
            <Link href="/evidence" style={{ color: '#F59E0B', textDecoration: 'none', fontSize: '14px', fontWeight: '600', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              Generate Certificate →
            </Link>
          </div>
        </div>
      </section>

      {/* Forensic Pipeline Steps */}
      <section style={{
        padding: '48px 32px',
        borderRadius: 'var(--radius-xl)',
        background: 'rgba(13, 21, 39, 0.5)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
      }}>
        <div style={{ textAlign: 'center', marginBottom: '36px' }}>
          <h2 style={{ fontSize: '28px', marginBottom: '8px' }}>Investigation Pipeline Workflow</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '15px' }}>
            Standard operating procedure for digital image evidence verification.
          </p>
        </div>

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
          gap: '20px',
        }}>
          <div style={{ padding: '20px', background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '12px', color: '#00F0FF', fontWeight: '700', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>PHASE 01</div>
            <h4 style={{ fontSize: '16px', marginBottom: '6px' }}>Intake &amp; Hash</h4>
            <p style={{ fontSize: '13px', color: 'var(--text-dim)' }}>File intake with immediate SHA-256 binary hashing before any processing.</p>
          </div>

          <div style={{ padding: '20px', background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '12px', color: '#3B82F6', fontWeight: '700', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>PHASE 02</div>
            <h4 style={{ fontSize: '16px', marginBottom: '6px' }}>ExifTool Parsing</h4>
            <p style={{ fontSize: '13px', color: 'var(--text-dim)' }}>Safe read-only execution extracting standardized EXIF, IPTC, and XMP blocks.</p>
          </div>

          <div style={{ padding: '20px', background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '12px', color: '#A855F7', fontWeight: '700', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>PHASE 03</div>
            <h4 style={{ fontSize: '16px', marginBottom: '6px' }}>Hex &amp; Steg Scan</h4>
            <p style={{ fontSize: '13px', color: 'var(--text-dim)' }}>Magic byte segment validation and trailing payload scanner past EOF marker.</p>
          </div>

          <div style={{ padding: '20px', background: 'rgba(15, 23, 42, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '12px', color: '#34D399', fontWeight: '700', fontFamily: 'var(--font-mono)', marginBottom: '8px' }}>PHASE 04</div>
            <h4 style={{ fontSize: '16px', marginBottom: '6px' }}>Tampering Verdict</h4>
            <p style={{ fontSize: '13px', color: 'var(--text-dim)' }}>Differential comparison scoring and automated Chain of Custody sealing.</p>
          </div>
        </div>
      </section>

      {/* CTA Box */}
      <section style={{
        textAlign: 'center',
        padding: '48px 24px',
        borderRadius: 'var(--radius-xl)',
        background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.1) 0%, rgba(59, 130, 246, 0.15) 100%)',
        border: '1px solid rgba(0, 240, 255, 0.3)',
      }}>
        <h2 style={{ fontSize: '32px', marginBottom: '12px' }}>Ready to Begin Your Investigation?</h2>
        <p style={{ color: 'var(--text-muted)', fontSize: '16px', marginBottom: '28px', maxWidth: '580px', margin: '0 auto 28px auto' }}>
          Open the dedicated investigator workspace to run single deep inspections or multi-image comparison matrices.
        </p>
        <Link href="/dashboard" className="btn btn-primary" style={{ padding: '14px 32px', fontSize: '16px' }}>
          Launch Forensics Hub →
        </Link>
      </section>
    </div>
  );
}
