'use client';

import Link from 'next/link';
import { useState, useEffect } from 'react';

export default function DashboardPage() {
  const [user, setUser] = useState('Bhuvana@123');

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem('trace_user_id');
      if (stored) setUser(stored);
    }
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '32px' }}>
      {/* Header Profile Greeting */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '16px',
        padding: '24px 28px',
        borderRadius: 'var(--radius-xl)',
        background: 'linear-gradient(135deg, rgba(13, 21, 39, 0.7) 0%, rgba(7, 11, 20, 0.9) 100%)',
        border: '1px solid var(--border-subtle)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{
            width: '54px',
            height: '54px',
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #00C2FF 0%, #3B82F6 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '22px',
            fontWeight: '800',
            color: '#070B14',
            boxShadow: '0 0 20px rgba(0, 194, 255, 0.4)',
          }}>
            KB
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '24px' }}>Welcome, {user}</h1>
              <span className="badge badge-cyan">Lead Forensic Analyst</span>
            </div>
            <div style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '2px' }}>
              Cyber Forensics Research Laboratory • Session ID: TRACE-ACTIVE-{Date.now().toString().slice(-6)}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Link href="/inspect" className="btn btn-primary">
            + New Deep Inspection
          </Link>
          <Link href="/compare" className="btn btn-secondary">
            Dual Compare
          </Link>
        </div>
      </div>

      {/* KPI Stats Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
        gap: '16px',
      }}>
        {/* KPI 1 */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Total Ingested Evidence</span>
            <span style={{ color: '#00F0FF', fontSize: '18px' }}>📁</span>
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)' }}>148</div>
          <div style={{ fontSize: '12px', color: '#34D399', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}>
            ↑ 12 files verified this week
          </div>
        </div>

        {/* KPI 2 */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Cryptographically Intact</span>
            <span style={{ color: '#34D399', fontSize: '18px' }}>🛡️</span>
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#34D399' }}>119</div>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>
            Bit-identical SHA-256 match
          </div>
        </div>

        {/* KPI 3 */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Tampered / Inconsistent</span>
            <span style={{ color: '#FB7185', fontSize: '18px' }}>⚠️</span>
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#FB7185' }}>29</div>
          <div style={{ fontSize: '12px', color: '#FB7185', marginTop: '4px' }}>
            Discrepancy flags detected
          </div>
        </div>

        {/* KPI 4 */}
        <div className="glass-panel" style={{ padding: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Custody Certificates</span>
            <span style={{ color: '#FBBF24', fontSize: '18px' }}>📜</span>
          </div>
          <div style={{ fontSize: '32px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#FBBF24' }}>42</div>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>
            Cryptographically sealed
          </div>
        </div>
      </div>

      {/* Quick Launchpad */}
      <div>
        <h2 style={{ fontSize: '20px', marginBottom: '16px' }}>Forensic Workbench Modules</h2>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '16px',
        }}>
          <Link href="/inspect" style={{ textDecoration: 'none', color: 'inherit' }}>
            <div className="glass-panel" style={{ padding: '20px', height: '100%', cursor: 'pointer' }}>
              <div style={{ fontSize: '24px', marginBottom: '12px' }}>🔬</div>
              <h3 style={{ fontSize: '17px', marginBottom: '6px', color: '#00F0FF' }}>Single Image Inspector</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Deep extraction of EXIF/IPTC/XMP, Hex signature inspection, GPS map correlation, and steganography scanning.
              </p>
            </div>
          </Link>

          <Link href="/compare" style={{ textDecoration: 'none', color: 'inherit' }}>
            <div className="glass-panel" style={{ padding: '20px', height: '100%', cursor: 'pointer' }}>
              <div style={{ fontSize: '24px', marginBottom: '12px' }}>⚖️</div>
              <h3 style={{ fontSize: '17px', marginBottom: '6px', color: '#38BDF8' }}>Dual Tampering Comparator</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Side-by-side differential analysis highlighting edited timestamps, software tags, and stripped headers.
              </p>
            </div>
          </Link>

          <Link href="/batch-analysis" style={{ textDecoration: 'none', color: 'inherit' }}>
            <div className="glass-panel" style={{ padding: '20px', height: '100%', cursor: 'pointer' }}>
              <div style={{ fontSize: '24px', marginBottom: '12px' }}>📊</div>
              <h3 style={{ fontSize: '17px', marginBottom: '6px', color: '#A855F7' }}>Batch Analysis Matrix</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Multi-image triage pipeline sorting up to 15 files by suspicious tampering probability and CSV export.
              </p>
            </div>
          </Link>

          <Link href="/sanitize" style={{ textDecoration: 'none', color: 'inherit' }}>
            <div className="glass-panel" style={{ padding: '20px', height: '100%', cursor: 'pointer' }}>
              <div style={{ fontSize: '24px', marginBottom: '12px' }}>🛡️</div>
              <h3 style={{ fontSize: '17px', marginBottom: '6px', color: '#34D399' }}>Privacy Scrubber</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Strip sensitive GPS coordinates and personal camera identifiers while preserving image binary clarity.
              </p>
            </div>
          </Link>

          <Link href="/evidence" style={{ textDecoration: 'none', color: 'inherit' }}>
            <div className="glass-panel" style={{ padding: '20px', height: '100%', cursor: 'pointer' }}>
              <div style={{ fontSize: '24px', marginBottom: '12px' }}>🔏</div>
              <h3 style={{ fontSize: '17px', marginBottom: '6px', color: '#FBBF24' }}>Chain of Custody Sealer</h3>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Generate ISO 27037 compliant legal custody certificates with cryptographic SHA-256 seal tokens.
              </p>
            </div>
          </Link>
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
          <div>
            <h2 style={{ fontSize: '18px' }}>Recent Forensic Investigations</h2>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>Audit trail of recent image evidence examinations.</p>
          </div>
          <Link href="/inspect" className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '13px' }}>
            View Full Audit Log
          </Link>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-dim)', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.05em' }}>
                <th style={{ padding: '12px 16px' }}>Evidence ID</th>
                <th style={{ padding: '12px 16px' }}>File Name</th>
                <th style={{ padding: '12px 16px' }}>SHA-256 Fingerprint</th>
                <th style={{ padding: '12px 16px' }}>Verdict</th>
                <th style={{ padding: '12px 16px' }}>Timestamp</th>
                <th style={{ padding: '12px 16px' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: '#00F0FF' }}>CASE-2026-081</td>
                <td style={{ padding: '14px 16px', fontWeight: '600' }}>DSC_0492_evidence.jpg</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>a3f9c2...b912</td>
                <td style={{ padding: '14px 16px' }}><span className="badge badge-emerald">INTACT (AUTHENTIC)</span></td>
                <td style={{ padding: '14px 16px', color: 'var(--text-dim)' }}>2026-10-29 18:42</td>
                <td style={{ padding: '14px 16px' }}><Link href="/inspect" style={{ color: '#00F0FF', textDecoration: 'none' }}>Inspect</Link></td>
              </tr>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: '#00F0FF' }}>CASE-2026-079</td>
                <td style={{ padding: '14px 16px', fontWeight: '600' }}>suspect_scene_edit.jpg</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>e14b8a...c029</td>
                <td style={{ padding: '14px 16px' }}><span className="badge badge-rose">TAMPERED (EDITED)</span></td>
                <td style={{ padding: '14px 16px', color: 'var(--text-dim)' }}>2026-10-29 17:15</td>
                <td style={{ padding: '14px 16px' }}><Link href="/compare" style={{ color: '#F43F5E', textDecoration: 'none' }}>Compare</Link></td>
              </tr>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: '#00F0FF' }}>CASE-2026-078</td>
                <td style={{ padding: '14px 16px', fontWeight: '600' }}>traffic_cam_01.png</td>
                <td style={{ padding: '14px 16px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>98cb11...72df</td>
                <td style={{ padding: '14px 16px' }}><span className="badge badge-amber">ANOMALY DETECTED</span></td>
                <td style={{ padding: '14px 16px', color: 'var(--text-dim)' }}>2026-10-29 15:30</td>
                <td style={{ padding: '14px 16px' }}><Link href="/inspect" style={{ color: '#FBBF24', textDecoration: 'none' }}>Review</Link></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
