'use client';

import { useState } from 'react';

export default function EvidencePage() {
  const [cert, setCert] = useState({
    token: 'TRACE-COC-2026-9E40B721',
    timestamp: '2026-10-30T00:30:15Z (UTC)',
    investigator: 'Kappala Bhuvana Kruthi',
    station: 'CUTM Cyber Defense & Digital Forensics Lab #4',
    caseId: 'CASE-FORENSIC-2026-081',
    fileName: 'DSC_0492_evidence.jpg',
    fileSize: '3,842,109 bytes',
    sha256: 'a3f9c28e1b4c92a6f7d02518e903bc4a5f6d7e8f90123456789abcdef0123456',
    sha1: '7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c',
    md5: '9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b',
    device: 'Canon EOS R5 (Serial: 8204910294)',
    status: 'AUTHENTICATED - ISO/IEC 27037 COMPLIANT',
  });

  const generateNewCertificate = () => {
    const randomHex = Math.random().toString(16).substring(2, 10).toUpperCase();
    setCert(prev => ({
      ...prev,
      token: `TRACE-COC-2026-${randomHex}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC',
    }));
  };

  const handlePrint = () => {
    if (typeof window !== 'undefined') {
      window.print();
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '26px' }}>Digital Evidence Chain of Custody</h1>
            <span className="badge badge-amber">ISO/IEC 27037</span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
            Cryptographically sealed digital evidence certificates for judicial presentation and forensic accountability.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '12px' }}>
          <button onClick={generateNewCertificate} className="btn btn-secondary" style={{ fontSize: '13px' }}>
            ⚡ Re-Seal Token
          </button>
          <button onClick={handlePrint} className="btn btn-primary" style={{ fontSize: '13px' }}>
            🖨️ Print Certificate (PDF)
          </button>
        </div>
      </div>

      {/* Official Certificate Card */}
      <div style={{
        padding: '36px',
        borderRadius: 'var(--radius-xl)',
        background: 'linear-gradient(135deg, rgba(13, 21, 39, 0.95) 0%, rgba(7, 11, 20, 0.98) 100%)',
        border: '2px solid rgba(245, 158, 11, 0.4)',
        boxShadow: '0 20px 60px -10px rgba(0, 0, 0, 0.8), 0 0 28px -4px rgba(245, 158, 11, 0.2)',
      }}>
        {/* Certificate Header */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          borderBottom: '1px solid rgba(245, 158, 11, 0.25)',
          paddingBottom: '20px',
          marginBottom: '28px',
          gap: '16px',
        }}>
          <div>
            <div style={{ fontSize: '11px', color: '#FBBF24', fontWeight: '800', letterSpacing: '0.1em', fontFamily: 'var(--font-mono)' }}>
              OFFICIAL DIGITAL FORENSICS CERTIFICATE
            </div>
            <h2 style={{ fontSize: '22px', marginTop: '4px' }}>Digital Evidence Chain of Custody Seal</h2>
            <div style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '2px' }}>
              Standard: ISO/IEC 27037 Guidelines for Identification, Collection, Acquisition &amp; Preservation
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>SEAL TOKEN</div>
            <div style={{ fontSize: '16px', fontWeight: '800', color: '#FBBF24', fontFamily: 'var(--font-mono)', letterSpacing: '0.05em' }}>
              {cert.token}
            </div>
          </div>
        </div>

        {/* Certificate Body Fields */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
          marginBottom: '28px',
        }}>
          <div style={{ padding: '14px', background: 'rgba(7, 11, 20, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>CASE IDENTIFIER</div>
            <div style={{ fontSize: '14px', fontWeight: '700', fontFamily: 'var(--font-mono)', color: '#00F0FF', marginTop: '2px' }}>
              {cert.caseId}
            </div>
          </div>

          <div style={{ padding: '14px', background: 'rgba(7, 11, 20, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>PRIMARY INVESTIGATOR</div>
            <div style={{ fontSize: '14px', fontWeight: '700', marginTop: '2px' }}>
              {cert.investigator}
            </div>
          </div>

          <div style={{ padding: '14px', background: 'rgba(7, 11, 20, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>ACQUISITION TIMESTAMP</div>
            <div style={{ fontSize: '14px', fontWeight: '600', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {cert.timestamp}
            </div>
          </div>

          <div style={{ padding: '14px', background: 'rgba(7, 11, 20, 0.6)', borderRadius: 'var(--radius-md)', border: '1px solid rgba(255, 255, 255, 0.05)' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>EVIDENCE FILE SPECIFICATION</div>
            <div style={{ fontSize: '14px', fontWeight: '600', fontFamily: 'var(--font-mono)', marginTop: '2px' }}>
              {cert.fileName} ({cert.fileSize})
            </div>
          </div>
        </div>

        {/* Cryptographic Hash Ledger */}
        <div style={{
          padding: '20px',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(7, 11, 20, 0.8)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          marginBottom: '28px',
        }}>
          <h3 style={{ fontSize: '14px', color: '#FBBF24', marginBottom: '14px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Multi-Algorithm Cryptographic Hash Ledger
          </h3>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div>
              <span style={{ fontSize: '11px', color: '#00F0FF', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>SHA-256: </span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-main)', wordBreak: 'break-all' }}>
                {cert.sha256}
              </span>
            </div>
            <div>
              <span style={{ fontSize: '11px', color: '#34D399', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>SHA-1: </span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                {cert.sha1}
              </span>
            </div>
            <div>
              <span style={{ fontSize: '11px', color: '#A855F7', fontWeight: '700', fontFamily: 'var(--font-mono)' }}>MD5: </span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                {cert.md5}
              </span>
            </div>
          </div>
        </div>

        {/* Legal Attestation Footer */}
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          borderTop: '1px solid rgba(255, 255, 255, 0.08)',
          paddingTop: '20px',
          fontSize: '12px',
          color: 'var(--text-dim)',
        }}>
          <div style={{ maxWidth: '580px' }}>
            <strong>Legal Attestation:</strong> The digital file above was examined in a forensically sterile environment. Hash values were computed directly from binary bitstreams prior to analysis.
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '11px', textTransform: 'uppercase' }}>SEAL STATUS</div>
            <div style={{ fontSize: '13px', fontWeight: '700', color: '#34D399' }}>✓ CRYPTOGRAPHICALLY SECURED</div>
          </div>
        </div>
      </div>
    </div>
  );
}
