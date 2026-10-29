'use client';

import { useState } from 'react';
import Link from 'next/link';

export default function ComparePage() {
  const [comparison, setComparison] = useState(null);
  const [comparing, setComparing] = useState(false);

  const loadSampleComparison = () => {
    setComparing(true);
    setTimeout(() => {
      setComparison({
        fileA: {
          name: 'original_camera_capture.jpg',
          size: '3,842 KB',
          sha256: '8e1b4c92a6f7d02518e903bc4a5f6d7e8f90123456789abcdef0123456789abc',
          software: 'Canon EOS R5 Firmware v1.8.1',
          date: '2026:04:10 11:32:04',
          modifyDate: '2026:04:10 11:32:04',
          gps: '20.2961° N, 85.8245° E',
        },
        fileB: {
          name: 'suspect_evidence_tampered.jpg',
          size: '1,420 KB',
          sha256: '3f92d8e1c4a5b6071829304a5b6c7d8e9f0123456789abcdef0123456789def',
          software: 'Adobe Photoshop 26.0 (Windows)',
          date: '2026:04:10 11:32:04',
          modifyDate: '2026:10-28 19:40:12 (TAMPERED DRIFT)',
          gps: 'STRIPPED / REMOVED',
        },
        riskScore: 'CRITICAL (92/100)',
        verdict: 'TAMPERING DETECTED: Secondary Editing Software & Stripped Geolocation',
        anomalies: [
          { tag: 'Software', ref: 'Canon EOS R5 Firmware v1.8.1', suspect: 'Adobe Photoshop 26.0 (Windows)', severity: 'CRITICAL', note: 'Image was re-saved in editing software' },
          { tag: 'ModifyDate', ref: '2026:04:10 11:32:04', suspect: '2026:10:28 19:40:12', severity: 'HIGH', note: 'Modified timestamp differs by 201 days from original capture' },
          { tag: 'GPSLatitude', ref: '20.2961° N', suspect: 'Tag Removed', severity: 'HIGH', note: 'GPS coordinate metadata was stripped' },
          { tag: 'GPSLongitude', ref: '85.8245° E', suspect: 'Tag Removed', severity: 'HIGH', note: 'GPS coordinate metadata was stripped' },
          { tag: 'Compression', ref: 'JPEG (old-style)', suspect: 'Photoshop Save for Web', severity: 'MEDIUM', note: 'Quantization table replacement detected' },
        ]
      });
      setComparing(false);
    }, 400);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      {/* Title Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '26px' }}>Dual Metadata Tampering Comparator</h1>
            <span className="badge badge-rose">DIFFERENTIAL DETECTOR</span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
            Performs differential analysis between a Reference File (A) and a Questioned File (B) to detect manipulation.
          </p>
        </div>

        <button onClick={loadSampleComparison} className="btn btn-cyber" style={{ fontSize: '13px' }}>
          ⚡ Load Sample Tampered Evidence Pair
        </button>
      </div>

      {/* Dual Intake Columns */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '20px',
      }}>
        {/* Box A */}
        <div className="glass-panel" style={{ padding: '24px', borderTop: '4px solid #34D399' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h3 style={{ fontSize: '16px', color: '#34D399' }}>FILE A: Reference / Baseline</h3>
            <span className="badge badge-emerald">AUTHENTIC</span>
          </div>
          <div style={{
            padding: '28px 16px',
            borderRadius: 'var(--radius-md)',
            border: '2px dashed rgba(52, 211, 153, 0.3)',
            textAlign: 'center',
            background: 'rgba(7, 11, 20, 0.6)',
          }}>
            <div style={{ fontSize: '28px', marginBottom: '8px' }}>📁</div>
            <div style={{ fontSize: '14px', fontWeight: '600' }}>
              {comparison ? comparison.fileA.name : 'Select or Drop Baseline Image'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>
              {comparison ? `${comparison.fileA.size} • SHA-256 Verified` : 'Original unedited reference file'}
            </div>
          </div>
        </div>

        {/* Box B */}
        <div className="glass-panel" style={{ padding: '24px', borderTop: '4px solid #FB7185' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
            <h3 style={{ fontSize: '16px', color: '#FB7185' }}>FILE B: Questioned / Suspect</h3>
            <span className="badge badge-rose">QUESTIONED</span>
          </div>
          <div style={{
            padding: '28px 16px',
            borderRadius: 'var(--radius-md)',
            border: '2px dashed rgba(244, 63, 94, 0.3)',
            textAlign: 'center',
            background: 'rgba(7, 11, 20, 0.6)',
          }}>
            <div style={{ fontSize: '28px', marginBottom: '8px' }}>⚠️</div>
            <div style={{ fontSize: '14px', fontWeight: '600' }}>
              {comparison ? comparison.fileB.name : 'Select or Drop Suspect Image'}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>
              {comparison ? `${comparison.fileB.size} • Suspect Evidence` : 'Potentially manipulated file'}
            </div>
          </div>
        </div>
      </div>

      {comparing && (
        <div style={{ padding: '24px', textAlign: 'center', color: '#F43F5E', fontFamily: 'var(--font-mono)' }}>
          ⚖️ Calculating byte differentials, cross-referencing timestamps, and computing anomaly score...
        </div>
      )}

      {/* Comparison Analysis Results */}
      {comparison && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          {/* Verdict Banner */}
          <div style={{
            padding: '24px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.15) 0%, rgba(225, 29, 72, 0.1) 100%)',
            border: '1px solid rgba(244, 63, 94, 0.4)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '16px',
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
                <span className="badge badge-rose">VERDICT CONFIRMED</span>
                <span style={{ fontSize: '14px', fontWeight: '700', color: '#FB7185', fontFamily: 'var(--font-mono)' }}>
                  RISK: {comparison.riskScore}
                </span>
              </div>
              <h2 style={{ fontSize: '20px', color: '#FFFFFF' }}>{comparison.verdict}</h2>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
                5 conflicting metadata tags discovered between reference baseline and suspect evidence file.
              </p>
            </div>

            <Link href="/evidence" className="btn btn-cyber" style={{ fontSize: '13px' }}>
              📜 Seal in Chain of Custody
            </Link>
          </div>

          {/* Differential Tag Table */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '17px', marginBottom: '16px' }}>Differential Metadata Comparison Ledger</h3>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-dim)', textTransform: 'uppercase', fontSize: '11px' }}>
                    <th style={{ padding: '12px 14px' }}>Metadata Tag</th>
                    <th style={{ padding: '12px 14px' }}>Reference File A</th>
                    <th style={{ padding: '12px 14px' }}>Suspect File B</th>
                    <th style={{ padding: '12px 14px' }}>Severity</th>
                    <th style={{ padding: '12px 14px' }}>Forensic Finding</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.anomalies.map((item, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', background: idx % 2 === 0 ? 'rgba(7, 11, 20, 0.3)' : 'transparent' }}>
                      <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: '#00F0FF' }}>{item.tag}</td>
                      <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', color: '#34D399' }}>{item.ref}</td>
                      <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', color: '#FB7185', fontWeight: '700' }}>{item.suspect}</td>
                      <td style={{ padding: '14px' }}>
                        <span className={`badge ${item.severity === 'CRITICAL' ? 'badge-rose' : item.severity === 'HIGH' ? 'badge-amber' : 'badge-cyan'}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td style={{ padding: '14px', color: 'var(--text-muted)' }}>{item.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
