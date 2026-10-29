'use client';

import { useState } from 'react';

export default function BatchAnalysisPage() {
  const [batchResults, setBatchResults] = useState([
    { id: 1, name: 'scene_photo_01.jpg', size: '2.4 MB', sha256: 'a1b2c3d4...', software: 'Canon EOS R5', risk: 'CLEAN', riskColor: 'badge-emerald', anomalies: 0 },
    { id: 2, name: 'evidence_weapon_macro.jpg', size: '1.8 MB', sha256: 'f4e5d6c7...', software: 'Adobe Photoshop 2026', risk: 'SUSPICIOUS', riskColor: 'badge-rose', anomalies: 4 },
    { id: 3, name: 'traffic_junction_cctv.png', size: '4.2 MB', sha256: 'b9a8c7d6...', software: 'Hikvision NVR v4.2', risk: 'CLEAN', riskColor: 'badge-emerald', anomalies: 0 },
    { id: 4, name: 'suspect_phone_snapshot.heic', size: '3.1 MB', sha256: 'c3d4e5f6...', software: 'iOS 18.1 Camera', risk: 'GPS STRIPPED', riskColor: 'badge-amber', anomalies: 2 },
    { id: 5, name: 'document_scan_flatbed.tiff', size: '8.9 MB', sha256: 'd7e8f9a0...', software: 'Epson Scan v3.9', risk: 'CLEAN', riskColor: 'badge-emerald', anomalies: 0 },
  ]);

  const exportCSV = () => {
    let csv = 'ID,File Name,Size,SHA-256 Fingerprint,Software Tag,Risk Verdict,Anomalies Count\n';
    batchResults.forEach(r => {
      csv += `${r.id},"${r.name}","${r.size}","${r.sha256}","${r.software}","${r.risk}",${r.anomalies}\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `TRACE_Batch_Triage_Report_${Date.now()}.csv`;
    a.click();
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '26px' }}>Batch Forensic Triage Matrix</h1>
            <span className="badge badge-cyan">UP TO 15 FILES</span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
            Multi-image parallel intake pipeline sorting evidence by suspicious tampering probability and anomaly count.
          </p>
        </div>

        <button onClick={exportCSV} className="btn btn-cyber" style={{ fontSize: '13px' }}>
          📥 Export Batch Matrix (CSV)
        </button>
      </div>

      {/* Batch Overview KPI Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '16px',
      }}>
        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>BATCH INTAKE SIZE</div>
          <div style={{ fontSize: '28px', fontWeight: '800', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>5 Files</div>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>Total: 20.4 MB parsed</div>
        </div>

        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>INTEGRITY VERIFIED</div>
          <div style={{ fontSize: '28px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#34D399', marginTop: '4px' }}>3 Files (60%)</div>
          <div style={{ fontSize: '12px', color: '#34D399' }}>Zero discrepancies</div>
        </div>

        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>HIGH-PRIORITY SUSPECT</div>
          <div style={{ fontSize: '28px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#FB7185', marginTop: '4px' }}>1 File (20%)</div>
          <div style={{ fontSize: '12px', color: '#FB7185' }}>Secondary editor signature</div>
        </div>

        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>ANOMALIES FLAGGED</div>
          <div style={{ fontSize: '28px', fontWeight: '800', fontFamily: 'var(--font-mono)', color: '#FBBF24', marginTop: '4px' }}>6 Flags</div>
          <div style={{ fontSize: '12px', color: '#FBBF24' }}>Timestamp &amp; GPS drifts</div>
        </div>
      </div>

      {/* Batch Triage Table */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '17px', marginBottom: '16px' }}>Automated Triage Priority Ledger</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13px' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: 'var(--text-dim)', textTransform: 'uppercase', fontSize: '11px' }}>
                <th style={{ padding: '12px 14px' }}>#</th>
                <th style={{ padding: '12px 14px' }}>File Name</th>
                <th style={{ padding: '12px 14px' }}>File Size</th>
                <th style={{ padding: '12px 14px' }}>Identified Software</th>
                <th style={{ padding: '12px 14px' }}>Triage Verdict</th>
                <th style={{ padding: '12px 14px' }}>Anomalies</th>
                <th style={{ padding: '12px 14px' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {batchResults.map((r) => (
                <tr key={r.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                  <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>0{r.id}</td>
                  <td style={{ padding: '14px', fontWeight: '600', fontFamily: 'var(--font-mono)' }}>{r.name}</td>
                  <td style={{ padding: '14px', color: 'var(--text-muted)' }}>{r.size}</td>
                  <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', color: r.software.includes('Photoshop') ? '#FB7185' : '#00F0FF' }}>{r.software}</td>
                  <td style={{ padding: '14px' }}><span className={`badge ${r.riskColor}`}>{r.risk}</span></td>
                  <td style={{ padding: '14px', fontFamily: 'var(--font-mono)', fontWeight: '700', color: r.anomalies > 0 ? '#FB7185' : '#34D399' }}>{r.anomalies}</td>
                  <td style={{ padding: '14px' }}><span style={{ color: '#34D399', fontSize: '12px' }}>● Verified</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
