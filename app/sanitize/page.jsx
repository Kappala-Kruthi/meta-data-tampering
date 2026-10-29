'use client';

import { useState } from 'react';

export default function SanitizePage() {
  const [scrubMode, setScrubMode] = useState('complete');
  const [sanitizing, setSanitizing] = useState(false);
  const [sanitizedData, setSanitizedData] = useState(null);

  const runSanitization = () => {
    setSanitizing(true);
    setTimeout(() => {
      setSanitizedData({
        originalName: 'crime_scene_exhibit_A.jpg',
        originalSize: '3,240 KB',
        sanitizedName: 'crime_scene_exhibit_A_sanitized.jpg',
        sanitizedSize: '3,212 KB',
        reduction: '28.0 KB (0.86% size reduction)',
        modeUsed: scrubMode === 'complete' ? 'Complete Forensic Metadata Wipe' : 'Selective Geolocation Scrub',
        strippedTags: [
          'GPSLatitude (20.2961 N)',
          'GPSLongitude (85.8245 E)',
          'GPSAltitude (45 m Above Sea Level)',
          'CameraSerialNumber (8204910294)',
          'LensSerialNumber (910248102)',
          'OwnerName (Detective B. Kruthi)',
          'XPAuthor (Cyber Forensics Division)',
          'Software (Camera Firmware Build)',
          'ModifyDate (2026:05:14 14:22:18)',
        ]
      });
      setSanitizing(false);
    }, 500);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '26px' }}>Privacy Sanitizer &amp; Metadata Scrubber</h1>
            <span className="badge badge-emerald">ZERO PRIVACY LEAK</span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
            Safely purges sensitive GPS coordinates, camera serial numbers, and investigator identities before publishing media.
          </p>
        </div>

        <button onClick={runSanitization} className="btn btn-primary" style={{ fontSize: '13px' }}>
          🛡️ Run Scrubbing Demonstration
        </button>
      </div>

      {/* Mode Selector */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <h3 style={{ fontSize: '16px', marginBottom: '14px' }}>Select Scrubbing Policy</h3>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
        }}>
          <div
            onClick={() => setScrubMode('complete')}
            style={{
              padding: '18px',
              borderRadius: 'var(--radius-md)',
              border: `2px solid ${scrubMode === 'complete' ? '#00F0FF' : 'rgba(255, 255, 255, 0.08)'}`,
              background: scrubMode === 'complete' ? 'rgba(0, 240, 255, 0.08)' : 'rgba(7, 11, 20, 0.6)',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <strong style={{ color: scrubMode === 'complete' ? '#00F0FF' : 'var(--text-main)' }}>
                Complete Metadata Wipe (Recommended)
              </strong>
              <span className="badge badge-cyan">ALL TAGS</span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Strips all standardized EXIF, IPTC, and XMP blocks. Guarantees 0% privacy leakage for sensitive releases.
            </p>
          </div>

          <div
            onClick={() => setScrubMode('gps_only')}
            style={{
              padding: '18px',
              borderRadius: 'var(--radius-md)',
              border: `2px solid ${scrubMode === 'gps_only' ? '#34D399' : 'rgba(255, 255, 255, 0.08)'}`,
              background: scrubMode === 'gps_only' ? 'rgba(52, 211, 153, 0.08)' : 'rgba(7, 11, 20, 0.6)',
              cursor: 'pointer',
              transition: 'all 0.2s',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
              <strong style={{ color: scrubMode === 'gps_only' ? '#34D399' : 'var(--text-main)' }}>
                Selective GPS-Only Scrub
              </strong>
              <span className="badge badge-emerald">GPS ONLY</span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
              Selectively wipes latitude, longitude, and altitude while retaining camera technical exposure metrics.
            </p>
          </div>
        </div>
      </div>

      {sanitizing && (
        <div style={{ padding: '24px', textAlign: 'center', color: '#10B981', fontFamily: 'var(--font-mono)' }}>
          🛡️ Scrubbing binary header blocks, zeroing GPS markers, and recalculating container size...
        </div>
      )}

      {/* Sanitization Results */}
      {sanitizedData && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{
            padding: '24px',
            borderRadius: 'var(--radius-lg)',
            background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(5, 150, 105, 0.1) 100%)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '16px',
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span className="badge badge-emerald">SCRUB COMPLETE</span>
                <span style={{ fontSize: '13px', color: '#34D399', fontFamily: 'var(--font-mono)' }}>
                  {sanitizedData.reduction}
                </span>
              </div>
              <h2 style={{ fontSize: '18px' }}>File Sanitized Successfully: {sanitizedData.sanitizedName}</h2>
              <p style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
                Policy: {sanitizedData.modeUsed} • {sanitizedData.strippedTags.length} sensitive metadata tags eliminated.
              </p>
            </div>

            <button
              onClick={() => alert('Download demonstration triggered for ' + sanitizedData.sanitizedName)}
              className="btn btn-primary"
              style={{ background: '#10B981', color: '#070B14' }}
            >
              ⬇ Download Sanitized Image
            </button>
          </div>

          {/* Stripped Tags Ledger */}
          <div className="glass-panel" style={{ padding: '24px' }}>
            <h3 style={{ fontSize: '16px', marginBottom: '14px' }}>Eliminated Metadata Tags Ledger</h3>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
              gap: '10px',
            }}>
              {sanitizedData.strippedTags.map((tag, idx) => (
                <div key={idx} style={{
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  background: 'rgba(7, 11, 20, 0.6)',
                  border: '1px solid rgba(255, 255, 255, 0.05)',
                  fontSize: '13px',
                  fontFamily: 'var(--font-mono)',
                  color: '#FB7185',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                }}>
                  <span>✗</span> {tag}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
