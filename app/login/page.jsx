'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';

export default function LoginPage() {
  const router = useRouter();
  const [userId, setUserId] = useState('Bhuvana@123');
  const [password, setPassword] = useState('123');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    // Authentication simulation & session storage
    setTimeout(() => {
      if (userId === 'Bhuvana@123' && password === '123') {
        if (typeof window !== 'undefined') {
          localStorage.setItem('trace_user_logged_in', 'true');
          localStorage.setItem('trace_user_id', userId);
        }
        router.push('/dashboard');
      } else {
        setError('Invalid Investigator ID or Passphrase. (Try Bhuvana@123 / 123)');
        setLoading(false);
      }
    }, 600);
  };

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: 'calc(100vh - 240px)',
      padding: '40px 16px',
    }}>
      <div className="glass-panel" style={{
        width: '100%',
        maxWidth: '460px',
        padding: '36px 32px',
        borderRadius: 'var(--radius-xl)',
        boxShadow: '0 20px 50px -10px rgba(0, 0, 0, 0.7), 0 0 24px -2px rgba(0, 240, 255, 0.2)',
      }}>
        {/* Header Badge & Title */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div style={{
            width: '48px',
            height: '48px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.15) 0%, rgba(59, 130, 246, 0.2) 100%)',
            border: '1px solid rgba(0, 240, 255, 0.4)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#00F0FF',
            fontSize: '22px',
            marginBottom: '16px',
            boxShadow: '0 0 16px rgba(0, 240, 255, 0.3)',
          }}>
            🔐
          </div>
          <h2 style={{ fontSize: '24px', marginBottom: '6px' }}>Investigator Sign In</h2>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
            Enter your credentials to access the forensic analysis workbench.
          </p>
        </div>

        {error && (
          <div style={{
            padding: '12px 16px',
            borderRadius: 'var(--radius-md)',
            background: 'rgba(244, 63, 94, 0.15)',
            border: '1px solid rgba(244, 63, 94, 0.4)',
            color: '#FB7185',
            fontSize: '13px',
            marginBottom: '20px',
          }}>
            ⚠️ {error}
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleLogin} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '13px', fontWeight: '600', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Investigator ID / Email
            </label>
            <input
              type="text"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '12px 14px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(7, 11, 20, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e) => e.target.style.borderColor = '#00F0FF'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-subtle)'}
            />
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '13px', fontWeight: '600', color: 'var(--text-muted)' }}>
                Passphrase
              </label>
              <span style={{ fontSize: '11px', color: '#00F0FF', fontFamily: 'var(--font-mono)' }}>
                Demo: 123
              </span>
            </div>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '12px 14px',
                borderRadius: 'var(--radius-md)',
                background: 'rgba(7, 11, 20, 0.8)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-main)',
                fontFamily: 'var(--font-mono)',
                fontSize: '14px',
                outline: 'none',
                transition: 'border-color 0.2s',
              }}
              onFocus={(e) => e.target.style.borderColor = '#00F0FF'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-subtle)'}
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ width: '100%', padding: '14px', fontSize: '15px', marginTop: '6px' }}
          >
            {loading ? 'Authenticating Investigator...' : 'Enter Forensics Lab →'}
          </button>

          <button
            type="button"
            onClick={() => {
              if (typeof window !== 'undefined') {
                localStorage.setItem('trace_user_logged_in', 'true');
                localStorage.setItem('trace_user_id', 'Bhuvana@123');
              }
              router.push('/dashboard');
            }}
            className="btn btn-secondary"
            style={{ width: '100%', padding: '12px', fontSize: '14px', marginTop: '8px', color: '#00F0FF', borderColor: 'rgba(0, 240, 255, 0.3)' }}
          >
            ⚡ One-Click Enter as Lead Analyst →
          </button>
        </form>

        {/* Demo Fast Fill Badge */}
        <div style={{
          marginTop: '24px',
          padding: '12px 14px',
          borderRadius: 'var(--radius-md)',
          background: 'rgba(0, 240, 255, 0.05)',
          border: '1px dashed rgba(0, 240, 255, 0.25)',
          fontSize: '12px',
          color: 'var(--text-dim)',
          textAlign: 'center',
        }}>
          💡 <strong>Demo Credentials Auto-Filled:</strong> Bhuvana@123 / 123
        </div>

        <div style={{ textAlign: 'center', marginTop: '20px', fontSize: '13px', color: 'var(--text-dim)' }}>
          <Link href="/" style={{ color: 'var(--text-muted)', textDecoration: 'none' }}>
            ← Back to Public Overview
          </Link>
        </div>
      </div>
    </div>
  );
}
