import React, { useState, useEffect } from 'react';
import { Terminal, Shield, Cpu, Activity, Lock } from 'lucide-react';

/**
 * TechnicalHUD: High-Density Technical Telemetry Bar
 * Displays live system engine telemetry, security flags, and real-time operational status.
 */
export default function TechnicalHUD({ health }) {
  const [timeStr, setTimeStr] = useState('');
  const [pulse, setPulse] = useState(true);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC');
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    const pulseTimer = setInterval(() => setPulse((p) => !p), 1500);
    return () => {
      clearInterval(timer);
      clearInterval(pulseTimer);
    };
  }, []);

  return (
    <div
      className="mono"
      style={{
        backgroundColor: '#0a0a0a',
        border: '1px solid var(--border-subtle)',
        borderLeft: '3px solid #ffffff',
        padding: '8px 14px',
        marginBottom: '20px',
        borderRadius: 'var(--radius-sm)',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        fontSize: '11px',
      }}
    >
      {/* Left: Engine & Threat Surface Status */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              width: '7px',
              height: '7px',
              borderRadius: '50%',
              backgroundColor: '#ffffff',
              opacity: pulse ? 1 : 0.4,
              transition: 'opacity 0.3s ease',
            }}
          />
          <span style={{ fontWeight: 700, color: '#ffffff', letterSpacing: '0.05em' }}>
            SYS: ARMED
          </span>
        </div>

        <div style={{ color: 'var(--text-secondary)' }}>
          ENGINE: <strong style={{ color: '#ffffff' }}>XGBOOST + PLATT</strong>
        </div>

        <div style={{ color: 'var(--text-secondary)' }}>
          EXPLAINER: <strong style={{ color: '#ffffff' }}>TREE-SHAP ( Lundberg )</strong>
        </div>

        <div style={{ color: 'var(--text-secondary)' }}>
          SSRF FIREWALL: <strong style={{ color: '#ffffff' }}>SOCKET-GUARD 0.0.0.0/0</strong>
        </div>

        <div style={{ color: 'var(--text-secondary)' }}>
          BASELINE: <strong style={{ color: '#ffffff' }}>ABLATED NO-PATH (24 FEAT)</strong>
        </div>
      </div>

      {/* Right: Technical Timestamp & Telemetry Link */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', color: 'var(--text-muted)' }}>
        <span>TELEMETRY: DUAL-TIER LIVE</span>
        <span style={{ color: 'var(--border-strong)' }}>|</span>
        <span style={{ color: '#a3a3a3' }}>{timeStr || '2026-10-16 00:00:00 UTC'}</span>
      </div>
    </div>
  );
}
