import React, { useState, useEffect } from 'react';
import { Shield, History, Settings2, Activity, ExternalLink } from 'lucide-react';
import ScanPage from './pages/ScanPage';
import HistoryPage from './pages/HistoryPage';
import PolicyPage from './pages/PolicyPage';
import ModelPage from './pages/ModelPage';
import { api } from './api/client';

import TechnicalHUD from './components/TechnicalHUD';

export default function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [health, setHealth] = useState({ status: 'connecting', version: '1.0.0' });

  useEffect(() => {
    async function checkHealth() {
      try {
        const res = await api.getHealth();
        setHealth(res);
      } catch (_) {
        setHealth({ status: 'offline', version: '1.0.0' });
      }
    }
    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-container">
      {/* ── Minimal Header ── */}
      <header className="app-header">
        <div className="header-inner">
          <div className="brand">
            <div className="brand-logo">PG</div>
            <div className="brand-text">
              <h1>PHISHGUARD</h1>
              <p>EXPLAINABLE ML THREAT RADAR</p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="nav-tabs">
            <button
              onClick={() => setActiveTab('scan')}
              className={`nav-tab mono ${activeTab === 'scan' ? 'active' : ''}`}
            >
              SCANNER
            </button>
            <button
              onClick={() => setActiveTab('history')}
              className={`nav-tab mono ${activeTab === 'history' ? 'active' : ''}`}
            >
              HISTORY
            </button>
            <button
              onClick={() => setActiveTab('policy')}
              className={`nav-tab mono ${activeTab === 'policy' ? 'active' : ''}`}
            >
              POLICY RULES
            </button>
            <button
              onClick={() => setActiveTab('model')}
              className={`nav-tab mono ${activeTab === 'model' ? 'active' : ''}`}
            >
              MODEL INSIGHTS
            </button>
          </nav>

          {/* Status Indicator */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                width: '7px',
                height: '7px',
                borderRadius: '50%',
                backgroundColor: health.status === 'ok' ? '#ffffff' : '#737373',
                display: 'inline-block',
              }}
            />
            <span className="mono text-muted" style={{ fontSize: '11px' }}>
              API: {health.status?.toUpperCase()}
            </span>
          </div>
        </div>
      </header>

      {/* ── Main View ── */}
      <main>
        <TechnicalHUD health={health} />
        {activeTab === 'scan' && <ScanPage />}
        {activeTab === 'history' && <HistoryPage />}
        {activeTab === 'policy' && <PolicyPage />}
        {activeTab === 'model' && <ModelPage />}
      </main>

      {/* ── Footer ── */}
      <footer
        style={{
          marginTop: '60px',
          borderTop: '1px solid var(--border-subtle)',
          paddingTop: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          fontSize: '11px',
          color: 'var(--text-muted)',
          fontFamily: 'var(--font-mono)',
        }}
      >
        <div>PHISHGUARD v{health.version || '1.0.0'} • ZERO-BIAS EXPLAINABLE ML</div>
        <div style={{ display: 'flex', gap: '16px' }}>
          <a href="http://localhost:8000/docs" target="_blank" rel="noopener noreferrer" style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            <span>OPENAPI DOCS</span>
            <ExternalLink size={11} />
          </a>
        </div>
      </footer>
    </div>
  );
}
