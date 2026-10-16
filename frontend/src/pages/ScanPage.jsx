import React, { useState } from 'react';
import { Search, Loader2, ListFilter, ArrowRight } from 'lucide-react';
import { api } from '../api/client';
import ScanResultCard from '../components/ScanResultCard';
import VerdictBadge from '../components/VerdictBadge';

const SAMPLE_URLS = [
  { label: 'Legitimate (Google)', url: 'https://www.google.com/search?q=cybersecurity' },
  { label: 'Legitimate (Wikipedia)', url: 'https://en.wikipedia.org/wiki/Phishing' },
  { label: 'PayPal Impersonator', url: 'http://paypal-security-update.account-verification.xyz/login.php' },
  { label: 'Raw IP Host', url: 'http://192.168.1.1/admin/login' },
  { label: 'Suspicious TLD', url: 'http://secure-banking-alert.top/verify' },
];

export default function ScanPage({ onScanComplete }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  // Batch scan state
  const [isBatchMode, setIsBatchMode] = useState(false);
  const [batchUrls, setBatchUrls] = useState('');
  const [batchResults, setBatchResults] = useState(null);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    try {
      const res = await api.scanUrl(url);
      setResult(res);
      if (onScanComplete) onScanComplete(res);
    } catch (err) {
      setError(err.message || 'Failed to scan URL');
    } finally {
      setLoading(false);
    }
  };

  const handleBatchScan = async (e) => {
    if (e) e.preventDefault();
    const list = batchUrls
      .split('\n')
      .map((u) => u.trim())
      .filter(Boolean);

    if (list.length === 0) return;

    setLoading(true);
    setError(null);
    try {
      const res = await api.scanBatch(list);
      setBatchResults(res);
    } catch (err) {
      setError(err.message || 'Batch scan failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="animate-fade">
      {/* Mode switcher */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
        <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
          MODE: {isBatchMode ? 'BATCH_SCANNER' : 'SINGLE_SCANNER'}
        </div>
        <button
          onClick={() => {
            setIsBatchMode(!isBatchMode);
            setError(null);
          }}
          className="btn btn-secondary btn-sm mono"
        >
          {isBatchMode ? 'SWITCH TO SINGLE SCAN' : 'SWITCH TO BATCH SCAN'}
        </button>
      </div>

      {!isBatchMode ? (
        /* ── Single URL Scanner ── */
        <div>
          <form onSubmit={handleScan}>
            <div style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                placeholder="Enter URL to analyze (e.g., https://example.com/login)..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="input-text mono"
                autoFocus
              />
              <button type="submit" className="btn btn-primary" disabled={loading || !url.trim()}>
                {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
                <span>ANALYZE</span>
              </button>
            </div>
          </form>

          {/* Quick Test Samples */}
          <div style={{ marginTop: '16px', display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center' }}>
            <span className="mono text-muted" style={{ fontSize: '11px' }}>
              TEST SAMPLES:
            </span>
            {SAMPLE_URLS.map((item, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => {
                  setUrl(item.url);
                  setError(null);
                }}
                className="btn btn-secondary btn-sm mono"
                style={{ fontSize: '11px', padding: '3px 8px' }}
              >
                {item.label}
              </button>
            ))}
          </div>

          {error && (
            <div
              className="card mono"
              style={{
                marginTop: '20px',
                borderColor: '#ffffff',
                color: '#ffffff',
                backgroundColor: 'var(--bg-secondary)',
                fontSize: '13px',
              }}
            >
              [ERROR]: {error}
            </div>
          )}

          {/* Result Card or Standby Diagnostic State */}
          {result ? (
            <ScanResultCard result={result} />
          ) : (
            <div
              className="card mono"
              style={{
                marginTop: '28px',
                padding: '24px',
                border: '1px dashed var(--border-strong)',
                backgroundColor: 'var(--bg-secondary)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#ffffff' }}>
                  AWAITING INGESTION // SCAN ENGINE IDLE
                </span>
                <span className="mono text-muted" style={{ fontSize: '11px' }}>
                  TARGET_STATUS: UNSET • SSRF GUARD: ARMED
                </span>
              </div>

              {/* Technical Pipeline Topology */}
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
                  gap: '8px',
                  marginBottom: '18px',
                }}
              >
                {[
                  { step: '01', title: 'URL PARSING', sub: 'Canonical www normalization' },
                  { step: '02', title: 'FEATURE INGEST', sub: '24 invariant ratio features' },
                  { step: '03', title: 'XGBOOST ML', sub: 'Platt calibrated inference' },
                  { step: '04', title: 'SHAP ATTRIBUTION', sub: 'TreeExplainer local math' },
                  { step: '05', title: 'STAGE 2 ENRICH', sub: 'TLS, DNS, RDAP, SSRF Guard' },
                ].map((s) => (
                  <div
                    key={s.step}
                    style={{
                      padding: '10px 12px',
                      backgroundColor: 'var(--bg-card)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '2px',
                    }}
                  >
                    <div style={{ color: 'var(--text-muted)', fontSize: '10px' }}>PHASE {s.step}</div>
                    <div style={{ color: '#ffffff', fontWeight: 600, fontSize: '11px', marginTop: '2px' }}>
                      {s.title}
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '9px', marginTop: '2px' }}>
                      {s.sub}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ fontSize: '11px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Select a test sample above or input any enterprise URL to generate the 6-Axis Threat Radar, SHAP Waterfall Attribution vector graph, Stage 2 live telemetry breakdown, and execution latency waterfall.
              </div>
            </div>
          )}
        </div>
      ) : (
        /* ── Batch URL Scanner ── */
        <div>
          <form onSubmit={handleBatchScan}>
            <div className="card">
              <div className="card-header">
                <span className="card-title">BATCH URL ANALYSIS (ONE URL PER LINE, UP TO 50)</span>
              </div>
              <textarea
                rows={6}
                placeholder="https://example.com/one&#10;https://example.com/two&#10;http://phish-site.xyz/login"
                value={batchUrls}
                onChange={(e) => setBatchUrls(e.target.value)}
                className="input-text mono"
                style={{ resize: 'vertical' }}
              />
              <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
                <button type="submit" className="btn btn-primary" disabled={loading || !batchUrls.trim()}>
                  {loading ? <Loader2 size={16} /> : <ArrowRight size={16} />}
                  <span>START BATCH ANALYSIS</span>
                </button>
              </div>
            </div>
          </form>

          {error && (
            <div
              className="card mono"
              style={{
                marginTop: '20px',
                borderColor: '#ffffff',
                color: '#ffffff',
                backgroundColor: 'var(--bg-secondary)',
                fontSize: '13px',
              }}
            >
              [ERROR]: {error}
            </div>
          )}

          {batchResults && (
            <div className="card animate-fade" style={{ marginTop: '24px' }}>
              <div className="card-header">
                <span className="card-title">
                  BATCH RESULTS ({batchResults.total} ANALYZED IN {batchResults.processing_time_ms} MS)
                </span>
              </div>
              <div className="table-container">
                <table className="minimal-table">
                  <thead>
                    <tr>
                      <th>Verdict</th>
                      <th>Risk Score</th>
                      <th>Domain</th>
                      <th>URL</th>
                      <th>Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {batchResults.results.map((r, i) => (
                      <tr key={i}>
                        <td>
                          <VerdictBadge verdict={r.verdict} />
                        </td>
                        <td className="mono" style={{ fontWeight: 600 }}>
                          {r.risk_score} / 100
                        </td>
                        <td className="mono text-secondary">{r.domain}</td>
                        <td className="mono" style={{ maxWidth: '320px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {r.url}
                        </td>
                        <td className="mono text-muted">{r.latency_ms} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
