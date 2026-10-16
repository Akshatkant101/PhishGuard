import React, { useState } from 'react';
import { Copy, Check, ExternalLink, ChevronDown, ChevronUp, Activity, Lock, Globe, FileText, BarChart3, ShieldAlert } from 'lucide-react';
import VerdictBadge from './VerdictBadge';
import RiskMeter from './RiskMeter';
import ReasonsList from './ReasonsList';
import EnrichmentAdjustmentsList from './EnrichmentAdjustmentsList';
import FeatureInspector from './FeatureInspector';
import CyberRadarChart from './CyberRadarChart';
import ShapWaterfallChart from './ShapWaterfallChart';
import LatencyWaterfall from './LatencyWaterfall';

export default function ScanResultCard({ result }) {
  const [copied, setCopied] = useState(false);
  const [showEnrichmentDetails, setShowEnrichmentDetails] = useState(false);
  const [shapViewMode, setShapViewMode] = useState('waterfall'); // 'waterfall' | 'list'

  if (!result) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const hasScoreDelta =
    result.lexical_risk_score !== undefined &&
    result.lexical_risk_score !== null &&
    result.lexical_risk_score !== result.risk_score;

  const enr = result.enrichment || {};

  return (
    <div className="card animate-fade" style={{ marginTop: '24px' }}>
      <div className="card-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <VerdictBadge verdict={result.verdict} />
          <span className="mono" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            DOMAIN: {result.domain}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="mono text-muted" style={{ fontSize: '11px' }}>
            {result.latency_ms} ms
          </span>
          <button
            onClick={handleCopy}
            className="btn btn-secondary btn-icon"
            title="Copy URL"
          >
            {copied ? <Check size={14} /> : <Copy size={14} />}
          </button>
        </div>
      </div>

      {/* Target URL */}
      <div
        className="mono"
        style={{
          wordBreak: 'break-all',
          padding: '10px 14px',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-sm)',
          fontSize: '13px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '8px',
        }}
      >
        <span>{result.url}</span>
        <a
          href={result.url}
          target="_blank"
          rel="noopener noreferrer"
          title="Open in new tab (CAUTION: May be phishing)"
          style={{ opacity: 0.6 }}
        >
          <ExternalLink size={14} />
        </a>
      </div>

      {/* Dual Score Banner if Stage 2 enrichment shifted risk */}
      {hasScoreDelta && (
        <div
          className="mono"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            padding: '8px 12px',
            backgroundColor: 'var(--bg-secondary)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12px',
            marginBottom: '16px',
          }}
        >
          <span style={{ color: 'var(--text-secondary)' }}>
            BASE ML LEXICAL SCORE: <strong>{result.lexical_risk_score}/100</strong>
          </span>
          <span style={{ color: 'var(--text-primary)' }}>
            STAGE 2 ENRICHED SCORE: <strong>{result.risk_score}/100</strong> (
            {result.risk_score > result.lexical_risk_score
              ? `+${(result.risk_score - result.lexical_risk_score).toFixed(1)}`
              : (result.risk_score - result.lexical_risk_score).toFixed(1)}
            )
          </span>
        </div>
      )}

      {/* ── Top Threat Diagnostics: Risk Gauge & 6-Axis Radar Grid ── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
          marginBottom: '20px',
        }}
      >
        {/* Left: Risk Meter */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <RiskMeter
            score={result.risk_score}
            confidence={result.confidence}
            verdict={result.verdict}
          />
        </div>

        {/* Right: 6-Axis Cyber Threat Radar */}
        <div className="card" style={{ padding: '16px' }}>
          <CyberRadarChart result={result} />
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '20px' }}>
        {/* ── 1. Pure ML SHAP Explainability & Waterfall Graph ── */}
        <div className="card" style={{ padding: '18px' }}>
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '14px',
              flexWrap: 'wrap',
              gap: '8px',
            }}
          >
            <div className="card-title" style={{ fontSize: '12px' }}>
              ML EXPLAINABILITY (PURE TREEEXPLAINER SHAP VECTOR ATTRIBUTION)
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                onClick={() => setShapViewMode('waterfall')}
                className={`btn btn-sm mono ${shapViewMode === 'waterfall' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '10px', padding: '3px 8px' }}
              >
                WATERFALL GRAPH
              </button>
              <button
                onClick={() => setShapViewMode('list')}
                className={`btn btn-sm mono ${shapViewMode === 'list' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '10px', padding: '3px 8px' }}
              >
                IMPACT BARS
              </button>
            </div>
          </div>

          {shapViewMode === 'waterfall' ? (
            <ShapWaterfallChart
              reasons={result.reasons}
              baseScore={50.0}
              finalScore={result.lexical_risk_score ?? result.risk_score}
            />
          ) : (
            <ReasonsList reasons={result.reasons} />
          )}
        </div>

        {/* ── 2. Stage 2 Documented Rule-Based Adjustments ── */}
        {result.enrichment_reasons && result.enrichment_reasons.length > 0 && (
          <div className="card" style={{ padding: '16px' }}>
            <div className="card-title" style={{ fontSize: '12px', marginBottom: '12px' }}>
              STAGE 2 LIVE THREAT INTELLIGENCE (DOCUMENTED RULE ADJUSTMENTS)
            </div>
            <EnrichmentAdjustmentsList adjustments={result.enrichment_reasons} />
          </div>
        )}

        {/* ── 3. Pipeline Latency Execution Profile ── */}
        <div className="card" style={{ padding: '16px' }}>
          <LatencyWaterfall
            totalLatencyMs={result.latency_ms || 85}
            enrichmentActive={!!(enr && enr.live_enrichment_active)}
          />
        </div>

        {/* ── 4. Stage 2 Live Signals Telemetry Accordion ── */}
        {enr && enr.live_enrichment_active && (
          <div className="card" style={{ padding: '14px 16px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
              }}
              onClick={() => setShowEnrichmentDetails(!showEnrichmentDetails)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Activity size={15} color="#ffffff" />
                <span className="mono" style={{ fontSize: '12px', fontWeight: 600 }}>
                  STAGE 2 LIVE SIGNALS TELEMETRY (TLS / DNS / WHOIS / CONTENT)
                </span>
              </div>
              <button className="btn btn-secondary btn-icon" style={{ padding: '2px 6px' }}>
                {showEnrichmentDetails ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>
            </div>

            {showEnrichmentDetails && (
              <div
                className="mono"
                style={{
                  marginTop: '14px',
                  paddingTop: '12px',
                  borderTop: '1px solid var(--border-subtle)',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                  gap: '12px',
                  fontSize: '11px',
                }}
              >
                {/* TLS */}
                <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                    <Lock size={12} /> TLS CERTIFICATE
                  </div>
                  <div>Active: {enr.tls?.tls_active ? 'YES' : 'NO'}</div>
                  <div>Valid: {enr.tls?.tls_valid ? 'YES' : 'NO'}</div>
                  <div>Issuer: {enr.tls?.issuer || 'N/A'}</div>
                  <div>Expires In: {enr.tls?.days_until_expiration !== null ? `${enr.tls?.days_until_expiration}d` : 'N/A'}</div>
                </div>

                {/* DNS */}
                <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                    <Globe size={12} /> DNS RESOLUTION
                  </div>
                  <div>Resolves: {enr.dns?.resolves ? 'YES' : 'NO'}</div>
                  <div>Resolved IPs: {enr.dns?.ips?.slice(0, 2).join(', ') || 'None'}</div>
                </div>

                {/* WHOIS / RDAP */}
                <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                    <FileText size={12} /> DOMAIN AGE (RDAP)
                  </div>
                  <div>Age: {enr.domain_age?.domain_age_days !== null ? `${enr.domain_age?.domain_age_days} days` : 'N/A'}</div>
                  <div>Registered: {enr.domain_age?.created_date || 'N/A'}</div>
                  <div>Newly Registered: {enr.domain_age?.is_newly_registered ? 'YES (< 30d)' : 'NO'}</div>
                </div>

                {/* Page Content */}
                <div style={{ padding: '8px 10px', backgroundColor: 'var(--bg-secondary)', borderRadius: '4px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, marginBottom: '4px' }}>
                    <Activity size={12} /> CONTENT INSPECTION
                  </div>
                  <div>Fetched: {enr.content?.content_fetched ? 'YES' : 'NO'}</div>
                  <div>Password Field: {enr.content?.has_password_field ? 'DETECTED' : 'NONE'}</div>
                  <div>External Form: {enr.content?.has_external_form_action ? 'DETECTED' : 'NONE'}</div>
                  <div>External Link Ratio: {enr.content?.external_link_ratio ? `${(enr.content.external_link_ratio * 100).toFixed(0)}%` : '0%'}</div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Raw feature inspector */}
      <FeatureInspector features={result.features} />
    </div>
  );
}
