import React from 'react';

export default function RiskMeter({ score = 0, confidence = 0, verdict = 'SAFE' }) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  const confPct = Math.round((confidence || 0) * 100);

  // 10-step segmented bar for stark minimalist terminal aesthetic
  const segments = 10;
  const activeSegments = Math.round((clampedScore / 100) * segments);

  return (
    <div className="risk-meter">
      <div className="risk-number">{clampedScore}</div>
      <div className="risk-label">RISK SCORE (0 - 100)</div>

      {/* Segmented Monochrome Bar */}
      <div style={{ display: 'flex', gap: '4px', width: '80%', maxWidth: '280px', margin: '16px 0 10px 0' }}>
        {Array.from({ length: segments }).map((_, i) => (
          <div
            key={i}
            style={{
              flex: 1,
              height: '8px',
              backgroundColor: i < activeSegments ? '#ffffff' : '#262626',
              borderRadius: '1px',
              transition: 'background-color 0.2s ease',
            }}
          />
        ))}
      </div>

      <div style={{ display: 'flex', gap: '16px', fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
        <span>CONFIDENCE: {confPct}%</span>
        <span>•</span>
        <span>VERDICT: {verdict}</span>
      </div>
    </div>
  );
}
