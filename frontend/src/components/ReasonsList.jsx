import React from 'react';

export default function ReasonsList({ reasons = [] }) {
  if (!reasons || reasons.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '12px 0' }}>
        No significant contributing signals detected.
      </div>
    );
  }

  // Find max absolute impact to normalize bar lengths
  const maxImpact = Math.max(...reasons.map((r) => Math.abs(r.impact || 1)), 1.0);

  return (
    <div style={{ width: '100%' }}>
      {reasons.map((item, idx) => {
        const isSuspicious = item.direction === 'suspicious';
        const impactRatio = Math.min(100, Math.round((Math.abs(item.impact) / maxImpact) * 100));

        return (
          <div key={idx} className="reason-row">
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                <span
                  className="mono"
                  style={{
                    fontSize: '10px',
                    padding: '1px 6px',
                    border: '1px solid ' + (isSuspicious ? '#ffffff' : '#525252'),
                    backgroundColor: isSuspicious ? '#ffffff' : 'transparent',
                    color: isSuspicious ? '#000000' : '#a3a3a3',
                    fontWeight: 600,
                  }}
                >
                  {isSuspicious ? '+ RISK' : '- RISK'}
                </span>
                <span className="mono" style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {item.feature}
                </span>
                <span className="mono text-muted" style={{ fontSize: '11px' }}>
                  (val: {item.value})
                </span>
              </div>
              <div style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                {item.description}
              </div>
            </div>

            {/* Impact visualization */}
            <div className="impact-bar-container">
              <div className="impact-track">
                <div
                  className="impact-fill"
                  style={{
                    width: `${impactRatio}%`,
                    backgroundColor: isSuspicious ? '#ffffff' : '#737373',
                  }}
                />
              </div>
              <span className="mono" style={{ fontSize: '11px', color: 'var(--text-muted)', width: '36px', textAlign: 'right' }}>
                {item.impact > 0 ? `+${item.impact}` : item.impact}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
