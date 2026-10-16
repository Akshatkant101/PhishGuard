import React from 'react';
import { ShieldAlert, ShieldCheck } from 'lucide-react';

export default function EnrichmentAdjustmentsList({ adjustments = [] }) {
  if (!adjustments || adjustments.length === 0) {
    return (
      <div style={{ color: 'var(--text-muted)', fontSize: '12px', padding: '8px 0' }}>
        No rule-based score modifications applied. Final score equals base ML lexical score.
      </div>
    );
  }

  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', gap: '8px' }}>
      {adjustments.map((item, idx) => {
        const isSuspicious = item.direction === 'suspicious' || item.points > 0;
        const ptsSign = item.points > 0 ? `+${item.points.toFixed(1)}` : `${item.points.toFixed(1)}`;

        return (
          <div
            key={idx}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '12px',
              padding: '10px 12px',
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
            }}
          >
            <div style={{ marginTop: '2px' }}>
              {isSuspicious ? (
                <ShieldAlert size={16} color="#ffffff" />
              ) : (
                <ShieldCheck size={16} color="#a3a3a3" />
              )}
            </div>

            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '3px' }}>
                <span
                  className="mono"
                  style={{
                    fontSize: '11px',
                    fontWeight: 700,
                    padding: '1px 6px',
                    borderRadius: '2px',
                    backgroundColor: isSuspicious ? '#ffffff' : '#262626',
                    color: isSuspicious ? '#000000' : '#e5e5e5',
                    border: '1px solid ' + (isSuspicious ? '#ffffff' : '#404040'),
                  }}
                >
                  {ptsSign} PTS
                </span>
                <span className="mono" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  SIGNAL: {item.signal}
                </span>
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                {item.description}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
