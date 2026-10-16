import React, { useState } from 'react';
import { ChevronDown, ChevronUp } from 'lucide-react';

export default function FeatureInspector({ features = {} }) {
  const [open, setOpen] = useState(false);
  const keys = Object.keys(features);

  if (keys.length === 0) return null;

  return (
    <div style={{ marginTop: '16px', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
      <button
        onClick={() => setOpen(!open)}
        className="btn btn-secondary btn-sm"
        style={{ width: '100%', justifyContent: 'space-between', fontFamily: 'var(--font-mono)' }}
      >
        <span>RAW FEATURE VECTOR ({keys.length} FEATURES)</span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>

      {open && (
        <div style={{ marginTop: '12px' }} className="animate-fade">
          <div className="table-container" style={{ maxHeight: '320px', overflowY: 'auto' }}>
            <table className="minimal-table">
              <thead>
                <tr>
                  <th>Feature Name</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k}>
                    <td className="mono" style={{ color: 'var(--text-secondary)' }}>
                      {k}
                    </td>
                    <td className="mono" style={{ color: features[k] > 0 ? '#ffffff' : 'var(--text-muted)' }}>
                      {features[k]}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
