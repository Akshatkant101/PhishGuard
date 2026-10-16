import React from 'react';

export default function VerdictBadge({ verdict, className = '' }) {
  const v = (verdict || 'UNKNOWN').toUpperCase();

  let badgeClass = 'badge-suspicious';
  if (v === 'SAFE') {
    badgeClass = 'badge-safe';
  } else if (v === 'PHISHING') {
    badgeClass = 'badge-phishing';
  }

  return (
    <span className={`badge ${badgeClass} ${className}`}>
      [{v}]
    </span>
  );
}
