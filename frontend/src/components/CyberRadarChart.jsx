import React from 'react';

/**
 * CyberRadarChart: 6-Axis Cybersecurity Risk Surface Radar
 * Renders an interactive SVG spider/radar chart in black & white minimal aesthetic.
 */
export default function CyberRadarChart({ result }) {
  if (!result) return null;

  const f = result.features || {};
  const enr = result.enrichment || {};

  // Compute 6 normalized risk dimensions (0 to 100 scale)
  // 1. Lexical & Entropy Risk
  const entropyVal = f.domain_entropy || 2.5;
  const entropyRisk = Math.min(100, Math.max(10, Math.round((entropyVal / 4.8) * 90 + (f.domain_digit_ratio || 0) * 30)));

  // 2. Brand Impersonation Risk
  const brandRisk = f.brand_in_subdomain ? 95 : f.brand_in_domain ? 75 : f.brand_impersonation ? 85 : 10;

  // 3. TLS Integrity & Certificate Risk (inverted: high score = high risk)
  let tlsRisk = 20; // default benign
  if (enr.tls) {
    if (!enr.tls.tls_active) tlsRisk = 80;
    else if (!enr.tls.tls_valid) tlsRisk = 95;
    else if (enr.tls.days_until_expiration !== null && enr.tls.days_until_expiration < 14) tlsRisk = 70;
    else tlsRisk = 15;
  } else if (!f.is_https) {
    tlsRisk = 75;
  }

  // 4. DNS & Infrastructure Risk
  let dnsRisk = 15;
  if (enr.dns) {
    if (!enr.dns.resolves) dnsRisk = 90;
    else if (f.has_ip_address) dnsRisk = 85;
    else if (f.subdomain_count >= 2) dnsRisk = 65;
    else dnsRisk = 20;
  } else if (f.has_ip_address) {
    dnsRisk = 85;
  }

  // 5. Domain Age & Registration Risk (new = high risk, mature = low risk)
  let ageRisk = 30;
  if (enr.domain_age) {
    if (enr.domain_age.is_newly_registered) ageRisk = 95;
    else if (enr.domain_age.domain_age_days !== null) {
      if (enr.domain_age.domain_age_days < 90) ageRisk = 70;
      else if (enr.domain_age.domain_age_days > 730) ageRisk = 10;
      else ageRisk = 35;
    }
  }

  // 6. Content & Harvesting Risk
  let contentRisk = 15;
  if (enr.content) {
    if (enr.content.has_password_field && enr.content.has_external_form_action) contentRisk = 98;
    else if (enr.content.has_password_field) contentRisk = 75;
    else if (enr.content.has_external_form_action) contentRisk = 70;
    else if (enr.content.has_hidden_iframe) contentRisk = 80;
    else if ((enr.content.external_link_ratio || 0) > 0.8) contentRisk = 65;
  }

  const axes = [
    { label: 'LEXICAL / ENTROPY', value: entropyRisk, code: `H=${entropyVal.toFixed(2)}` },
    { label: 'BRAND SPOOF', value: brandRisk, code: brandRisk > 50 ? 'FLAGGED' : 'CLEAR' },
    { label: 'TLS / SSL TRUST', value: tlsRisk, code: tlsRisk > 50 ? 'UNTRUSTED' : 'SECURE' },
    { label: 'DNS / NETWORK', value: dnsRisk, code: dnsRisk > 50 ? 'ANOMALOUS' : 'RESOLVED' },
    { label: 'DOMAIN AGE', value: ageRisk, code: ageRisk > 50 ? 'NEW (<90d)' : 'ESTABLISHED' },
    { label: 'CONTENT / HARVEST', value: contentRisk, code: contentRisk > 50 ? 'HARVEST_RISK' : 'BENIGN' },
  ];

  // Radar geometry
  const size = 300;
  const center = size / 2;
  const radius = 105;
  const angleStep = (Math.PI * 2) / axes.length;

  // Grid levels (20%, 40%, 60%, 80%, 100%)
  const levels = [0.2, 0.4, 0.6, 0.8, 1.0];

  const getCoordinates = (valueNormalized, index) => {
    const angle = index * angleStep - Math.PI / 2;
    const r = radius * valueNormalized;
    return {
      x: center + r * Math.cos(angle),
      y: center + r * Math.sin(angle),
    };
  };

  // Build polygon path for data
  const dataPoints = axes.map((axis, i) => getCoordinates(axis.value / 100, i));
  const dataPolygonPath = dataPoints.map((pt) => `${pt.x},${pt.y}`).join(' ');

  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div
        className="mono"
        style={{
          fontSize: '11px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.06em',
          marginBottom: '8px',
          display: 'flex',
          justifyContent: 'space-between',
          width: '100%',
        }}
      >
        <span>RADAR: 6-DIMENSIONAL THREAT SURFACE</span>
        <span style={{ color: '#ffffff' }}>AGGREGATE ENVELOPE</span>
      </div>

      <div style={{ position: 'relative', width: '100%', maxWidth: '340px' }}>
        <svg viewBox={`0 0 ${size} ${size}`} style={{ width: '100%', height: 'auto', overflow: 'visible' }}>
          {/* Background Concentric Radar Polygons */}
          {levels.map((level, lvlIdx) => {
            const levelPoints = axes
              .map((_, i) => {
                const pt = getCoordinates(level, i);
                return `${pt.x},${pt.y}`;
              })
              .join(' ');

            return (
              <g key={lvlIdx}>
                <polygon
                  points={levelPoints}
                  fill="none"
                  stroke={lvlIdx === levels.length - 1 ? '#404040' : '#222222'}
                  strokeWidth={lvlIdx === levels.length - 1 ? '1.5' : '1'}
                  strokeDasharray={lvlIdx < levels.length - 1 ? '2 2' : 'none'}
                />
                {/* Level indicator */}
                <text
                  x={center + 4}
                  y={center - radius * level + 10}
                  fill="#555555"
                  fontSize="8"
                  fontFamily="monospace"
                >
                  {Math.round(level * 100)}%
                </text>
              </g>
            );
          })}

          {/* Radial Spokes */}
          {axes.map((_, i) => {
            const edge = getCoordinates(1.0, i);
            return (
              <line
                key={i}
                x1={center}
                y1={center}
                x2={edge.x}
                y2={edge.y}
                stroke="#262626"
                strokeWidth="1"
              />
            );
          })}

          {/* Data Surface Fill (Monochrome crisp aesthetic) */}
          <polygon
            points={dataPolygonPath}
            fill="#ffffff"
            fillOpacity="0.12"
            stroke="#ffffff"
            strokeWidth="2"
          />

          {/* Vertex Point Coordinates & Value Rings */}
          {dataPoints.map((pt, i) => (
            <g key={i}>
              <circle
                cx={pt.x}
                cy={pt.y}
                r="4"
                fill="#ffffff"
                stroke="#000000"
                strokeWidth="1.5"
              />
              <circle
                cx={pt.x}
                cy={pt.y}
                r="7"
                fill="none"
                stroke="#ffffff"
                strokeWidth="0.7"
                opacity="0.4"
              />
            </g>
          ))}

          {/* Axis Labels */}
          {axes.map((axis, i) => {
            const angle = i * angleStep - Math.PI / 2;
            const labelRadius = radius + 26;
            const x = center + labelRadius * Math.cos(angle);
            const y = center + labelRadius * Math.sin(angle);

            let textAnchor = 'middle';
            if (Math.cos(angle) > 0.3) textAnchor = 'start';
            else if (Math.cos(angle) < -0.3) textAnchor = 'end';

            return (
              <g key={i}>
                <text
                  x={x}
                  y={y - 4}
                  textAnchor={textAnchor}
                  fill="#ffffff"
                  fontSize="9"
                  fontFamily="monospace"
                  fontWeight="600"
                >
                  {axis.label}
                </text>
                <text
                  x={x}
                  y={y + 8}
                  textAnchor={textAnchor}
                  fill="#888888"
                  fontSize="8"
                  fontFamily="monospace"
                >
                  {axis.value}/100 [{axis.code}]
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Axis Breakdown Readout Grid */}
      <div
        className="mono"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '6px',
          width: '100%',
          marginTop: '16px',
          fontSize: '10px',
        }}
      >
        {axes.map((axis, i) => (
          <div
            key={i}
            style={{
              padding: '6px 8px',
              backgroundColor: 'var(--bg-secondary)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '2px',
            }}
          >
            <div style={{ color: 'var(--text-muted)' }}>{axis.label}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2px' }}>
              <span style={{ color: axis.value >= 60 ? '#ffffff' : '#a3a3a3', fontWeight: 700 }}>
                {axis.value}%
              </span>
              <span style={{ color: 'var(--text-muted)' }}>{axis.code}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
