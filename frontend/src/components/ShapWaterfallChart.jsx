import React from 'react';

/**
 * ShapWaterfallChart: Visual SHAP Feature Attribution Waterfall Diagram
 * Renders step-by-step vector bars showing how each feature pushes the risk
 * up (+) or down (-) from the base expectation to the final lexical prediction.
 */
export default function ShapWaterfallChart({ reasons = [], baseScore = 50.0, finalScore = 50.0 }) {
  if (!reasons || reasons.length === 0) return null;

  // Take top 6 contributing features for clean display
  const items = reasons.slice(0, 6);

  // Compute waterfall running cumulative positions
  let currentAccumulator = baseScore;
  const steps = items.map((r) => {
    const start = currentAccumulator;
    const impactDelta = (r.impact || 0) * (r.direction === 'suspicious' ? 1 : -1);
    const end = Math.max(0, Math.min(100, start + impactDelta));
    currentAccumulator = end;
    return {
      feature: r.feature,
      value: r.value,
      direction: r.direction,
      impact: r.impact,
      delta: impactDelta,
      start,
      end,
      description: r.description,
    };
  });

  const chartHeight = steps.length * 38 + 60;
  const chartWidth = 560;
  const leftMargin = 160;
  const rightMargin = 60;
  const plotWidth = chartWidth - leftMargin - rightMargin;

  // Scale: 0 to 100 -> plotWidth
  const scaleX = (val) => leftMargin + (Math.max(0, Math.min(100, val)) / 100) * plotWidth;

  return (
    <div style={{ width: '100%' }}>
      <div
        className="mono"
        style={{
          fontSize: '11px',
          color: 'var(--text-secondary)',
          letterSpacing: '0.06em',
          marginBottom: '10px',
          display: 'flex',
          justifyContent: 'space-between',
        }}
      >
        <span>VECTOR SHAP ATTRIBUTION WATERFALL</span>
        <span>f(x) = E[f(x)] + ∑ φᵢ</span>
      </div>

      <div style={{ overflowX: 'auto', width: '100%' }}>
        <svg
          viewBox={`0 0 ${chartWidth} ${chartHeight}`}
          style={{ width: '100%', minWidth: '480px', height: 'auto', display: 'block' }}
        >
          {/* Grid lines at 0, 25, 50, 75, 100 */}
          {[0, 25, 50, 75, 100].map((tick) => {
            const x = scaleX(tick);
            return (
              <g key={tick}>
                <line
                  x1={x}
                  y1={24}
                  x2={x}
                  y2={chartHeight - 20}
                  stroke={tick === 50 ? '#383838' : '#222222'}
                  strokeWidth="1"
                  strokeDasharray={tick === 50 ? '3 3' : 'none'}
                />
                <text
                  x={x}
                  y={16}
                  fill="#666666"
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor="middle"
                >
                  {tick}
                </text>
              </g>
            );
          })}

          {/* Base Expectation Line */}
          <line
            x1={scaleX(baseScore)}
            y1={24}
            x2={scaleX(baseScore)}
            y2={chartHeight - 20}
            stroke="#ffffff"
            strokeWidth="1"
            strokeDasharray="2 2"
            opacity="0.4"
          />
          <text
            x={scaleX(baseScore)}
            y={chartHeight - 6}
            fill="#888888"
            fontSize="8"
            fontFamily="monospace"
            textAnchor="middle"
          >
            E[f(x)]={baseScore.toFixed(0)}
          </text>

          {/* Waterfall Steps */}
          {steps.map((step, idx) => {
            const y = 38 + idx * 38;
            const x1 = scaleX(Math.min(step.start, step.end));
            const x2 = scaleX(Math.max(step.start, step.end));
            const width = Math.max(x2 - x1, 4);
            const isPushRisk = step.delta >= 0;

            // Connector line from previous step
            const prevY = idx === 0 ? 38 : 38 + (idx - 1) * 38;
            const prevEnd = idx === 0 ? scaleX(baseScore) : scaleX(steps[idx - 1].end);

            return (
              <g key={idx}>
                {/* Step Connector Line */}
                {idx > 0 && (
                  <line
                    x1={prevEnd}
                    y1={prevY + 9}
                    x2={scaleX(step.start)}
                    y2={y + 9}
                    stroke="#444444"
                    strokeWidth="1"
                    strokeDasharray="2 2"
                  />
                )}

                {/* Feature Label */}
                <text
                  x={leftMargin - 12}
                  y={y + 12}
                  fill="#ffffff"
                  fontSize="10"
                  fontFamily="monospace"
                  textAnchor="end"
                  fontWeight="500"
                >
                  {step.feature}
                </text>
                <text
                  x={leftMargin - 12}
                  y={y + 22}
                  fill="#666666"
                  fontSize="8"
                  fontFamily="monospace"
                  textAnchor="end"
                >
                  val: {step.value}
                </text>

                {/* Waterfall Bar */}
                <rect
                  x={x1}
                  y={y}
                  width={width}
                  height={18}
                  fill={isPushRisk ? '#ffffff' : '#1e1e1e'}
                  stroke={isPushRisk ? '#ffffff' : '#666666'}
                  strokeWidth="1"
                  rx="1"
                />

                {/* Direction Hash Indicator inside bar if negative */}
                {!isPushRisk && (
                  <line
                    x1={x1 + 4}
                    y1={y + 9}
                    x2={x2 - 4}
                    y2={y + 9}
                    stroke="#888888"
                    strokeWidth="1"
                  />
                )}

                {/* Delta Value Label */}
                <text
                  x={isPushRisk ? x2 + 6 : x1 - 6}
                  y={y + 13}
                  fill={isPushRisk ? '#ffffff' : '#a3a3a3'}
                  fontSize="9"
                  fontFamily="monospace"
                  textAnchor={isPushRisk ? 'start' : 'end'}
                  fontWeight="600"
                >
                  {isPushRisk ? `+${step.delta.toFixed(1)}` : step.delta.toFixed(1)}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      <div
        className="mono"
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginTop: '6px',
          padding: '6px 10px',
          backgroundColor: 'var(--bg-secondary)',
          border: '1px solid var(--border-subtle)',
          fontSize: '10px',
          color: 'var(--text-secondary)',
        }}
      >
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span style={{ width: '10px', height: '10px', backgroundColor: '#ffffff', display: 'inline-block' }} />
          WHITE = +RISK ATTRIBUTION (PHISHING PUSH)
        </span>
        <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              width: '10px',
              height: '10px',
              backgroundColor: '#1e1e1e',
              border: '1px solid #666666',
              display: 'inline-block',
            }}
          />
          DARK = -RISK ATTRIBUTION (BENIGN MITIGATION)
        </span>
      </div>
    </div>
  );
}
