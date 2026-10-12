import React from 'react';
import { AnalyzeURLResponse, HistoryDetailResponse } from '../types/api';
import { RiskBadge } from './RiskBadge';

interface AnalysisResultCardProps {
  result: AnalyzeURLResponse | HistoryDetailResponse;
}

const FEATURE_LABELS: Record<string, string> = {
  url_length: 'Total URL Length',
  hostname_length: 'Hostname Length',
  path_length: 'Path Length',
  query_length: 'Query String Length',
  dot_count: 'Dot (.) Count',
  hyphen_count: 'Total Hyphen (-) Count',
  hostname_hyphen_count: 'Hostname Hyphen Count',
  digit_count: 'Total Digit Count',
  hostname_digit_count: 'Hostname Digit Count',
  query_param_count: 'Query Parameter Count',
  subdomain_count: 'Subdomain Levels',
  is_ip_address: 'IP Address Hostname (0/1)',
  has_at_symbol: 'Contains "@" Symbol (0/1)',
  is_https: 'Uses HTTPS Scheme (0/1)',
  has_punycode: 'Punycode / IDN Label (0/1)',
  percent_encoding_count: 'Percent-Encoded (%XX) Count',
  suspicious_keyword_count: 'Credential Keyword Count',
  hostname_entropy: 'Hostname Shannon Entropy',
};

export const AnalysisResultCard: React.FC<AnalysisResultCardProps> = ({ result }) => {
  const isFallback = result.is_fallback || result.analysis_method === 'rule_based_fallback';
  const heuristicNote =
    'heuristic_score_note' in result && result.heuristic_score_note
      ? result.heuristic_score_note
      : null;

  return (
    <section className="card" aria-labelledby="analysis-result-heading" data-testid="analysis-result-card">
      <div className="card-header">
        <div>
          <h2 id="analysis-result-heading" className="section-title">
            URL Risk Assessment Result
          </h2>
          <p className="section-desc">
            Analysed at {new Date(result.analyzed_at).toLocaleString()} &bull; Schema v
            {result.feature_schema_version}
          </p>
        </div>
        <RiskBadge category={result.risk_category} />
      </div>

      {isFallback && (
        <div className="alert-banner warning" role="status">
          <strong>Rule-Based Fallback Mode Active:</strong> This assessment was generated using
          deterministic lexical rules rather than a trained machine-learning model. Heuristic rule
          points are not calibrated probabilities.
        </div>
      )}

      <div>
        <div className="meta-label">Submitted URL (Safely Escaped Text — Never Visited or Rendered)</div>
        <div className="mono-url" data-testid="submitted-url-display">
          {result.submitted_url}
        </div>
      </div>

      <div className="meta-grid">
        <div className="meta-item">
          <div className="meta-label">Normalized Destination Hostname</div>
          <div className="meta-value">{result.hostname}</div>
        </div>
        <div className="meta-item">
          <div className="meta-label">Registrable Domain</div>
          <div className="meta-value">{result.registrable_domain}</div>
        </div>
        <div className="meta-item">
          <div className="meta-label">Analysis Method</div>
          <div className="meta-value" data-testid="analysis-method-value">
            {isFallback ? 'Rule-Based Fallback Mode' : 'Trained ML Model'}
          </div>
        </div>
        <div className="meta-item">
          <div className="meta-label">Model Version</div>
          <div className="meta-value">{result.model_version ?? 'N/A (Rule-Based Fallback)'}</div>
        </div>
        <div className="meta-item">
          <div className="meta-label">Calibrated ML Risk Score</div>
          <div className="meta-value" data-testid="calibrated-score-value">
            {result.calibrated_score !== null && result.calibrated_score !== undefined
              ? `${result.calibrated_score.toFixed(4)} (0.0000 - 1.0000 scale)`
              : 'Not applicable (Rule-Based Mode)'}
          </div>
        </div>
        <div className="meta-item">
          <div className="meta-label">URL SHA-256 Fingerprint</div>
          <div className="meta-value" style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            {result.url_sha256.slice(0, 24)}&hellip;
          </div>
        </div>
      </div>

      {heuristicNote && (
        <div className="notice-box" style={{ marginBottom: '1.25rem' }}>
          <strong>Scoring Methodology Note</strong>
          {heuristicNote}
        </div>
      )}

      {/* Explainable Indicators */}
      <div style={{ marginTop: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>
          Explainable Assessment Indicators ({result.indicators.length})
        </h3>
        <p className="section-desc">
          Lexical characteristics identified in the submitted URL string. Individual indicators are
          signals for review, not proof of malicious activity.
        </p>

        <div className="indicator-list">
          {result.indicators.map((ind, idx) => (
            <div
              key={`${ind.code}-${idx}`}
              className={`indicator-item sev-${ind.severity}`}
              data-testid="indicator-item"
            >
              <div className="indicator-top">
                <span className="indicator-title">
                  [{ind.severity.toUpperCase()}] {ind.title}
                </span>
                <span className="indicator-observed">{ind.observed_value}</span>
              </div>
              <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>{ind.description}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Recommended Actions */}
      <div style={{ marginTop: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>Recommended Cautionary Actions</h3>
        <ul style={{ marginTop: '0.6rem', paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
          {result.recommended_actions.map((action, idx) => (
            <li key={idx} style={{ marginBottom: '0.35rem', fontSize: '0.92rem' }}>
              {action}
            </li>
          ))}
        </ul>
      </div>

      {/* Extracted Lexical Features */}
      <div style={{ marginTop: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', fontWeight: 700 }}>
          Extracted URL Lexical Characteristics ({Object.keys(result.features).length} features)
        </h3>
        <div className="feature-grid">
          {Object.entries(result.features).map(([key, val]) => (
            <div key={key} className="feature-cell">
              <span className="feature-name">{FEATURE_LABELS[key] || key}</span>
              <span className="feature-val">{val}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Limitations & Uncertainty Notice */}
      <div className="notice-box" style={{ marginTop: '1.5rem' }} data-testid="limitations-notice">
        <strong>Limitations &amp; Uncertainty Disclosure</strong>
        {result.limitations_notice}
      </div>
    </section>
  );
};
