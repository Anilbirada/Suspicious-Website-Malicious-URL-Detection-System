import React, { useState } from 'react';
import { analyzeUrl, ApiClientError } from '../services/apiClient';
import { AnalyzeURLResponse, HistoryItem, ModelStatusResponse } from '../types/api';
import { AnalysisResultCard } from '../components/AnalysisResultCard';
import { RiskBadge } from '../components/RiskBadge';

interface DashboardPageProps {
  modelStatus: ModelStatusResponse | null;
  recentHistory: HistoryItem[];
  onAnalysisCompleted: (result: AnalyzeURLResponse) => void;
  onNavigateToHistory: () => void;
}

const SAMPLE_URLS = [
  {
    label: 'Lower-Risk Documentation URL',
    url: 'https://docs.python.org/3/library/urllib.parse.html',
  },
  {
    label: 'Suspicious Subdomain & Keyword Pattern',
    url: 'https://login.verify.account-update.portal-service.xyz/signin?continue=home',
  },
  {
    label: 'High-Risk @ Userinfo & IP Pattern',
    url: 'http://trusted-bank.com@198.51.100.42:8080/secure/banking/update-credentials.html',
  },
];

export const DashboardPage: React.FC<DashboardPageProps> = ({
  modelStatus,
  recentHistory,
  onAnalysisCompleted,
  onNavigateToHistory,
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [forceFallback, setForceFallback] = useState(false);
  const [saveToHistory, setSaveToHistory] = useState(true);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [currentResult, setCurrentResult] = useState<AnalyzeURLResponse | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setErrorCode(null);

    const trimmed = urlInput.trim();
    if (!trimmed) {
      setErrorCode('EMPTY_URL');
      setErrorMessage('Please enter a URL to analyse. Input cannot be empty.');
      return;
    }

    setLoading(true);
    try {
      const response = await analyzeUrl({
        url: trimmed,
        force_fallback: forceFallback,
        save_to_history: saveToHistory,
      });
      setCurrentResult(response);
      onAnalysisCompleted(response);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setErrorCode(err.errorCode);
        setErrorMessage(err.message);
      } else {
        setErrorCode('ANALYSIS_ERROR');
        setErrorMessage('An unexpected error occurred while analysing the URL.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <section className="card" aria-labelledby="analyzer-heading">
        <div className="card-header">
          <div>
            <h1 id="analyzer-heading" className="section-title">
              Inspect a URL for Suspicious or Malicious Lexical Indicators
            </h1>
            <p className="section-desc">
              Submit an HTTP or HTTPS link to evaluate its structural and lexical characteristics
              without visiting or fetching the destination website.
            </p>
          </div>
        </div>

        <form className="url-form" onSubmit={handleSubmit} noValidate>
          <label htmlFor="url-input-field" className="input-label">
            Target URL to Analyse (http:// or https://, max 2,048 characters)
          </label>

          <div className="url-input-row">
            <input
              id="url-input-field"
              type="text"
              className="url-input"
              placeholder="https://example.com/path?query=value"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              disabled={loading}
              aria-describedby="url-input-guidance"
            />
            <button
              type="submit"
              className="primary-btn"
              disabled={loading}
              data-testid="analyze-submit-btn"
            >
              {loading ? 'Analysing URL...' : 'Analyse URL'}
            </button>
          </div>

          <div className="options-row">
            <div className="checkbox-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={saveToHistory}
                  onChange={(e) => setSaveToHistory(e.target.checked)}
                  disabled={loading}
                />
                Save result in local analysis history
              </label>

              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={forceFallback}
                  onChange={(e) => setForceFallback(e.target.checked)}
                  disabled={loading}
                />
                Use Rule-Based Fallback Mode (bypass ML model)
              </label>
            </div>

            <div className="preset-row">
              <span className="preset-label">Load test fixture:</span>
              {SAMPLE_URLS.map((item) => (
                <button
                  key={item.label}
                  type="button"
                  className="secondary-btn"
                  onClick={() => {
                    setUrlInput(item.url);
                    setErrorMessage(null);
                  }}
                  disabled={loading}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        </form>

        <div id="url-input-guidance" className="notice-grid">
          <div className="notice-box">
            <strong>Supported Input &amp; Zero-Fetch Security</strong>
            Supports <code>http://</code> and <code>https://</code> URLs (including IPv4, IPv6, and
            internationalized domain names). The system analyses only the URL string in memory and
            never visits or downloads content from the destination.
          </div>
          <div className="notice-box">
            <strong>Privacy &amp; Assessment Limitations</strong>
            A prediction is a lexical risk assessment, not proof that a website is guaranteed safe
            or malicious. HTTPS alone never proves domain legitimacy. Do not submit URLs containing
            secret API tokens or private passwords in query strings.
          </div>
          <div className="notice-box">
            <strong>Active Analysis Engine</strong>
            {modelStatus?.model_loaded && !forceFallback ? (
              <span>
                Using calibrated machine-learning model{' '}
                <code>{modelStatus.model_version}</code> (schema v
                {modelStatus.feature_schema_version}).
              </span>
            ) : (
              <span>
                Using deterministic <strong>Rule-Based Fallback Mode</strong>. Heuristic rule points
                are clearly distinguished from calibrated ML probabilities.
              </span>
            )}
          </div>
        </div>
      </section>

      {errorMessage && (
        <div className="alert-banner error" role="alert" data-testid="analysis-error-banner">
          <strong>Analysis Validation / Request Error ({errorCode || 'ERROR'}):</strong>{' '}
          {errorMessage}
        </div>
      )}

      {currentResult && <AnalysisResultCard result={currentResult} />}

      {recentHistory.length > 0 && (
        <section className="card" aria-labelledby="recent-history-heading">
          <div className="card-header">
            <div>
              <h2 id="recent-history-heading" className="section-title">
                Recent Analysis History
              </h2>
              <p className="section-desc">
                Most recent URL assessments stored locally on this system.
              </p>
            </div>
            <button type="button" className="secondary-btn" onClick={onNavigateToHistory}>
              View Full History &amp; Controls
            </button>
          </div>

          <div className="data-table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Submitted URL</th>
                  <th>Assessment Category</th>
                  <th>Method</th>
                </tr>
              </thead>
              <tbody>
                {recentHistory.slice(0, 5).map((item) => (
                  <tr key={item.analysis_id}>
                    <td>{new Date(item.analyzed_at).toLocaleTimeString()}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                      {item.submitted_url}
                    </td>
                    <td>
                      <RiskBadge category={item.risk_category} />
                    </td>
                    <td>
                      {item.is_fallback
                        ? 'Rule-Based Fallback'
                        : `ML (${item.model_version ?? 'v1'})`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  );
};
