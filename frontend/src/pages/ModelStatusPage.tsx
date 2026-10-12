import React from 'react';
import { ModelStatusResponse } from '../types/api';

interface ModelStatusPageProps {
  modelStatus: ModelStatusResponse | null;
  error: string | null;
  onRefresh: () => void;
}

export const ModelStatusPage: React.FC<ModelStatusPageProps> = ({
  modelStatus,
  error,
  onRefresh,
}) => {
  const evalMeta = modelStatus?.evaluation_metadata ?? null;

  return (
    <div>
      <section className="card" aria-labelledby="model-status-heading">
        <div className="card-header">
          <div>
            <h1 id="model-status-heading" className="section-title">
              Machine Learning Model &amp; Fallback Status
            </h1>
            <p className="section-desc">
              Live status of the lexical inference pipeline, feature schema compatibility, and
              verified held-out evaluation metadata.
            </p>
          </div>
          <button type="button" className="secondary-btn" onClick={onRefresh}>
            Refresh Status
          </button>
        </div>

        {error && (
          <div className="alert-banner error" role="alert">
            {error}
          </div>
        )}

        {!modelStatus ? (
          <p className="section-desc">Loading model status from backend...</p>
        ) : (
          <>
            <div className="meta-grid">
              <div className="meta-item">
                <div className="meta-label">Model Loaded</div>
                <div className="meta-value" data-testid="model-loaded-indicator">
                  {modelStatus.model_loaded ? 'Yes — Active' : 'No — Fallback Active'}
                </div>
              </div>
              <div className="meta-item">
                <div className="meta-label">Active Analysis Mode</div>
                <div className="meta-value">
                  {modelStatus.active_mode === 'trained_ml_model'
                    ? 'Trained ML Model'
                    : 'Rule-Based Fallback Mode'}
                </div>
              </div>
              <div className="meta-item">
                <div className="meta-label">Model Version</div>
                <div className="meta-value">{modelStatus.model_version ?? 'Not Loaded'}</div>
              </div>
              <div className="meta-item">
                <div className="meta-label">Classifier Architecture</div>
                <div className="meta-value">{modelStatus.model_type ?? 'Deterministic Rules'}</div>
              </div>
              <div className="meta-item">
                <div className="meta-label">Feature Schema Version</div>
                <div className="meta-value">
                  v{modelStatus.feature_schema_version} ({modelStatus.expected_feature_count} lexical
                  features)
                </div>
              </div>
              <div className="meta-item">
                <div className="meta-label">Trained / Evaluated Timestamp</div>
                <div className="meta-value">
                  {modelStatus.trained_at
                    ? new Date(modelStatus.trained_at).toLocaleString()
                    : 'N/A'}
                </div>
              </div>
            </div>

            <div className="notice-box" style={{ marginTop: '1rem' }}>
              <strong>Pipeline Status Message</strong>
              {modelStatus.status_message}
            </div>
          </>
        )}
      </section>

      {evalMeta && (
        <section className="card" aria-labelledby="eval-metrics-heading">
          <div className="card-header">
            <div>
              <h2 id="eval-metrics-heading" className="section-title">
                Held-Out Evaluation Report (Actual Test Split Predictions)
              </h2>
              <p className="section-desc">
                Dataset: <code>{evalMeta.dataset_name}</code> &bull; Split:{' '}
                {evalMeta.split_method}
              </p>
            </div>
          </div>

          <div className="meta-grid">
            <div className="meta-item">
              <div className="meta-label">Precision (Malicious Class 1)</div>
              <div className="meta-value">{evalMeta.precision.toFixed(4)}</div>
            </div>
            <div className="meta-item">
              <div className="meta-label">Recall (Malicious Class 1)</div>
              <div className="meta-value">{evalMeta.recall.toFixed(4)}</div>
            </div>
            <div className="meta-item">
              <div className="meta-label">F1-Score (Malicious Class 1)</div>
              <div className="meta-value">{evalMeta.f1_score.toFixed(4)}</div>
            </div>
            <div className="meta-item">
              <div className="meta-label">ROC-AUC / PR-AUC</div>
              <div className="meta-value">
                {evalMeta.roc_auc !== null ? evalMeta.roc_auc.toFixed(4) : 'N/A'} /{' '}
                {evalMeta.pr_auc !== null ? evalMeta.pr_auc.toFixed(4) : 'N/A'}
              </div>
            </div>
            <div className="meta-item">
              <div className="meta-label">Train / Held-Out Sample Size</div>
              <div className="meta-value">
                {evalMeta.train_sample_size} train / {evalMeta.evaluation_sample_size} held-out test
              </div>
            </div>
            <div className="meta-item">
              <div className="meta-label">Confusion Matrix (Held-Out Test)</div>
              <div className="meta-value">
                TN={evalMeta.confusion_matrix.true_negative}, FP=
                {evalMeta.confusion_matrix.false_positive}, FN=
                {evalMeta.confusion_matrix.false_negative}, TP=
                {evalMeta.confusion_matrix.true_positive}
              </div>
            </div>
          </div>

          <div className="notice-grid">
            <div className="notice-box">
              <strong>Dataset Provenance &amp; Licence</strong>
              Source: {evalMeta.dataset_source}
              <br />
              Licence: {evalMeta.dataset_licence}
            </div>
            <div className="notice-box">
              <strong>Calibrated Classification Thresholds</strong>
              Lower Risk Indicators Found: <code>&lt; {evalMeta.thresholds.suspicious_threshold}</code>
              <br />
              Suspicious: <code>&gt;= {evalMeta.thresholds.suspicious_threshold}</code> and{' '}
              <code>&lt; {evalMeta.thresholds.malicious_threshold}</code>
              <br />
              Potentially Malicious: <code>&gt;= {evalMeta.thresholds.malicious_threshold}</code>
            </div>
          </div>

          <div style={{ marginTop: '1.25rem' }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700 }}>
              Documented Model &amp; Dataset Limitations
            </h3>
            <ul style={{ marginTop: '0.5rem', paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
              {evalMeta.known_limitations.map((lim, idx) => (
                <li key={idx} style={{ marginBottom: '0.35rem', fontSize: '0.9rem' }}>
                  {lim}
                </li>
              ))}
            </ul>
          </div>
        </section>
      )}
    </div>
  );
};
