import React, { useEffect, useState } from 'react';
import {
  ApiClientError,
  deleteHistory,
  fetchHistory,
  fetchHistoryDetail,
} from '../services/apiClient';
import { HistoryDetailResponse, HistoryItem, RiskCategory } from '../types/api';
import { RiskBadge } from '../components/RiskBadge';
import { AnalysisResultCard } from '../components/AnalysisResultCard';

interface HistoryPageProps {
  onHistoryChanged: () => void;
}

export const HistoryPage: React.FC<HistoryPageProps> = ({ onHistoryChanged }) => {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [historyEnabled, setHistoryEnabled] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<RiskCategory | ''>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedDetail, setSelectedDetail] = useState<HistoryDetailResponse | null>(null);

  const loadHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchHistory({
        search,
        riskCategory: riskFilter,
        limit: 100,
      });
      setHistoryEnabled(res.history_enabled);
      setItems(res.items);
      setTotal(res.total);
    } catch (err) {
      if (err instanceof ApiClientError) {
        if (err.errorCode === 'HISTORY_DISABLED') {
          setHistoryEnabled(false);
        }
        setError(err.message);
      } else {
        setError('Unable to load analysis history.');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [riskFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadHistory();
  };

  const handleInspectRecord = async (analysisId: string) => {
    try {
      const detail = await fetchHistoryDetail(analysisId);
      setSelectedDetail(detail);
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message);
      }
    }
  };

  const handleDeleteOne = async (analysisId: string) => {
    try {
      await deleteHistory(analysisId);
      if (selectedDetail?.analysis_id === analysisId) {
        setSelectedDetail(null);
      }
      await loadHistory();
      onHistoryChanged();
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message);
      }
    }
  };

  const handleClearAll = async () => {
    try {
      await deleteHistory();
      setSelectedDetail(null);
      await loadHistory();
      onHistoryChanged();
    } catch (err) {
      if (err instanceof ApiClientError) {
        setError(err.message);
      }
    }
  };

  return (
    <div>
      <section className="card" aria-labelledby="history-page-heading">
        <div className="card-header">
          <div>
            <h1 id="history-page-heading" className="section-title">
              Analysis History &amp; Retention Controls
            </h1>
            <p className="section-desc">
              Review, filter, or permanently delete locally stored URL risk assessments.
            </p>
          </div>
          {items.length > 0 && (
            <button
              type="button"
              className="danger-btn"
              onClick={handleClearAll}
              data-testid="clear-all-history-btn"
            >
              Delete All History ({total})
            </button>
          )}
        </div>

        {!historyEnabled ? (
          <div className="alert-banner warning">
            History storage is currently disabled by server privacy configuration.
          </div>
        ) : (
          <>
            <form className="table-controls" onSubmit={handleSearchSubmit}>
              <input
                type="text"
                className="url-input"
                style={{ padding: '0.6rem 0.9rem', fontSize: '0.9rem' }}
                placeholder="Filter by hostname or URL substring..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                aria-label="Filter history by hostname or URL"
              />
              <select
                className="filter-select"
                value={riskFilter}
                onChange={(e) => setRiskFilter(e.target.value as RiskCategory | '')}
                aria-label="Filter history by risk category"
              >
                <option value="">All Assessment Categories</option>
                <option value="Potentially Malicious">Potentially Malicious</option>
                <option value="Suspicious">Suspicious</option>
                <option value="Lower Risk Indicators Found">Lower Risk Indicators Found</option>
                <option value="Unable to Determine">Unable to Determine</option>
              </select>
              <button type="submit" className="primary-btn" style={{ padding: '0.6rem 1.1rem' }}>
                Apply Filter
              </button>
            </form>

            {error && (
              <div className="alert-banner error" role="alert">
                {error}
              </div>
            )}

            {loading ? (
              <p className="section-desc">Loading analysis history...</p>
            ) : items.length === 0 ? (
              <div className="notice-box" data-testid="empty-history-state">
                <strong>No Analysis History Found</strong>
                No stored URL assessments match the current filter criteria.
              </div>
            ) : (
              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Date &amp; Time</th>
                      <th>Submitted URL (Escaped)</th>
                      <th>Category</th>
                      <th>Analysis Method</th>
                      <th>Calibrated Score</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((item) => (
                      <tr key={item.analysis_id}>
                        <td>{new Date(item.analyzed_at).toLocaleString()}</td>
                        <td style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                          {item.submitted_url}
                        </td>
                        <td>
                          <RiskBadge category={item.risk_category} />
                        </td>
                        <td>
                          {item.is_fallback
                            ? 'Rule-Based Fallback'
                            : `Trained ML (${item.model_version ?? 'v1'})`}
                        </td>
                        <td>
                          {item.calibrated_score !== null && item.calibrated_score !== undefined
                            ? item.calibrated_score.toFixed(4)
                            : 'N/A (Fallback)'}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: '0.4rem' }}>
                            <button
                              type="button"
                              className="secondary-btn"
                              onClick={() => handleInspectRecord(item.analysis_id)}
                            >
                              Details
                            </button>
                            <button
                              type="button"
                              className="danger-btn"
                              onClick={() => handleDeleteOne(item.analysis_id)}
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </section>

      {selectedDetail && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '0.5rem' }}>
            <button
              type="button"
              className="secondary-btn"
              onClick={() => setSelectedDetail(null)}
            >
              Close Record Detail
            </button>
          </div>
          <AnalysisResultCard result={selectedDetail} />
        </div>
      )}
    </div>
  );
};
