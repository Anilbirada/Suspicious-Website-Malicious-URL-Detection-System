export type RiskCategory =
  | 'Potentially Malicious'
  | 'Suspicious'
  | 'Lower Risk Indicators Found'
  | 'Unable to Determine';

export type AnalysisMethod = 'trained_ml_model' | 'rule_based_fallback';

export interface IndicatorItem {
  code: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  description: string;
  observed_value: string;
  source: string;
}

export interface AnalyzeURLRequest {
  url: string;
  force_fallback?: boolean;
  save_to_history?: boolean;
}

export interface AnalyzeURLResponse {
  analysis_id: string;
  submitted_url: string;
  normalized_url: string;
  hostname: string;
  registrable_domain: string;
  url_sha256: string;
  risk_category: RiskCategory;
  analysis_method: AnalysisMethod;
  is_fallback: boolean;
  model_version: string | null;
  model_type: string | null;
  feature_schema_version: string;
  calibrated_score: number | null;
  heuristic_score_note: string | null;
  features: Record<string, number>;
  indicators: IndicatorItem[];
  recommended_actions: string[];
  limitations_notice: string;
  analyzed_at: string;
  stored_in_history: boolean;
}

export interface EvaluationMetrics {
  dataset_name: string;
  dataset_source: string;
  dataset_licence: string;
  split_method: string;
  train_sample_size: number;
  evaluation_sample_size: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number | null;
  pr_auc: number | null;
  confusion_matrix: {
    true_negative: number;
    false_positive: number;
    false_negative: number;
    true_positive: number;
  };
  per_class_metrics: Record<
    string,
    {
      precision: number;
      recall: number;
      f1_score: number;
      support: number;
    }
  >;
  thresholds: {
    suspicious_threshold: number;
    malicious_threshold: number;
  };
  known_limitations: string[];
  evaluated_at: string;
}

export interface ModelStatusResponse {
  model_loaded: boolean;
  active_mode: AnalysisMethod;
  fallback_mode_active: boolean;
  allow_fallback_mode: boolean;
  model_version: string | null;
  model_type: string | null;
  feature_schema_version: string;
  expected_feature_count: number;
  feature_names: string[];
  trained_at: string | null;
  evaluation_metadata: EvaluationMetrics | null;
  status_message: string;
}

export interface HistoryItem {
  analysis_id: string;
  submitted_url: string;
  normalized_url: string;
  hostname: string;
  url_sha256: string;
  risk_category: RiskCategory;
  analysis_method: AnalysisMethod;
  is_fallback: boolean;
  model_version: string | null;
  calibrated_score: number | null;
  analyzed_at: string;
}

export interface HistoryDetailResponse extends HistoryItem {
  registrable_domain: string;
  feature_schema_version: string;
  features: Record<string, number>;
  indicators: IndicatorItem[];
  recommended_actions: string[];
  limitations_notice: string;
}

export interface HistoryListResponse {
  history_enabled: boolean;
  total: number;
  items: HistoryItem[];
}

export interface ApiErrorPayload {
  error_code: string;
  message: string;
}
