# REST API Documentation

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Base Path**: `/api/v1`  

---

## 1. Endpoints Overview

| Method | Path | Rate Limited | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/health` | No | Check service availability and active configuration flags |
| `GET` | `/api/v1/model/status` | No | Retrieve loaded ML model status, schema version, and held-out evaluation report |
| `POST` | `/api/v1/analyze` | Yes | Validate URL, extract 18 lexical features, and run ML or fallback analysis |
| `GET` | `/api/v1/history` | Yes | List and filter stored analysis history |
| `GET` | `/api/v1/history/{analysis_id}` | Yes | Retrieve full detail of a single analysis history record |
| `DELETE` | `/api/v1/history` | Yes | Delete a specific history record (`?analysis_id=...`) or clear all records |

---

## 2. Endpoint Specifications

### 2.1 `GET /api/v1/health`

**Response (`200 OK`)**:
```json
{
  "status": "ok",
  "app_name": "Suspicious Website / Malicious URL Detection System",
  "app_version": "1.0.0",
  "developer": "Anil Biradar",
  "model_loaded": true,
  "fallback_available": true,
  "history_enabled": true,
  "timestamp": "2026-10-12T17:10:00Z"
}
```

---

### 2.2 `GET /api/v1/model/status`

**Response (`200 OK`)**:
```json
{
  "model_loaded": true,
  "active_mode": "trained_ml_model",
  "fallback_mode_active": false,
  "allow_fallback_mode": true,
  "model_version": "1.0.0-logreg-calibrated",
  "model_type": "CalibratedClassifierCV(StandardScaler + LogisticRegression, sigmoid, 5-fold)",
  "feature_schema_version": "1.0.0",
  "expected_feature_count": 18,
  "feature_names": [
    "url_length", "hostname_length", "path_length", "query_length",
    "dot_count", "hyphen_count", "hostname_hyphen_count", "digit_count",
    "hostname_digit_count", "query_param_count", "subdomain_count",
    "is_ip_address", "has_at_symbol", "is_https", "has_punycode",
    "percent_encoding_count", "suspicious_keyword_count", "hostname_entropy"
  ],
  "trained_at": "2026-10-12T17:04:59.327180+00:00",
  "evaluation_metadata": {
    "dataset_name": "curated_url_benchmark.csv",
    "dataset_source": "Curated Local Lexical Benchmark Dataset (Standard Public Domains + Defanged Synthetic Phishing Lexical Patterns)",
    "dataset_licence": "CC0-1.0 / MIT (RFC 2606 & RFC 5737 safe test ranges)",
    "split_method": "GroupShuffleSplit (75% train / 25% held-out test, grouped by registrable_domain; 0 overlapping domains)",
    "train_sample_size": 225,
    "evaluation_sample_size": 58,
    "precision": 0.9667,
    "recall": 0.9667,
    "f1_score": 0.9667,
    "roc_auc": 0.9976,
    "pr_auc": 0.9978,
    "confusion_matrix": {
      "true_negative": 27,
      "false_positive": 1,
      "false_negative": 1,
      "true_positive": 29
    },
    "thresholds": {
      "suspicious_threshold": 0.35,
      "malicious_threshold": 0.70
    },
    "known_limitations": [
      "Trained on a curated lexical benchmark (283 valid URLs across 132 registrable domains)..."
    ],
    "evaluated_at": "2026-10-12T17:04:59.327180+00:00"
  },
  "status_message": "Trained ML model (1.0.0-logreg-calibrated) is loaded and verified against feature schema v1.0.0."
}
```

---

### 2.3 `POST /api/v1/analyze`

**Request Headers**: `Content-Type: application/json`  
**Request Body**:
```json
{
  "url": "http://trusted-bank.com@198.51.100.42:8080/secure/banking/update-credentials.html",
  "force_fallback": false,
  "save_to_history": true
}
```

**Response (`200 OK`)**:
```json
{
  "analysis_id": "9f8c2b10-4c1a-4b0e-8d12-3f9a1b2c3d4e",
  "submitted_url": "http://trusted-bank.com@198.51.100.42:8080/secure/banking/update-credentials.html",
  "normalized_url": "http://198.51.100.42:8080/secure/banking/update-credentials.html",
  "hostname": "198.51.100.42",
  "registrable_domain": "198.51.100.42",
  "url_sha256": "...",
  "risk_category": "Potentially Malicious",
  "analysis_method": "trained_ml_model",
  "is_fallback": false,
  "model_version": "1.0.0-logreg-calibrated",
  "model_type": "CalibratedClassifierCV(StandardScaler + LogisticRegression, sigmoid, 5-fold)",
  "feature_schema_version": "1.0.0",
  "calibrated_score": 0.9615,
  "heuristic_score_note": "Calibrated ML probability score: 0.9615 (thresholds: Suspicious >= 0.35, Potentially Malicious >= 0.70).",
  "features": {
    "url_length": 85,
    "hostname_length": 13,
    "path_length": 42,
    "query_length": 0,
    "dot_count": 5,
    "hyphen_count": 2,
    "hostname_hyphen_count": 0,
    "digit_count": 14,
    "hostname_digit_count": 10,
    "query_param_count": 0,
    "subdomain_count": 0,
    "is_ip_address": 1,
    "has_at_symbol": 1,
    "is_https": 0,
    "has_punycode": 0,
    "percent_encoding_count": 0,
    "suspicious_keyword_count": 4,
    "hostname_entropy": 2.7772
  },
  "indicators": [
    {
      "code": "IP_ADDRESS_HOSTNAME",
      "title": "Literal IP Address Hostname",
      "severity": "high",
      "description": "The destination hostname is a raw IP address rather than a registered domain name...",
      "observed_value": "198.51.100.42",
      "source": "lexical"
    }
  ],
  "recommended_actions": [
    "Do NOT enter passwords, multi-factor authentication codes, financial details, or personal data on this URL."
  ],
  "limitations_notice": "IMPORTANT LIMITATIONS: This assessment is generated by a lexical machine-learning model...",
  "analyzed_at": "2026-10-12T17:12:00Z",
  "stored_in_history": true
}
```

---

### 2.4 Error Response Format

All error responses return a consistent JSON object without internal stack traces or file paths:
```json
{
  "error_code": "UNSUPPORTED_SCHEME",
  "message": "Unsupported URL scheme 'ftp'. Only 'http' and 'https' are supported."
}
```

| HTTP Status | Error Codes |
| :--- | :--- |
| `413 Request Entity Too Large` | `PAYLOAD_TOO_LARGE` |
| `415 Unsupported Media Type` | `UNSUPPORTED_MEDIA_TYPE` |
| `422 Unprocessable Entity` | `EMPTY_URL`, `MALFORMED_URL`, `UNSUPPORTED_SCHEME`, `URL_TOO_LONG`, `INVALID_REQUEST_PAYLOAD` |
| `429 Too Many Requests` | `RATE_LIMIT_EXCEEDED` |
| `403 Forbidden` | `HISTORY_DISABLED` |
| `404 Not Found` | `RECORD_NOT_FOUND` |
| `503 Service Unavailable` | `MODEL_UNAVAILABLE` |
