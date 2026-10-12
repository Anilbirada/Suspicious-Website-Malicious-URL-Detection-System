# Machine Learning Pipeline (`ml/`)

**Developer**: Anil Biradar  
**Project**: Suspicious Website / Malicious URL Detection System

## Overview

This directory contains the reproducible machine-learning pipeline for lexical URL risk assessment:

- `data/curated_url_benchmark.csv` — Documented benchmark dataset with URL, binary label (`0` = benign reference, `1` = synthetic/defanged phishing or malicious lexical pattern), source identifier, timestamp, and licence reference.
- `scripts/train_and_evaluate.py` — End-to-end script that:
  1. Audits the dataset for missing URLs, missing/invalid labels, exact duplicates, conflicting labels, and malformed URLs.
  2. Writes `reports/data_quality_report.json` and `reports/DATA_QUALITY_REPORT.md`.
  3. Extracts the 18 lexical URL features using `backend/app/features/url_extractor.py` (ensuring 100% training/inference schema consistency).
  4. Performs a domain-grouped split (`GroupShuffleSplit` grouped by `registrable_domain`) to prevent train/test data leakage across related URLs.
  5. Trains a calibrated logistic regression pipeline (`CalibratedClassifierCV`) alongside a Random Forest comparison baseline.
  6. Computes held-out evaluation metrics (`Precision`, `Recall`, `F1`, `ROC-AUC`, `PR-AUC`, `Confusion Matrix`) from actual predictions and writes `reports/evaluation_report.json`, `reports/EVALUATION_REPORT.md`, and `backend/app/ml/artefacts/url_model_v1.joblib`.

## Running the Pipeline

```bash
python ml/scripts/train_and_evaluate.py
```

## Dataset Provenance & Limitations

- **Source**: Curated local lexical benchmark combining public standard domains (RFC/documentation/educational/open-source domains) and defanged synthetic phishing lexical patterns (using RFC 2606 / RFC 5737 reserved ranges and non-existent test domains).
- **Limitations**: This benchmark verifies the end-to-end lexical feature extraction, domain-grouped splitting, calibration, and inference pipeline without redistributing proprietary third-party datasets. To train a model for production deployment, supply an approved, licensed institutional dataset with identical CSV columns (`url,label,source_id,collected_at,licence_ref`) and re-run `python ml/scripts/train_and_evaluate.py`.
