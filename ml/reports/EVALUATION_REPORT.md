# Model Evaluation Report

- **Model Version**: `1.0.0-logreg-calibrated`
- **Model Type**: `CalibratedClassifierCV(StandardScaler + LogisticRegression, sigmoid, 5-fold)`
- **Feature Schema Version**: `1.0.0` (18 lexical features)
- **Evaluated At**: `2026-10-12T17:07:24.505085+00:00`
- **Split Method**: GroupShuffleSplit (75% train / 25% held-out test, grouped by registrable_domain; 0 overlapping domains)
- **Train Sample Size**: 225
- **Held-Out Evaluation Sample Size**: 58

## Held-Out Test Set Metrics (Actual Predictions)

| Metric | Value |
| :--- | ---: |
| **Precision (Class 1 - Potentially Malicious)** | 0.9667 |
| **Recall (Class 1 - Potentially Malicious)** | 0.9667 |
| **F1-Score (Class 1)** | 0.9667 |
| **ROC-AUC** | 0.9976 |
| **PR-AUC** | 0.9978 |
| **Comparison Baseline (Random Forest F1)** | 1.0000 |

## Confusion Matrix (Held-Out Test Set)

| | Predicted Benign (0) | Predicted Malicious (1) |
| :--- | ---: | ---: |
| **Actual Benign (0)** | TN = 27 | FP = 1 |
| **Actual Malicious (1)** | FN = 1 | TP = 29 |

## Decision Thresholds

- **Lower Risk Indicators Found**: Calibrated probability `< 0.35`
- **Suspicious**: Calibrated probability `>= 0.35` and `< 0.70`
- **Potentially Malicious**: Calibrated probability `>= 0.70`

## Known Limitations

- Trained on a curated lexical benchmark (283 valid URLs across 132 registrable domains); performance on this benchmark does not guarantee equivalent precision/recall on novel internet-wide zero-day phishing campaigns.
- Analyses only lexical URL string features; does not inspect live HTML content, JavaScript behavior, DNS age, or TLS certificate chains.
- Compromised legitimate domains hosting malicious pages on clean paths may produce false negatives.
- Legitimate enterprise OAuth or redirect URLs with many parameters and keywords may produce false positives.
