# Data Quality Report

- **Dataset**: `ml/data/curated_url_benchmark.csv`
- **Audited At**: `2026-10-12T17:07:24.261007+00:00`
- **Total Raw Records**: 287
- **Valid Cleaned Records**: 283
- **Unique Registrable Domains**: 132

## Quality Check Findings

| Check | Count | Handling |
| :--- | ---: | :--- |
| Missing URLs | 1 | Excluded prior to feature extraction |
| Missing Labels | 0 | Excluded prior to feature extraction |
| Invalid Labels (not in {0, 1}) | 1 | Excluded prior to feature extraction |
| Exact Duplicate URLs | 1 | Deduplicated to prevent train/test inflation |
| Conflicting Labels | 0 | Excluded |
| Malformed / Unsupported Scheme URLs | 1 | Rejected by `validate_and_parse_url` |

## Class Balance

- **Benign (`0`)**: 174
- **Potentially Malicious (`1`)**: 109
- **Benign-to-Malicious Ratio**: 1.5963

## Provenance & Limitations

- **Source**: Curated Local Lexical Benchmark Dataset (Standard Public Domains + Defanged Synthetic Phishing Lexical Patterns)
- **Licence**: CC0-1.0 / MIT (RFC 2606 & RFC 5737 safe test ranges)
- **Limitations**: This dataset is a curated lexical benchmark for reproducible pipeline verification and local baseline model training. It is not a substitute for live threat intelligence feeds.
