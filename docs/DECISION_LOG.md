# Architecture and Technical Decision Log (ADR)

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## ADR-01: Pure Lexical Analysis Without Live Destination Fetching

- **Context**: Visiting or fetching untrusted URLs from a backend introduces severe Server-Side Request Forgery (SSRF), drive-by malware, and privacy-leakage risks.
- **Decision**: Analyse submitted URL strings strictly lexically in memory (`backend/app/features/url_extractor.py`) with zero outbound network or DNS calls.
- **Consequences**: Complete elimination of SSRF and remote execution attack surfaces (`TC-25`). Trade-off: cannot inspect live page DOM or TLS certificate validity; this limitation is explicitly disclosed in every response.

## ADR-02: Domain-Grouped Train/Test Split (`GroupShuffleSplit`)

- **Context**: Standard random train/test splitting on URL datasets allows multiple paths from the same domain (`example.com/a` and `example.com/b`) to appear in both train and test sets, artificially inflating evaluation metrics.
- **Decision**: Group all dataset records by `registrable_domain` and split using `GroupShuffleSplit(test_size=0.25, random_state=42)` with an explicit assertion that train and test domain sets have zero intersection.
- **Consequences**: Held-out evaluation measures generalization to unseen domains rather than memorization of seen hostnames.

## ADR-03: Calibrated Logistic Regression vs. Uncalibrated Heuristics

- **Context**: Users need interpretable risk scores and feature-level explanations, while fallback heuristics must never be misrepresented as probabilities.
- **Decision**:
  1. Use `CalibratedClassifierCV(StandardScaler + LogisticRegression)` for the ML pipeline so output probabilities in `[0.0, 1.0]` are calibrated and linear weights provide transparent feature-contribution explanations.
  2. Keep `run_rule_based_fallback()` in an isolated module (`backend/app/services/fallback_analyzer.py`) that sets `calibrated_score = null` and labels its output as `rule_based_fallback`.
- **Consequences**: Clear separation between statistical ML inference and deterministic fallback rules (`TC-18`).

## ADR-04: Optional Local History With Per-Request Opt-Out and Deletion

- **Context**: Storing submitted URLs helps analysts review recent checks, but some URLs may contain sensitive query parameters.
- **Decision**: Provide a per-request `save_to_history` checkbox on the dashboard, search/delete controls on the History page, and environment flags (`ENABLE_HISTORY`, `STORE_RAW_URL_IN_HISTORY`) to disable or redact storage globally.
- **Consequences**: Balances usability for local demonstrations with strong privacy controls (`TC-29`).

## ADR-05: Omission of Multi-User Authentication in MVP

- **Context**: Section 10 specifies `USER_ACCOUNT — ONLY IF AUTHENTICATION IS REQUIRED`.
- **Decision**: Omit user login/authentication tables for the local single-user application to avoid unnecessary complexity while documenting where authentication would be added for a multi-tenant deployment.
