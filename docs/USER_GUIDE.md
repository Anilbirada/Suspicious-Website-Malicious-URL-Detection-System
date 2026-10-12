# User Guide

**Project**: Suspicious Website / Malicious URL Detection System  
**Developer**: Anil Biradar  
**Version**: 1.0.0  

---

## 1. Analysing a URL

1. Open the application in your browser (`http://localhost:5173`).
2. On the **Analyse URL** dashboard, enter a complete `http://` or `https://` URL into the input field (or click one of the three **Load test fixture** buttons to populate an example).
3. Optional controls:
   - **Save result in local analysis history**: Checked by default. Uncheck if you do not want the URL saved in the local SQLite database.
   - **Use Rule-Based Fallback Mode**: Check to compare deterministic heuristic rules against the calibrated ML model.
4. Click **Analyse URL**.

---

## 2. Understanding Assessment Results

Each assessment assigns one of four categories:

- **Potentially Malicious (Red)**: The URL contains strong lexical risk indicators or a calibrated ML probability $\ge 0.70$ (e.g., raw IP address with credential paths, `@` authority obfuscation, or multiple high-risk lexical patterns).
- **Suspicious (Amber)**: The URL contains notable lexical warning signs or a calibrated ML probability between $0.35$ and $0.70$ (e.g., deep subdomain hierarchy, hyphenated brand keywords, or Punycode domain labels).
- **Lower Risk Indicators Found (Green)**: Fewer lexical risk indicators were detected in the URL string ($< 0.35$). **Important**: This does not guarantee that the destination website is safe.
- **Unable to Determine (Neutral)**: The system could not establish a category.

### Reviewing Indicators and Features
- **Explainable Assessment Indicators**: Lists each specific lexical finding (`[HIGH]`, `[MEDIUM]`, `[LOW]`, `[INFO]`) along with the exact observed value in the URL.
- **Extracted URL Lexical Characteristics**: Displays all 18 numeric features extracted from the URL string.
- **Recommended Cautionary Actions**: Practical steps to stay safe before interacting with the link.

---

## 3. Managing Analysis History

1. Click **Analysis History** in the top navigation bar.
2. Filter stored records by entering a domain/URL substring or selecting an assessment category.
3. Click **Details** on any row to inspect the full indicator and feature breakdown for that historical analysis.
4. Click **Delete** on an individual row or **Delete All History** to permanently remove stored records.

---

## 4. Checking Model Status & Evaluation Metrics

Click **Model Status** in the top navigation bar to view:
- Whether the calibrated ML model (`1.0.0-logreg-calibrated`) is active or fallback mode is active.
- Feature schema version (`v1.0.0`, 18 features).
- Held-out evaluation metrics (`Precision`, `Recall`, `F1-Score`, `ROC-AUC`, `PR-AUC`, and `Confusion Matrix`) computed on the domain-grouped test split.
