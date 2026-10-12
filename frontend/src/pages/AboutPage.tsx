import React from 'react';

export const AboutPage: React.FC = () => {
  return (
    <div>
      <section className="card" aria-labelledby="about-heading">
        <h1 id="about-heading" className="section-title">
          About &amp; Project Credits
        </h1>
        <p className="section-desc">
          Suspicious Website / Malicious URL Detection System — Explainable Lexical URL Risk
          Assessment Application.
        </p>

        <div className="meta-grid" style={{ marginTop: '1.25rem' }}>
          <div className="meta-item">
            <div className="meta-label">Project Title</div>
            <div className="meta-value">Suspicious Website / Malicious URL Detection System</div>
          </div>
          <div className="meta-item">
            <div className="meta-label">Developer Credit</div>
            <div className="meta-value" data-testid="about-developer-credit">
              Developer: Anil Biradar
            </div>
          </div>
          <div className="meta-item">
            <div className="meta-label">Architecture</div>
            <div className="meta-value">FastAPI + Scikit-Learn + React + TypeScript + SQLite</div>
          </div>
        </div>

        <div className="notice-grid" style={{ marginTop: '1.25rem' }}>
          <div className="notice-box">
            <strong>Security-First Zero-Fetch Design</strong>
            This system evaluates submitted URL strings strictly lexically in memory. It never
            opens submitted links in a browser, never fetches remote HTML or scripts from the
            backend, and never executes external shell commands—preventing Server-Side Request
            Forgery (SSRF) and drive-by remote content execution.
          </div>
          <div className="notice-box">
            <strong>Honest Machine Learning &amp; Fallback Separation</strong>
            When a verified, schema-compatible scikit-learn model is loaded, predictions use
            calibrated probability thresholds evaluated on a domain-grouped held-out split. When
            fallback mode is active, deterministic lexical rules are used and explicitly labelled
            so heuristic points are never misrepresented as probabilities.
          </div>
          <div className="notice-box">
            <strong>Third-Party Open-Source Attribution</strong>
            Built using open-source software including Python, FastAPI, Pydantic, SQLAlchemy,
            scikit-learn, pandas, NumPy, joblib, idna, React, TypeScript, and Vite under their
            respective open-source licences (MIT, BSD, Apache-2.0, PSF).
          </div>
        </div>
      </section>
    </div>
  );
};
