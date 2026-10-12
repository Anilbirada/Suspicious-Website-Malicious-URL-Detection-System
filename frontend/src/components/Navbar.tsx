import React from 'react';
import { ModelStatusResponse } from '../types/api';

export type ActiveTab = 'dashboard' | 'history' | 'model' | 'about';

interface NavbarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: ActiveTab) => void;
  modelStatus: ModelStatusResponse | null;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onSelectTab, modelStatus }) => {
  const isMlLoaded = modelStatus?.model_loaded ?? false;

  return (
    <header className="navbar" role="banner">
      <div className="navbar-inner">
        <div className="brand-block">
          <div className="brand-shield" aria-hidden="true">
            URL
          </div>
          <div>
            <div className="brand-title">Suspicious Website / Malicious URL Detection System</div>
            <div className="brand-subtitle">
              Lexical Risk Assessment &amp; Explainable Indicator Engine
            </div>
          </div>
        </div>

        <nav className="nav-links" aria-label="Primary Navigation">
          <button
            type="button"
            className={`nav-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => onSelectTab('dashboard')}
          >
            Analyse URL
          </button>
          <button
            type="button"
            className={`nav-btn ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => onSelectTab('history')}
          >
            Analysis History
          </button>
          <button
            type="button"
            className={`nav-btn ${activeTab === 'model' ? 'active' : ''}`}
            onClick={() => onSelectTab('model')}
          >
            Model Status
          </button>
          <button
            type="button"
            className={`nav-btn ${activeTab === 'about' ? 'active' : ''}`}
            onClick={() => onSelectTab('about')}
          >
            About &amp; Credits
          </button>

          {modelStatus && (
            <span
              className={`mode-pill ${isMlLoaded ? 'ml' : 'fallback'}`}
              title={modelStatus.status_message}
            >
              {isMlLoaded
                ? `ML Active (${modelStatus.model_version})`
                : 'Rule-Based Fallback Mode'}
            </span>
          )}
        </nav>
      </div>
    </header>
  );
};
