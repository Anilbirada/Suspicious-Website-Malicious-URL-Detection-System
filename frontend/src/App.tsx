import React, { useCallback, useEffect, useState } from 'react';
import { ActiveTab, Navbar } from './components/Navbar';
import { Footer } from './components/Footer';
import { DashboardPage } from './pages/DashboardPage';
import { HistoryPage } from './pages/HistoryPage';
import { ModelStatusPage } from './pages/ModelStatusPage';
import { AboutPage } from './pages/AboutPage';
import { fetchHistory, fetchModelStatus } from './services/apiClient';
import { AnalyzeURLResponse, HistoryItem, ModelStatusResponse } from './types/api';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('dashboard');
  const [modelStatus, setModelStatus] = useState<ModelStatusResponse | null>(null);
  const [modelError, setModelError] = useState<string | null>(null);
  const [recentHistory, setRecentHistory] = useState<HistoryItem[]>([]);

  const loadInitialData = useCallback(async () => {
    try {
      setModelError(null);
      const status = await fetchModelStatus();
      setModelStatus(status);
    } catch (err) {
      setModelError(
        err instanceof Error ? err.message : 'Unable to retrieve model status from backend.'
      );
    }

    try {
      const hist = await fetchHistory({ limit: 5 });
      if (hist.history_enabled) {
        setRecentHistory(hist.items);
      }
    } catch {
      // Ignore history fetch failure on initial mount if history is disabled
    }
  }, []);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  const handleAnalysisCompleted = (_result: AnalyzeURLResponse) => {
    loadInitialData();
  };

  return (
    <div className="app-shell">
      <Navbar activeTab={activeTab} onSelectTab={setActiveTab} modelStatus={modelStatus} />

      <main className="main-container" role="main">
        {activeTab === 'dashboard' && (
          <DashboardPage
            modelStatus={modelStatus}
            recentHistory={recentHistory}
            onAnalysisCompleted={handleAnalysisCompleted}
            onNavigateToHistory={() => setActiveTab('history')}
          />
        )}

        {activeTab === 'history' && <HistoryPage onHistoryChanged={loadInitialData} />}

        {activeTab === 'model' && (
          <ModelStatusPage
            modelStatus={modelStatus}
            error={modelError}
            onRefresh={loadInitialData}
          />
        )}

        {activeTab === 'about' && <AboutPage />}
      </main>

      <Footer />
    </div>
  );
};

export default App;
