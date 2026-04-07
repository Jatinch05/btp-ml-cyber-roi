import { useEffect, useLayoutEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import DecisionPage from "./pages/DecisionPage";
import MetricsPage from "./pages/MetricsPage";
import ScanPage from "./pages/ScanPage";

export default function App() {
  const [showIntro, setShowIntro] = useState(true);
  const [uiMode, setUiMode] = useState(() => {
    const saved = window.localStorage.getItem("uiMode") || "modern";
    document.body.dataset.ui = saved;
    return saved;
  });

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setShowIntro(false);
    }, 2400);

    return () => window.clearTimeout(timer);
  }, []);

  useLayoutEffect(() => {
    document.body.dataset.ui = uiMode;
    window.localStorage.setItem("uiMode", uiMode);
    return () => {
      delete document.body.dataset.ui;
    };
  }, [uiMode]);

  return (
    <>
      {showIntro ? (
        <div className="intro-overlay" aria-hidden="true">
          <div className="intro-orbs">
            <span className="intro-orb orb-a" />
            <span className="intro-orb orb-b" />
            <span className="intro-orb orb-c" />
          </div>
          <div className="intro-card">
            <span className="eyebrow">Atlas Risk Console</span>
            <h1>From threat evidence to investment clarity.</h1>
            <p>Forecast impact, run VAPT intake, and compare safeguards with confidence.</p>
            <div className="intro-steps">
              <span>1. Define risk scenario</span>
              <span>2. Simulate loss and controls</span>
              <span>3. Review expected return</span>
              <span>4. Validate with scan findings</span>
            </div>
            <div className="intro-loader">
              <span />
              <span />
              <span />
            </div>
          </div>
        </div>
      ) : null}

      <div className={`app-shell app-shell-enter ${uiMode === "legacy" ? "legacy-shell" : ""}`}>
        <header className="topbar">
          <div>
            <span className="brand-pill">Atlas Risk Console</span>
            <h1>Cyber ROI Decision Studio</h1>
            <p>Business impact forecasting, safeguard planning, and return simulation</p>
          </div>
          <div className="topbar-actions">
            <nav>
              <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>Decision Studio</NavLink>
              <NavLink to="/scan" className={({ isActive }) => (isActive ? "active" : "")}>Quick VAPT Scan</NavLink>
              <NavLink to="/metrics" className={({ isActive }) => (isActive ? "active" : "")}>Data Metrics</NavLink>
            </nav>
            <button
              type="button"
              className="theme-toggle"
              onClick={() => setUiMode((mode) => (mode === "modern" ? "legacy" : "modern"))}
              aria-label={uiMode === "legacy" ? "Switch to light mode" : "Switch to dark mode"}
              aria-pressed={uiMode === "legacy"}
            >
              {uiMode === "legacy" ? "Light" : "Dark"}
            </button>
          </div>
        </header>

        <main>
          <Routes>
            <Route path="/" element={<DecisionPage />} />
            <Route path="/scan" element={<ScanPage />} />
            <Route path="/metrics" element={<MetricsPage />} />
          </Routes>
        </main>
      </div>
    </>
  );
}
