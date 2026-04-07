import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import DecisionPage from "./pages/DecisionPage";
import MetricsPage from "./pages/MetricsPage";
import ScanPage from "./pages/ScanPage";

export default function App() {
  const [showIntro, setShowIntro] = useState(true);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      setShowIntro(false);
    }, 6800);

    return () => window.clearTimeout(timer);
  }, []);

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
            <span className="eyebrow">Cyber ROI Studio</span>
            <h1>Turning cyber signals into business decisions.</h1>
            <p>Predict risk, scan vulnerabilities, and see the return before you invest.</p>
            <div className="intro-steps">
              <span>1. Assess incident risk</span>
              <span>2. Run the safeguard case</span>
              <span>3. Review expected return</span>
              <span>4. Explore VAPT intake</span>
            </div>
            <div className="intro-loader">
              <span />
              <span />
              <span />
            </div>
          </div>
        </div>
      ) : null}

      <div className="app-shell app-shell-enter">
        <header className="topbar">
          <div>
            <h1>Cyber ROI Decision Studio</h1>
            <p>Business impact forecasting, safeguard planning, and return simulation</p>
          </div>
          <nav>
            <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>Decision Studio</NavLink>
            <NavLink to="/scan" className={({ isActive }) => (isActive ? "active" : "")}>Quick VAPT Scan</NavLink>
            <NavLink to="/metrics" className={({ isActive }) => (isActive ? "active" : "")}>Data Metrics</NavLink>
          </nav>
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
