import { NavLink, Route, Routes } from "react-router-dom";
import DecisionPage from "./pages/DecisionPage";
import MetricsPage from "./pages/MetricsPage";

export default function App() {
  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <h1>Cyber ROI Decision Studio</h1>
          <p>Business impact forecasting, safeguard planning, and return simulation</p>
        </div>
        <nav>
          <NavLink to="/" end className={({ isActive }) => (isActive ? "active" : "")}>Decision Studio</NavLink>
          <NavLink to="/metrics" className={({ isActive }) => (isActive ? "active" : "")}>Data Metrics</NavLink>
        </nav>
      </header>

      <main>
        <Routes>
          <Route path="/" element={<DecisionPage />} />
          <Route path="/metrics" element={<MetricsPage />} />
        </Routes>
      </main>
    </div>
  );
}
