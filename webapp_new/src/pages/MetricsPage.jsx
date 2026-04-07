import { useEffect, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Pie,
  PieChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  Cell,
} from "recharts";
import MetricCard from "../components/MetricCard";
import { fetchAnalytics } from "../api";
import { normalizeLabel, summarizeDataCategoryRows } from "../utils/dataTaxonomy";

const COLORS = ["#1d8f8a", "#f4a261", "#4f6d9b", "#e76f51", "#2a9d8f", "#264653", "#d47e3f", "#7f8da6"];

export default function MetricsPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    (async () => {
      try {
        setData(await fetchAnalytics());
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  if (error) return <div className="card error">{error}</div>;
  if (!data) return <div className="card">Loading analytics...</div>;

  const k = data.kpis || {};
  const industry = (data.industry_avg || []).map((r) => ({
    ...r,
    Industry: normalizeLabel(r.Industry),
  }));

  const dataCategories = summarizeDataCategoryRows(data.top_data_type || [], 3);

  return (
    <section className="page-enter">
      <div className="hero-panel card glow-card metrics-hero">
        <div className="hero-copy">
          <span className="eyebrow">Data Metrics</span>
          <h2>See how the dataset behaves before you trust the result.</h2>
          <p className="muted">
            This page highlights the size, spread, and shape of the incident dataset so the business case is grounded in the data behind it.
          </p>
        </div>
        <div className="metrics-badges">
          <div className="metrics-badge">Top categories are generalized</div>
          <div className="metrics-badge">Counts reflect the generated dataset</div>
          <div className="metrics-badge">Charts use live backend analytics</div>
        </div>
      </div>

      <div className="cards-grid">
        <MetricCard title="Records" value={new Intl.NumberFormat("en-US").format(k.rows || 0)} />
        <MetricCard title="Industries" value={k.industries || 0} />
        <MetricCard title="Threat Scenarios" value={k.attack_types || 0} />
        <MetricCard title="Sensitive Data Categories" value={dataCategories.length || k.data_types || 0} />
        <MetricCard title="Avg Impact (USD M)" value={new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(k.avg_impact_musd || 0)} />
        <MetricCard title="Median Impact (USD M)" value={new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(k.median_impact_musd || 0)} />
      </div>

      <div className="two-col">
        <div className="card">
          <h3>Average Business Impact by Industry (USD M)</h3>
          <p className="muted">Higher bars indicate industries with greater average expected business impact.</p>
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={industry.slice(0, 12)}>
              <defs>
                <linearGradient id="metricsBarGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#1d8f8a" stopOpacity={0.95} />
                  <stop offset="100%" stopColor="#4f6d9b" stopOpacity={0.9} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="Industry" angle={-20} textAnchor="end" interval={0} height={90} />
              <YAxis />
              <Tooltip formatter={(value) => new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(Number(value || 0) * 1_000_000)} />
              <Bar dataKey="avg_impact_musd" fill="url(#metricsBarGradient)" radius={[12, 12, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Top Sensitive Data Categories</h3>
          <p className="muted">The chart groups niche categories into Other so the distribution stays readable.</p>
          <ResponsiveContainer width="100%" height={320}>
            <PieChart>
              <Pie data={dataCategories} dataKey="count" nameKey="data_category" outerRadius={120} label>
                {dataCategories.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
          <p className="muted">The top three categories are shown directly; the remaining categories are grouped into Other.</p>
        </div>
      </div>

      <div className="card">
        <h3>Recovery Time vs Business Impact</h3>
        <p className="muted">Each dot represents one incident record; farther right means longer recovery time and higher operational disruption.</p>
        <ResponsiveContainer width="100%" height={360}>
          <ScatterChart>
            <CartesianGrid />
            <XAxis type="number" dataKey="recovery_time_days" name="Recovery Time (days)" />
            <YAxis type="number" dataKey="impact_musd" name="Impact (USD M)" />
            <Tooltip cursor={{ strokeDasharray: "3 3" }} />
            <Scatter data={data.scatter || []} fill="#0ea5e9" />
          </ScatterChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
