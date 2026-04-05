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

const COLORS = ["#0ea5e9", "#22c55e", "#f97316", "#a78bfa", "#ef4444", "#14b8a6", "#f59e0b", "#8b5cf6"];

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
    <section>
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
          <ResponsiveContainer width="100%" height={320}>
            <BarChart data={industry.slice(0, 12)}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="Industry" angle={-20} textAnchor="end" interval={0} height={90} />
              <YAxis />
              <Tooltip />
              <Bar dataKey="avg_impact_musd" fill="#a78bfa" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h3>Top Sensitive Data Categories</h3>
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
