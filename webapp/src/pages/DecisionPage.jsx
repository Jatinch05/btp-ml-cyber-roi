import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import MetricCard from "../components/MetricCard";
import { fetchAnalytics, healthz, predictAndRecommend } from "../api";
import {
  GENERAL_THREAT_SCENARIO_OPTIONS,
  GENERAL_THREAT_SCENARIO_TO_RAW,
  GENERAL_DATA_CATEGORY_OPTIONS,
  GENERAL_DATA_CATEGORY_TO_RAW,
  normalizeLabel,
} from "../utils/dataTaxonomy";

function prettyLabel(value) {
  return normalizeLabel(value);
}

function usd(v) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(v || 0);
}

function usdM(v) {
  return `${new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(v || 0)} M USD`;
}

function ratio(v) {
  return new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(v || 0);
}

function orderedRange(low, high) {
  if (low == null && high == null) return [null, null];
  if (low == null) return [null, high];
  if (high == null) return [low, null];
  return low <= high ? [low, high] : [high, low];
}

function rangeText(low, high, formatter = ratio) {
  const [lo, hi] = orderedRange(low, high);
  if (lo == null && hi == null) return "N/A";
  if (lo == null) return `Up to ${formatter(hi)}`;
  if (hi == null) return `From ${formatter(lo)}`;
  return `${formatter(lo)} to ${formatter(hi)}`;
}

export default function DecisionPage() {
  const [health, setHealth] = useState({ ok: false, model: "" });
  const [options, setOptions] = useState({ industries: [], attack_types: [], data_types: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const [form, setForm] = useState({
    Industry: "",
    Year: new Date().getFullYear(),
    Attack_Type: "",
    Data_Type: "",
    Records_Compromised: 10000,
    Employee_Count: 500,
    Security_Budget_Million_USD: "",
    Incident_Severity: "",
    Recovery_Time_Days: "",
    Country: "",
  });

  useEffect(() => {
    (async () => {
      try {
        const [h, a] = await Promise.all([healthz(), fetchAnalytics()]);
        setHealth({ ok: !!h.ok, model: h.model || "" });
        setOptions(a.options || { industries: [], attack_types: [], data_types: [] });
        setForm((f) => ({
          ...f,
          Industry: f.Industry || (a.options?.industries?.[0] ?? ""),
          Attack_Type: f.Attack_Type || GENERAL_THREAT_SCENARIO_OPTIONS[0],
          Data_Type: f.Data_Type || GENERAL_DATA_CATEGORY_OPTIONS[0],
        }));
      } catch (e) {
        setError(String(e));
      }
    })();
  }, []);

  const onChange = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  const onSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const payload = {
        Industry: form.Industry,
        Year: Number(form.Year),
        Attack_Type: GENERAL_THREAT_SCENARIO_TO_RAW[form.Attack_Type] || form.Attack_Type,
        Data_Type: GENERAL_DATA_CATEGORY_TO_RAW[form.Data_Type] || form.Data_Type,
        Records_Compromised: Number(form.Records_Compromised),
        Employee_Count: form.Employee_Count === "" ? null : Number(form.Employee_Count),
        Security_Budget_Million_USD: form.Security_Budget_Million_USD === "" ? null : Number(form.Security_Budget_Million_USD),
        Incident_Severity: form.Incident_Severity === "" ? null : Number(form.Incident_Severity),
        Recovery_Time_Days: form.Recovery_Time_Days === "" ? null : Number(form.Recovery_Time_Days),
        Country: form.Country || null,
      };
      const out = await predictAndRecommend(payload);
      setResult(out);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const rec = result?.recommendation;
  const controls = rec?.recommendations ?? [];
  const expectedLossUsd = result?.expected_loss_usd ?? rec?.loss_before ?? result?.prediction_usd ?? 0;
  const rawLossUsd = result?.prediction_usd ?? rec?.raw_loss_before ?? 0;
  const attackProb = rec?.attack_probability ?? null;

  const controlChart = useMemo(
    () => controls.slice(0, 8).map((c) => ({
      name: c.control,
      expected_return: c.rosi ?? 0,
      return_low: c.rosi_low ?? null,
      return_high: c.rosi_high ?? null,
    })),
    [controls]
  );

  const businessWaterfall = useMemo(() => {
    if (!rec) return [];
    const reduction = Math.max((rec.loss_before || 0) - (rec.loss_after || 0), 0);
    return [
      { name: "Loss Avoided", value: reduction },
      { name: "Annual Safeguard Cost", value: -(rec.control_cost || 0) },
      { name: "Net Annual Value", value: reduction - (rec.control_cost || 0) },
    ];
  }, [rec]);

  return (
    <section>
      <div className="status-row">
        <span className={health.ok ? "pill ok" : "pill bad"}>{health.ok ? "Backend Connected" : "Backend Unavailable"}</span>
        {health.model ? <span className="muted">Model: {health.model}</span> : null}
      </div>

      <div className="card">
        <h2>Business Case Inputs</h2>
        <form className="grid" onSubmit={onSubmit}>
          <label>
            Business Segment
            <select value={form.Industry} onChange={(e) => onChange("Industry", e.target.value)} required>
              {options.industries.map((v) => <option key={v} value={v}>{prettyLabel(v)}</option>)}
            </select>
          </label>
          <label>
            Threat Scenario
            <select value={form.Attack_Type} onChange={(e) => onChange("Attack_Type", e.target.value)} required>
              {GENERAL_THREAT_SCENARIO_OPTIONS.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label>
            Sensitive Data Category
            <select value={form.Data_Type} onChange={(e) => onChange("Data_Type", e.target.value)} required>
              {GENERAL_DATA_CATEGORY_OPTIONS.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
          <label>
            Calendar Year
            <input type="number" value={form.Year} onChange={(e) => onChange("Year", e.target.value)} required />
          </label>
          <label>
            Records Exposed
            <input type="number" min="1" value={form.Records_Compromised} onChange={(e) => onChange("Records_Compromised", e.target.value)} required />
          </label>
          <label>
            Workforce Size (optional)
            <input type="number" min="0" value={form.Employee_Count} onChange={(e) => onChange("Employee_Count", e.target.value)} />
          </label>
          <label>
            Annual Protection Budget (M USD, optional)
            <input type="number" min="0" step="0.01" value={form.Security_Budget_Million_USD} onChange={(e) => onChange("Security_Budget_Million_USD", e.target.value)} />
          </label>
          <label>
            Incident Severity 1-5 (optional)
            <input type="number" min="1" max="5" value={form.Incident_Severity} onChange={(e) => onChange("Incident_Severity", e.target.value)} />
          </label>
          <label>
            Recovery Time (days, optional)
            <input type="number" min="0" value={form.Recovery_Time_Days} onChange={(e) => onChange("Recovery_Time_Days", e.target.value)} />
          </label>
          <label>
            Country (optional)
            <input value={form.Country} onChange={(e) => onChange("Country", e.target.value)} />
          </label>
          <div className="actions">
            <button type="submit" disabled={loading}>{loading ? "Running business case..." : "Run Business Case"}</button>
          </div>
        </form>
      </div>

      {error ? <div className="card error">{error}</div> : null}

      {result ? (
        <>
          <div className="cards-grid">
            <MetricCard
              title="Expected Business Loss"
              value={usd(expectedLossUsd)}
              subtitle={`Probability-adjusted from raw estimate ${usd(rawLossUsd)}${attackProb != null ? ` at ${(attackProb * 100).toFixed(1)}% annual likelihood` : ""}`}
            />
            <MetricCard title="Residual Business Loss" value={usd(rec?.loss_after)} subtitle="Expected loss remaining after recommended safeguards" />
            <MetricCard
              title="Annual Safeguard Cost"
              value={usd(rec?.control_cost)}
              subtitle={`Annual range: ${usd(rec?.control_cost_low)} to ${usd(rec?.control_cost_high)}`}
            />
            <MetricCard
              title="Expected Return"
              value={`${ratio(rec?.rosi)}x`}
              subtitle={`Range: ${rangeText(rec?.rosi_low, rec?.rosi_high)}x`}
            />
          </div>

          <div className="card">
            <h3>How To Read These Numbers</h3>
            <p className="muted">
              Raw model estimate is the impact if the incident occurs. Expected Business Loss applies annual threat likelihood.
              Residual Business Loss is expected loss after safeguard impact. Annual Safeguard Cost is annualized and size-scaled.
              Expected Return is the net value per $1 spent (ratio, not percent).
            </p>
          </div>

          <div className="two-col">
            <div className="card">
              <h3>Business Impact Waterfall (USD)</h3>
              <p className="muted">Probability-weighted loss avoided minus annual safeguard cost equals net annual value.</p>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={businessWaterfall}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip formatter={(v) => usd(v)} />
                  <Bar dataKey="value" fill="#0ea5e9" />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <h3>Expected Return by Safeguard</h3>
              <p className="muted">This chart shows the expected return ratio. Higher values mean more business benefit per dollar spent. The return is now probability-weighted and cost-floored for realism.</p>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={controlChart} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis type="category" dataKey="name" width={140} />
                  <Tooltip
                    formatter={(value, name, props) => {
                      if (name === "expected_return") {
                        return [ratio(value), "Expected Return"];
                      }
                      return [value, name];
                    }}
                    labelFormatter={(label) => `Safeguard: ${label}`}
                    content={({ active, payload, label }) => {
                      if (!active || !payload?.length) return null;
                      const row = payload[0].payload;
                      return (
                        <div className="tooltip-card">
                          <div className="tooltip-title">{label}</div>
                          <div>Expected Return: {ratio(row.expected_return)}x</div>
                          <div>Return Range: {rangeText(row.return_low, row.return_high)}x</div>
                        </div>
                      );
                    }}
                  />
                  <Bar dataKey="expected_return" fill="#22c55e" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="card">
            <h3>Top Recommended Safeguards</h3>
            <p className="muted">All costs are annual USD estimates. Return is ratio (not percent).</p>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Business Safeguard</th>
                    <th>Example Tools</th>
                    <th>Category</th>
                    <th>Effort</th>
                    <th>Annual Cost (USD)</th>
                    <th>Annual Cost Range (USD)</th>
                    <th>Annual Loss Reduction</th>
                    <th>Residual Loss (USD)</th>
                    <th>Expected Return (x)</th>
                    <th>Return Range (x)</th>
                    <th>Priority</th>
                  </tr>
                </thead>
                <tbody>
                  {controls.map((c, i) => (
                    <tr key={`${c.control}-${i}`}>
                      <td>{c.control}</td>
                      <td>{c.tool_examples}</td>
                      <td>{c.control_type}</td>
                      <td>{c.effort}</td>
                      <td>{usd(c.cost)}</td>
                      <td>{rangeText(c.cost_low, c.cost_high, usd)}</td>
                      <td>{new Intl.NumberFormat('en-US',{style:'percent',maximumFractionDigits:1}).format(c.risk_reduction || 0)}</td>
                      <td>{usd(c.loss_after)}</td>
                      <td>{`${ratio(c.rosi)}x`}</td>
                      <td>{`${rangeText(c.rosi_low, c.rosi_high)}x`}</td>
                      <td>{c.priority}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </section>
  );
}
