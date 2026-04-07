import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
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

const MIN_RUN_OVERLAY_MS = 4200;
const REVEAL_FADE_MS = 700;

function delay(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export default function DecisionPage() {
  const [health, setHealth] = useState({ ok: false, model: "" });
  const [options, setOptions] = useState({ industries: [], attack_types: [], data_types: [] });
  const [loading, setLoading] = useState(false);
  const [runPhase, setRunPhase] = useState("idle");
  const [error, setError] = useState("");
  const [scanPrefillHint, setScanPrefillHint] = useState("");
  const [result, setResult] = useState(null);
  const revealTimerRef = useRef(null);

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

  useEffect(() => {
    const raw = localStorage.getItem("scanPrefill");
    if (!raw) return;
    try {
      const prefill = JSON.parse(raw);
      setForm((f) => ({
        ...f,
        Attack_Type: prefill.Attack_Type || f.Attack_Type,
        Incident_Severity:
          prefill.Incident_Severity == null ? f.Incident_Severity : String(prefill.Incident_Severity),
        Records_Compromised:
          prefill.Records_Compromised == null ? f.Records_Compromised : String(prefill.Records_Compromised),
      }));
      if (prefill?.scanner_summary) {
        setScanPrefillHint(
          `Prefilled from scan: ${prefill.scanner_summary.suggested_attack_type || "scenario"}, severity ${prefill.scanner_summary.suggested_incident_severity || "N/A"}`
        );
      } else {
        setScanPrefillHint("Prefilled from scan results");
      }
    } catch {
      // Ignore malformed scanner prefill data.
    } finally {
      localStorage.removeItem("scanPrefill");
    }
  }, []);

  const onChange = (key, value) => setForm((f) => ({ ...f, [key]: value }));

  const onSubmit = async (e) => {
    e.preventDefault();
    if (revealTimerRef.current) {
      window.clearTimeout(revealTimerRef.current);
      revealTimerRef.current = null;
    }
    setError("");
    setLoading(true);
    setRunPhase("running");
    setResult(null);
    const startedAt = performance.now();
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

      const elapsed = performance.now() - startedAt;
      const remaining = Math.max(0, MIN_RUN_OVERLAY_MS - elapsed);
      if (remaining > 0) {
        await delay(remaining);
      }

      setResult(out);
      setRunPhase("revealing");
      revealTimerRef.current = window.setTimeout(() => {
        setRunPhase("idle");
        revealTimerRef.current = null;
      }, REVEAL_FADE_MS);
    } catch (err) {
      setError(String(err));
      setRunPhase("idle");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    return () => {
      if (revealTimerRef.current) {
        window.clearTimeout(revealTimerRef.current);
      }
    };
  }, []);

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

  const flowSteps = [
    { label: "Input", detail: "Business segment and scenario" },
    { label: "Predict", detail: "Expected annual impact" },
    { label: "Recommend", detail: "Safeguards and costs" },
    { label: "ROI", detail: "Return and range" },
  ];

  const insightChips = [
    { label: "Expected Loss", value: usd(expectedLossUsd) },
    { label: "Residual Loss", value: usd(rec?.loss_after) },
    { label: "Safeguard Cost", value: usd(rec?.control_cost) },
    { label: "Return", value: `${ratio(rec?.rosi)}x` },
  ];

  return (
    <section className={`page-enter ${runPhase === "revealing" ? "page-reveal" : ""}`}>
      <div className="hero-panel card glow-card">
        <div className="hero-copy">
          <span className="eyebrow">Business Case Studio</span>
          <h2>Predict the impact. See the safeguards. Understand the return.</h2>
          <p className="muted">
            A clearer decision flow for cyber incidents: estimate financial impact, compare safeguard options,
            and review the return before spending.
          </p>
          <div className="hero-chips">
            {insightChips.map((chip) => (
              <div key={chip.label} className="hero-chip">
                <span>{chip.label}</span>
                <strong>{chip.value}</strong>
              </div>
            ))}
          </div>
        </div>
        <div className="hero-orbit">
          <div className="orbit-ring ring-one" />
          <div className="orbit-ring ring-two" />
          <div className="orbit-core">
            <span>Live</span>
            <strong>Decision Flow</strong>
            <small>Input → Predict → Recommend → ROI</small>
          </div>
        </div>
      </div>

      <div className="card flow-card">
        {flowSteps.map((step, idx) => (
          <div key={step.label} className="flow-step">
            <div className="flow-index">0{idx + 1}</div>
            <div>
              <strong>{step.label}</strong>
              <p>{step.detail}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="status-row">
        <span className={health.ok ? "pill ok" : "pill bad"}>{health.ok ? "Backend Connected" : "Backend Unavailable"}</span>
        {health.model ? <span className="muted">Model: {health.model}</span> : null}
        <span className="pill pulse">Probability-weighted ROI enabled</span>
        {scanPrefillHint ? <span className="pill ok">{scanPrefillHint}</span> : null}
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

      {runPhase === "running" || runPhase === "revealing" ? (
        <div className={`run-overlay-full ${runPhase === "revealing" ? "revealing" : ""}`} aria-live="polite" aria-busy="true">
          <div className="run-overlay-core">
            <div className="run-orb large" />
            <span className="eyebrow">Business Case in Progress</span>
            <h2>Calculating expected loss and safeguard return</h2>
            <p className="muted">Applying probability weighting, cost scaling, overlap penalties, and realistic mitigation bands.</p>
            <div className="run-bars large">
              <span />
              <span />
              <span />
              <span />
            </div>
            <small className="muted">Hold tight — results will reveal in a moment.</small>
          </div>
        </div>
      ) : null}

      {error ? <div className="card error">{error}</div> : null}

      {result ? (
        <div className={`results-reveal ${runPhase === "idle" ? "is-visible" : "is-hidden"}`}>
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

          <div className="card placeholder-card">
            <div className="placeholder-badge">Remediation Tools</div>
            <h3>Quick VAPT Scan</h3>
            <p className="muted">
              The scan experience lives on its own page so users can run or upload a scan first, then move into the business case flow.
            </p>
            <div className="placeholder-grid">
              <div>
                <span>Input mode</span>
                <strong>Run / upload</strong>
              </div>
              <div>
                <span>Output</span>
                <strong>Normalized findings</strong>
              </div>
              <div>
                <span>Next step</span>
                <strong>Controls + ROI</strong>
              </div>
            </div>
            <Link className="ghost-button inline-link" to="/scan">Open Quick VAPT Scan</Link>
          </div>

          <div className="two-col">
            <div className="card">
              <h3>Business Impact Waterfall (USD)</h3>
              <p className="muted">Probability-weighted loss avoided minus annual safeguard cost equals net annual value.</p>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={businessWaterfall}>
                  <defs>
                    <linearGradient id="businessWaterfallGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#22c55e" stopOpacity={0.78} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip formatter={(v) => usd(v)} />
                  <Bar dataKey="value" fill="url(#businessWaterfallGradient)" radius={[12, 12, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div className="card">
              <h3>Expected Return by Safeguard</h3>
              <p className="muted">This chart shows the expected return ratio. Higher values mean more business benefit per dollar spent. The return is now probability-weighted and cost-floored for realism.</p>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={controlChart} layout="vertical">
                  <defs>
                    <linearGradient id="expectedReturnGradient" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#22c55e" stopOpacity={0.95} />
                      <stop offset="100%" stopColor="#a78bfa" stopOpacity={0.95} />
                    </linearGradient>
                  </defs>
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
                  <Bar dataKey="expected_return" fill="url(#expectedReturnGradient)" radius={[0, 12, 12, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

        </div>
      ) : null}
    </section>
  );
}
