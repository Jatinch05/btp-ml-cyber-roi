import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  scannerDownloadAgent,
  scannerDownloadChecksum,
  scannerLatestResults,
  scannerUploadRaw,
} from "../api";
import { generalizeThreatScenario } from "../utils/dataTaxonomy";

const STEP_FLOW = [
  { title: "Download Agent", detail: "Get script and checksum" },
  { title: "Script Checks", detail: "Script verifies Nmap and checksum" },
  { title: "Choose Mode", detail: "Fast or thorough scan" },
  { title: "Run Scan", detail: "Execute locally on host" },
  { title: "Upload & Map", detail: "Normalize findings to taxonomy" },
  { title: "Prefill Business Case", detail: "Send suggested scenario to ROI" },
];

function downloadText(filename, text, mime = "text/plain") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ScanPage() {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [results, setResults] = useState([]);
  const [summary, setSummary] = useState(null);
  const [uploadText, setUploadText] = useState("");

  const findingsPreview = useMemo(() => results.slice(0, 15), [results]);

  async function onDownloadAgent() {
    setError("");
    setBusy(true);
    try {
      const [script, checksum] = await Promise.all([scannerDownloadAgent(), scannerDownloadChecksum()]);
      downloadText("secure_scope_local_scanner.py", script, "text/x-python");
      downloadText("secure_scope_local_scanner.py.sha256", checksum, "text/plain");
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onRefreshResults() {
    setError("");
    setBusy(true);
    try {
      const out = await scannerLatestResults();
      setResults(out?.data || []);
      setSummary(out?.summary || null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onUploadManualJson() {
    setError("");
    setBusy(true);
    try {
      const rows = JSON.parse(uploadText || "[]");
      if (!Array.isArray(rows)) {
        throw new Error("Manual upload must be a JSON array of rows");
      }
      const out = await scannerUploadRaw(rows);
      setResults(out?.data || []);
      setSummary(out?.summary || null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  function onUseForBusinessCase() {
    const attackRaw = summary?.suggested_attack_type || "Other";
    const severity = Number(summary?.suggested_incident_severity || 2);
    const records = Number(summary?.suggested_records_compromised || 10000);

    const prefill = {
      Attack_Type: generalizeThreatScenario(attackRaw),
      Incident_Severity: severity,
      Records_Compromised: records,
      scanner_summary: summary,
    };
    localStorage.setItem("scanPrefill", JSON.stringify(prefill));
    navigate("/");
  }

  return (
    <section className="page-enter">
      <div className="hero-panel card glow-card scan-hero">
        <div className="hero-copy">
          <span className="eyebrow">Quick VAPT Scan</span>
          <h2>Scan locally, then feed findings into business case analysis.</h2>
          <p className="muted">
            Users download the scanner, validate requirements, run scan on host, and return mapped findings into this app for ROSI recommendations.
          </p>
        </div>
      </div>

      <div className="card">
        <h3>Scan Flow</h3>
        <div className="flow-card scan-flow">
          {STEP_FLOW.map((step, idx) => (
            <div key={step.title} className="flow-step">
              <div className="flow-index">0{idx + 1}</div>
              <div>
                <strong>{step.title}</strong>
                <p>{step.detail}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="two-col">
        <div className="card">
          <h3>1) Download Scanner Agent</h3>
          <p className="muted">Downloads both script and checksum in one click.</p>
          <button type="button" onClick={onDownloadAgent} disabled={busy}>Download Script + Checksum</button>

          <h3 style={{ marginTop: 24 }}>2) Script Checks</h3>
          <p className="muted">
            The script now checks Nmap and verifies the checksum before asking for the target. If a check fails, it prints the fix steps and stops.
          </p>

          <h3 style={{ marginTop: 24 }}>3) Choose Scan Mode</h3>
          <p className="muted">
            When you run the script, choose fast scan for common ports or thorough scan for the deeper full-port pass.
          </p>
        </div>

        <div className="card">
          <h3>4) Upload / Refresh Findings</h3>
          <p className="muted">After running the local script, click refresh to fetch latest uploaded scan results.</p>
          <button type="button" onClick={onRefreshResults} disabled={busy}>Refresh Uploaded Results</button>

          <details style={{ marginTop: 14 }}>
            <summary>Manual JSON upload (fallback)</summary>
            <textarea
              rows={8}
              value={uploadText}
              onChange={(e) => setUploadText(e.target.value)}
              placeholder='[{"Host":"127.0.0.1","Port":"80","Service":"http","Product":"nginx","Version":"1.20","CPE":""}]'
            />
            <button type="button" onClick={onUploadManualJson} disabled={busy}>Upload JSON Findings</button>
          </details>

          {summary ? (
            <div className="placeholder-grid" style={{ marginTop: 14 }}>
              <div>
                <span>Rows processed</span>
                <strong>{summary.row_count}</strong>
              </div>
              <div>
                <span>Suggested scenario</span>
                <strong>{generalizeThreatScenario(summary.suggested_attack_type)}</strong>
              </div>
              <div>
                <span>Suggested severity</span>
                <strong>{summary.suggested_incident_severity}</strong>
              </div>
            </div>
          ) : null}

          <button type="button" className="inline-link" onClick={onUseForBusinessCase} disabled={!summary || busy}>
            Use Suggestions In Business Case
          </button>
        </div>
      </div>

      <div className="card">
        <h3>4) Mapped Findings Preview</h3>
        {findingsPreview.length === 0 ? (
          <p className="muted">No findings available yet. Run the local script and click Refresh Uploaded Results.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Attack Type</th>
                  <th>Vulnerability Type</th>
                  <th>CVE</th>
                  <th>CVSS</th>
                  <th>NVD Severity</th>
                </tr>
              </thead>
              <tbody>
                {findingsPreview.map((r, idx) => (
                  <tr key={`${r.Host}-${r.Port}-${idx}`}>
                    <td>{r.Host}</td>
                    <td>{r.Port}</td>
                    <td>{r.Service}</td>
                    <td>{r.Attack_Type}</td>
                    <td>{r.Security_Vulnerability_Type}</td>
                    <td>{r.CVE}</td>
                    <td>{r.CVSS_Score ?? ""}</td>
                    <td>{r.NVD_Severity}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {error ? <div className="card error">{error}</div> : null}
    </section>
  );
}