# SecureScope

SecureScope runs local nmap scans from a downloaded agent, enriches results with NVD CVE/CVSS data, maps remediation controls, and supports ROI analysis.

NVD enrichment uses CPE-first matching (when available), plus keyword fallback and CVSS-based candidate ranking for improved relevance.

## Quick Start (Local)

1. Create and activate virtual environment.
2. Install dependencies:

```powershell
pip install -r requirements.txt
```

3. Start backend:

```powershell
cd backend
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

4. Start frontend:

```powershell
cd frontend
streamlit run app.py
```

5. In Scanner page, download the local agent and run it on the target machine.

## Security Configuration (Production)

Set these environment variables before running backend:

- `SECURESCOPE_API_KEY`: API key required by backend endpoints when set.
- `SECURESCOPE_ALLOWED_ORIGINS`: Comma-separated allowed frontend origins.
- `SECURESCOPE_ENABLE_SERVER_SIDE_SCAN`: `false` by default. Keep disabled unless explicitly needed.
- `SECURESCOPE_MAX_UPLOAD_ROWS`: Upload row safety limit, default `2000`.
- `SECURESCOPE_RATE_LIMIT_WINDOW_SEC`: Rate-limit window seconds, default `60`.
- `SECURESCOPE_RATE_LIMIT_MAX_REQUESTS`: Max requests per IP in window, default `60`.
- `NVD_API_KEY`: NVD key for faster and more reliable CVE lookups.

Example:

```powershell
$env:SECURESCOPE_API_KEY = "replace-with-strong-key"
$env:SECURESCOPE_ALLOWED_ORIGINS = "https://your-frontend.example.com"
$env:SECURESCOPE_ENABLE_SERVER_SIDE_SCAN = "false"
$env:SECURESCOPE_MAX_UPLOAD_ROWS = "2000"
$env:SECURESCOPE_RATE_LIMIT_WINDOW_SEC = "60"
$env:SECURESCOPE_RATE_LIMIT_MAX_REQUESTS = "60"
$env:NVD_API_KEY = "replace-with-nvd-key"
```

Set these environment variables on machines running the downloaded local agent:

- `SECURESCOPE_BACKEND_URL`: API base URL, for example `https://your-api.example.com`.
- `SECURESCOPE_API_KEY`: Same API key configured on backend.
- `SECURESCOPE_UPLOAD_TIMEOUT`: Upload timeout seconds, default `900`.
- `SECURESCOPE_AGENT_SHA256`: Optional expected SHA-256 hash for local script self-verification.

Example:

```powershell
$env:SECURESCOPE_BACKEND_URL = "https://your-api.example.com"
$env:SECURESCOPE_API_KEY = "replace-with-strong-key"
$env:SECURESCOPE_UPLOAD_TIMEOUT = "900"
$env:SECURESCOPE_AGENT_SHA256 = "paste-agent-sha256-here"
python secure_scope_local_scanner.py
```

NVD performance note:

- Without `NVD_API_KEY`, NVD queries are rate-limited and can be slow for large scans.
- The backend uses a faster no-key strategy by default to reduce timeouts.
- For best speed and coverage, configure `NVD_API_KEY` on backend.

## Integrity Verification Workflow

1. In Scanner page, download both files:
	- `secure_scope_local_scanner.py`
	- `secure_scope_local_scanner.py.sha256`
2. Verify hash on target machine:

```powershell
Get-FileHash -Algorithm SHA256 .\secure_scope_local_scanner.py
```

3. Compare output with the `.sha256` file value.
4. Optional strict mode: set `SECURESCOPE_AGENT_SHA256` to the expected value; the agent exits on mismatch.

## Coverage Quality Metrics

The Scanner page includes coverage metrics:

- CVE Coverage: rows with non-`N/A` CVE.
- CVSS Coverage: rows with non-null CVSS score.
- Specific Remediation: rows mapped to explicit controls (not generic fallback).
- Fallback Remediation: rows using manual fallback remediation.

Use these metrics to justify data quality and prioritization confidence during evaluation.

## Production Notes

- Always run backend behind HTTPS (reverse proxy or load balancer).
- Keep `SECURESCOPE_ENABLE_SERVER_SIDE_SCAN=false` unless absolutely required.
- Rotate API keys periodically.
- Restrict inbound firewall rules to trusted frontend/agent networks.
- Move persistent data from CSV to a database before multi-tenant deployment.
