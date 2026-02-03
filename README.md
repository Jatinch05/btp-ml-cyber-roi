ML-Based Cyber Vulnerability Impact & ROI

Overview
- Decision-support system that estimates breach financial impact (loss) in millions USD — it does not predict breach likelihood.
- Uses enriched real + synthetic data; ML estimates expected loss based on industry, attack/data types, scale, and security posture.
- User-input priority: users provide what they know; only missing/invalid optional fields are filled with defensible industry baselines (IBM/DBIR-style anchors). See FIELD_HANDLING.md.
- ROI/ROSI: computed from before–after loss estimates minus control cost (final formula configurable).

Repository Layout
- Data pipeline: src/btp/enrich.py (merges raw datasets, normalizes fields, applies IBM baselines, computes proxies)
- Inference: src/btp/infer.py (preprocessing + CatBoost inference; optional fields filled only if missing)
- API: src/btp/api.py (FastAPI endpoints /healthz, /predict)
- CLI: src/btp/cli_predict.py (reads JSON/JSONL from stdin, prints predictions)
- Streamlit prototype: src/btp/stream_app.py (demo dashboard)
- Notebooks: notebooks/ (training/synthetic generation)
- Models: data/models/ (expected CatBoost pickle + preprocessing meta)

Quickstart (Windows, Python 3.10 recommended)
1) Create and activate a Python 3.10 virtual env
```powershell
py -3.10 -m venv .venv310
.\.venv310\Scripts\Activate.ps1
python -V
python -m pip install --upgrade pip
```

2) Install dependencies
```powershell
python -m pip install -r requirements.txt
# Required for model/API/run
python -m pip install catboost==1.2.5 fastapi uvicorn
# Optional (Streamlit dashboard)
python -m pip install streamlit plotly
```

3) Prepare data (optional, if you want to regenerate processed/enriched data)
```powershell
$env:PYTHONPATH = ".\src"
python -m btp.enrich
```
This writes processed files under data/processed/.

4) Run the API
```powershell
$env:PYTHONPATH = ".\src"
uvicorn btp.api:app --reload --port 8000
```
Health: http://localhost:8000/healthz
Docs: http://localhost:8000/docs

5) Call the API
POST /predict — body is a list of incidents. Example (minimal: mandatory fields only):
```json
[
	{
		"Industry": "Finance",
		"Year": 2024,
		"Attack_Type": "Phishing",
		"Data_Type": "PII_Customer",
		"Records_Compromised": 50000
	}
]
```
Response:
```json
[
	{ "prediction_musd": 3.45, "fields_filled": ["Employee_Count","Security_Budget_Million_USD","Recovery_Time_Days","Incident_Severity","Baseline_Industry_Cost_Million_USD"] }
]
```

6) CLI usage (stdin JSON/JSONL)
```powershell
$env:PYTHONPATH = ".\src"
@"
{"Industry":"Finance","Year":2024,"Attack_Type":"Phishing","Data_Type":"PII_Customer","Records_Compromised":50000}
"@ | python -m btp.cli_predict
```

Field Handling (Mandatory vs Optional)
- Mandatory (must provide): Industry, Year, Attack_Type, Data_Type, Records_Compromised
- Optional (filled only if missing/invalid): Country, Employee_Count, Security_Budget_Million_USD, Recovery_Time_Days, Incident_Severity, Baseline_Industry_Cost_Million_USD, Canonical_Attack_Vector
- Policy: User values always take precedence. Only null/zero/negative (for numerics) or null (for strings) will be baseline-filled.
- See FIELD_HANDLING.md for details and examples.

Running Local Validation
```powershell
python .\test_field_handling.py
```
This script demonstrates minimal/full/partial inputs and shows that user values are preserved while missing optional fields are filled.

Models & Artifacts
- Place trained model artefacts under data/models/ (e.g., impact_regressor_CatBoostRegressor.pkl plus optional preproc_cat.pkl).
- Inference will auto-select the best available CatBoost model; raises a clear error if none are found.

Notes & Decisions
- This project estimates financial impact only; it does not model breach likelihood.
- ROSI/ROI is computed from before–after loss estimates minus control cost; final policy can be configured in the application layer.
- Synthetic data can be ablated or reweighted during training to assess performance impact.

Troubleshooting
- If API fails to start due to missing packages, ensure you installed fastapi and uvicorn.
- If CatBoost unpickle errors occur, install a compatible version (catboost==1.2.x on Python 3.10 is a safe choice).
- If module imports fail, set PYTHONPATH to include ./src when running modules (PowerShell: `$env:PYTHONPATH=".\src"`).

Additional Docs
- FIELD_HANDLING.md — Mandatory vs optional fields, baseline logic, examples
- IMPLEMENTATION_NOTES.md — Technical changes and reasoning
- QUICK_REFERENCE.md — One-page reference for developers
