Cyber Impact and ROI Platform

Overview
- This project estimates cyber incident financial impact and recommends controls with ROI style scoring.
- It combines model inference, control recommendation logic, analytics APIs, and scanner ingestion.
- It supports two React frontends:
	- Existing frontend in webapp
	- New redesigned frontend in webapp_new

Current Architecture
- Backend API: src/btp/api.py
	- FastAPI service for prediction, recommendations, analytics, and scanner endpoints.
- Inference engine: src/btp/infer.py
	- CatBoost based prediction with optional field filling from baselines.
- Recommendation engine: src/btp/mitigation.py
	- Maps attack type to control recommendations and computes expected return metrics.
- Scanner integration layer: src/btp/scanner_integration.py
	- Normalizes raw findings, enriches with NVD and remediation mapping, and builds scan prefill summaries.
- Scanner runtime assets: src/btp/scanner
	- Local agent script and remediation reference data used by scanner endpoints.
- Frontend (stable): webapp
- Frontend (new redesign): webapp_new
- Model and metadata artifacts: data/models
- Training and optimization notebooks: notebooks

Repository Layout
- src/btp/api.py: HTTP endpoints and request/response contracts.
- src/btp/app.py: ASGI entrypoint re-exporting the API app.
- src/btp/infer.py: Feature preparation and model inference.
- src/btp/mitigation.py: Control recommendation and ROI style calculations.
- src/btp/scanner_integration.py: Scanner ingestion and enrichment pipeline.
- src/btp/scanner/local_scanner.py: Downloaded local scanning agent.
- data/model_ready: Training-ready datasets.
- data/models: Serialized model artifacts and metadata.
- webapp: Original React frontend.
- webapp_new: New React frontend with theme mode toggle.

Backend Endpoints In Use
- GET /healthz
- GET /analytics
- POST /predict
- POST /recommend-controls
- POST /predict-and-recommend
- GET /scanner/readiness
- GET /scanner/agent
- GET /scanner/agent.sha256
- POST /scanner/upload_raw_scan
- GET /scanner/latest_results

Run Locally (Windows)

1. Create and activate virtual environment

	py -3.10 -m venv .venv310
	.\.venv310\Scripts\Activate.ps1
	python -m pip install --upgrade pip

2. Install backend dependencies

	python -m pip install -r requirements.txt

3. Start backend API from repo root

	$env:PYTHONPATH = ".\src"
	uvicorn btp.api:app --host 127.0.0.1 --port 8000 --reload

4. Start original frontend

	Set-Location .\webapp
	npm install
	npm run dev

5. Start redesigned frontend

	Set-Location .\webapp_new
	npm install
	npm run dev

Default URLs
- Backend: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs
- Original frontend: http://127.0.0.1:5173
- New frontend: http://127.0.0.1:5174

Environment Variables
- Frontend API base URL (optional): VITE_API_BASE
	- If not set, frontend defaults to http://127.0.0.1:8000
- NVD API key (optional but recommended for enrichment reliability): NVD_API_KEY

Field Handling Policy
- Mandatory input fields:
	- Industry
	- Year
	- Attack_Type
	- Data_Type
	- Records_Compromised
- Optional fields are filled only when missing or invalid:
	- Country
	- Employee_Count
	- Security_Budget_Million_USD
	- Recovery_Time_Days
	- Incident_Severity
	- Baseline_Industry_Cost_Million_USD
	- Canonical_Attack_Vector
- User supplied values always win over baseline fills.

Scanner Notes
- The scanner folder is part of the active architecture.
- Removing src/btp/scanner entirely will break scanner endpoints and scan workflows in both frontends.
- If scanner features are no longer needed, feature-flag and remove scanner routes first, then delete scanner assets.

Model Artifacts
- Runtime expects CatBoost model artifacts in data/models.
- The inference loader prefers impact_regressor_CatBoostRegressor.pkl and related metadata.
- Keep model and matching meta files aligned when replacing artifacts.

Common Troubleshooting
- Import errors when starting API:
	- Ensure PYTHONPATH is set to .\src before running uvicorn.
- Frontend says backend unavailable:
	- Confirm backend is running on port 8000 and CORS allows frontend port in src/btp/api.py.
- Scanner CVE and severity enrichment sparse:
	- Install nvdlib and set NVD_API_KEY to improve lookup quality and rate limits.
