from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
import pandas as pd
from .infer import ImpactCatBoost
from .mitigation import recommend_controls, estimate_company_size
from .scanner_integration import (
    agent_script_sha256,
    agent_script_text,
    latest_scan_results,
    process_raw_scan,
    scanner_readiness,
    summarize_for_prefill,
)

app = FastAPI(title="Cyber Impact Inference API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
_model = ImpactCatBoost()
ROOT = Path(__file__).resolve().parents[2]
MODEL_READY_REAL = ROOT / "data" / "model_ready" / "combined_clean.csv"
MODEL_READY_SYN = ROOT / "data" / "model_ready" / "synthetic_samples_ctgan_v2.csv"

class IncidentIn(BaseModel):
    """
    Input schema for incident breach prediction.
    
    FIELD PRIORITY: User-provided values ALWAYS take precedence over baselines.
    Only missing or invalid optional fields will be filled from industry baselines.
    
    Mandatory fields (user MUST provide):
      - Industry: Target industry
      - Year: Year of incident
      - Attack_Type: Type of attack vector
      - Data_Type: Type of data compromised
      - Records_Compromised: Number of records compromised
    
    Optional fields (user can omit; will be filled from baselines if missing/invalid):
      - Country: Country of incident
      - Employee_Count: Organization employee count (≤0 triggers fill)
      - Security_Budget_Million_USD: Annual security budget (≤0 triggers fill)
      - Recovery_Time_Days: Time to recover in days (≤0 triggers fill)
      - Incident_Severity: Severity level 1–5 (≤0 triggers fill)
      - Baseline_Industry_Cost_Million_USD: Industry baseline cost (≤0 triggers fill)
      - Canonical_Attack_Vector: (derived if missing)
    """
    # Mandatory
    Industry: str
    Year: int
    Attack_Type: str
    Data_Type: str
    Records_Compromised: float
    
    # Optional with baseline fallback (only filled if missing or invalid)
    Country: Optional[str] = None
    Employee_Count: Optional[float] = None
    Security_Budget_Million_USD: Optional[float] = Field(None, alias="Security_Budget_Million_USD")
    Recovery_Time_Days: Optional[float] = None
    Incident_Severity: Optional[float] = None
    Baseline_Industry_Cost_Million_USD: Optional[float] = None
    Canonical_Attack_Vector: Optional[str] = None  # handled in preprocessing

class PredictionOut(BaseModel):
    prediction_musd: float
    fields_filled: Optional[List[str]] = None  # Which optional fields were filled from baselines


class RecommendationIn(BaseModel):
    attack_type: str
    predicted_loss_usd: float
    industry: str
    company_size: Optional[str] = None
    employee_count: Optional[float] = None
    device_count: Optional[float] = None
    coverage: Optional[float] = None
    implementation_quality: Optional[float] = None


class RecommendationOut(BaseModel):
    attack_type_input: str
    mapped_vulnerability: str
    raw_loss_before: float
    attack_probability: float
    loss_before: float
    expected_loss_before: Optional[float] = None
    coverage: float
    implementation_quality: float
    company_size: str
    mitigatable_fraction: Optional[float] = None
    combined_effectiveness: float
    combined_effectiveness_low: Optional[float] = None
    combined_effectiveness_high: Optional[float] = None
    loss_after: float
    loss_after_low: Optional[float] = None
    loss_after_high: Optional[float] = None
    control_cost: float
    control_cost_low: Optional[float] = None
    control_cost_high: Optional[float] = None
    rosi: Optional[float] = None
    rosi_low: Optional[float] = None
    rosi_high: Optional[float] = None
    recommendations: List[Dict[str, Any]]


class PredictAndRecommendOut(BaseModel):
    prediction_musd: float
    prediction_usd: float
    expected_loss_usd: float
    fields_filled: Optional[List[str]] = None
    recommendation: RecommendationOut


class ScannerReadinessOut(BaseModel):
    ready: bool
    checks: List[Dict[str, Any]]
    instructions: List[str]


class ScannerUploadOut(BaseModel):
    status: str
    data: List[Dict[str, Any]]
    summary: Dict[str, Any]


def _load_analytics_df() -> pd.DataFrame:
    if not MODEL_READY_REAL.exists():
        raise FileNotFoundError(f"Dataset not found: {MODEL_READY_REAL}")
    df_real = pd.read_csv(MODEL_READY_REAL)
    if MODEL_READY_SYN.exists():
        df_syn = pd.read_csv(MODEL_READY_SYN)
        return pd.concat([df_real, df_syn], ignore_index=True)
    return df_real


@app.get("/scanner/readiness", response_model=ScannerReadinessOut)
def scanner_readiness_endpoint():
    return scanner_readiness()


@app.get("/scanner/agent")
def scanner_agent_download():
    return PlainTextResponse(agent_script_text(), media_type="text/x-python")


@app.get("/scanner/agent.sha256")
def scanner_agent_checksum():
    digest = agent_script_sha256()
    content = f"{digest}  secure_scope_local_scanner.py\n"
    return PlainTextResponse(content, media_type="text/plain")


@app.post("/upload_raw_scan", response_model=ScannerUploadOut)
@app.post("/scanner/upload_raw_scan", response_model=ScannerUploadOut)
def scanner_upload_raw_scan(raw_results: List[Dict[str, Any]]):
    if not raw_results:
        raise HTTPException(status_code=400, detail="No scan results provided")
    if len(raw_results) > 10000:
        raise HTTPException(status_code=413, detail="Too many scan rows")
    enriched = process_raw_scan(raw_results).fillna("")
    rows = enriched.to_dict(orient="records")
    return {
        "status": "success",
        "data": rows,
        "summary": summarize_for_prefill(rows),
    }


@app.get("/scanner/latest_results", response_model=ScannerUploadOut)
def scanner_latest_results():
    rows = latest_scan_results()
    return {
        "status": "success",
        "data": rows,
        "summary": summarize_for_prefill(rows),
    }

@app.get("/healthz")
def healthz():
    return {"ok": True, "model": "CatBoostRegressor", "model_path": str(_model.model_path.name)}


@app.get("/analytics")
def analytics():
    """Aggregated analytics payload for web frontend dashboards."""
    df = _load_analytics_df()
    loss_col = "Financial_Impact_Million_USD" if "Financial_Impact_Million_USD" in df.columns else "Financial_Loss_Million_USD"
    time_col = "Recovery_Time_Days" if "Recovery_Time_Days" in df.columns else "Resolution_Time_Hours"

    kpis = {
        "rows": int(len(df)),
        "industries": int(df["Industry"].nunique() if "Industry" in df.columns else 0),
        "attack_types": int(df["Attack_Type"].nunique() if "Attack_Type" in df.columns else 0),
        "data_types": int(df["Data_Type"].nunique() if "Data_Type" in df.columns else 0),
        "avg_impact_musd": float(pd.to_numeric(df[loss_col], errors="coerce").mean()),
        "median_impact_musd": float(pd.to_numeric(df[loss_col], errors="coerce").median()),
    }

    loss_col_name = str(loss_col)
    if "Industry" in df.columns:
        industry_avg_df = (
            df.groupby("Industry", as_index=False)
            .agg(avg_impact_musd=(loss_col_name, "mean"))
            .sort_values("avg_impact_musd", ascending=False)
        )
        industry_avg = industry_avg_df.to_dict(orient="records")
    else:
        industry_avg = []

    attack_share = (
        df["Attack_Type"].astype(str).value_counts(dropna=False).rename_axis("attack_type").reset_index(name="count").to_dict(orient="records")
    ) if "Attack_Type" in df.columns else []

    top_data_type = (
        df["Data_Type"].astype(str).value_counts(dropna=False).rename_axis("data_type").reset_index(name="count").head(12).to_dict(orient="records")
    ) if "Data_Type" in df.columns else []

    scatter_cols = [c for c in ["Industry", "Attack_Type", "Data_Type", time_col, loss_col] if c in df.columns]
    scatter_df = df[scatter_cols].copy()
    if len(scatter_df) > 2500:
        scatter_df = scatter_df.sample(2500, random_state=42)
    scatter_rows = []
    for _, r in scatter_df.iterrows():
        scatter_rows.append(
            {
                "industry": str(r.get("Industry", "")),
                "attack_type": str(r.get("Attack_Type", "")),
                "data_type": str(r.get("Data_Type", "")),
                "recovery_time_days": float(pd.to_numeric(pd.Series([r.get(time_col)]), errors="coerce").fillna(0.0).iloc[0]),
                "impact_musd": float(pd.to_numeric(pd.Series([r.get(loss_col)]), errors="coerce").fillna(0.0).iloc[0]),
            }
        )

    options = {
        "industries": sorted(df["Industry"].dropna().astype(str).str.strip().unique().tolist()) if "Industry" in df.columns else [],
        "attack_types": sorted(df["Attack_Type"].dropna().astype(str).str.strip().unique().tolist()) if "Attack_Type" in df.columns else [],
        "data_types": sorted(df["Data_Type"].dropna().astype(str).str.strip().unique().tolist()) if "Data_Type" in df.columns else [],
    }

    return {
        "kpis": kpis,
        "industry_avg": industry_avg,
        "attack_share": attack_share,
        "top_data_type": top_data_type,
        "scatter": scatter_rows,
        "options": options,
    }

@app.post("/predict", response_model=List[PredictionOut])
def predict(items: List[IncidentIn]):
    """
    Predict breach financial impact (millions USD).
    
    USER INPUT PRIORITY:
    - User-provided values ALWAYS take precedence over baselines.
    - Missing or invalid optional fields are filled from industry baselines.
    - Response includes 'fields_filled' to show which optional fields were baseline-filled.
    """
    results = []
    for item in items:
        row_dict = item.model_dump(by_alias=True)
        filled_fields = _track_filled_fields(row_dict)
        df = pd.DataFrame([row_dict])
        pred = _model.predict_musd(df)[0]
        results.append({
            "prediction_musd": float(pred),
            "fields_filled": filled_fields
        })
    return results


@app.post("/recommend-controls", response_model=RecommendationOut)
def recommend_endpoint(item: RecommendationIn):
    if item.predicted_loss_usd < 0:
        raise ValueError("predicted_loss_usd must be >= 0")
    result = recommend_controls(
        attack_type=item.attack_type,
        loss_before=float(item.predicted_loss_usd),
        industry=item.industry,
        company_size=item.company_size,
        employee_count=item.employee_count,
        device_count=item.device_count,
        coverage=item.coverage,
        implementation_quality=item.implementation_quality,
    )
    return result


@app.post("/predict-and-recommend", response_model=List[PredictAndRecommendOut])
def predict_and_recommend(items: List[IncidentIn]):
    """Predict incident impact, then compute control recommendations + ROSI."""
    outputs = []
    for item in items:
        row_dict = item.model_dump(by_alias=True)
        filled_fields = _track_filled_fields(row_dict)
        df = pd.DataFrame([row_dict])
        pred_musd = float(_model.predict_musd(df)[0])
        pred_usd = pred_musd * 1_000_000.0

        rec = recommend_controls(
            attack_type=row_dict.get("Attack_Type", "Other"),
            loss_before=pred_usd,
            industry=row_dict.get("Industry", "Unknown"),
            company_size=estimate_company_size(row_dict.get("Employee_Count"), None),
            employee_count=row_dict.get("Employee_Count"),
            device_count=row_dict.get("Employee_Count"),
        )

        outputs.append(
            {
                "prediction_musd": pred_musd,
                "prediction_usd": pred_usd,
                "expected_loss_usd": float(rec.get("loss_before", pred_usd)),
                "fields_filled": filled_fields,
                "recommendation": rec,
            }
        )
    return outputs

def _track_filled_fields(row_dict: dict) -> List[str]:
    """
    Identify which optional fields were missing/invalid and will be filled from baselines.
    Returns list of field names that will be baseline-filled.
    """
    filled = []
    optional_numeric = {
        "Employee_Count", "Security_Budget_Million_USD",
        "Recovery_Time_Days", "Incident_Severity", "Baseline_Industry_Cost_Million_USD"
    }
    optional_string = {"Country", "Canonical_Attack_Vector"}
    
    # Check numeric optionals: filled if None or <= 0
    for field in optional_numeric:
        val = row_dict.get(field)
        if val is None or (isinstance(val, (int, float)) and val <= 0):
            filled.append(field)
    
    # Check string optionals: filled only if None
    for field in optional_string:
        val = row_dict.get(field)
        if val is None:
            filled.append(field)
    
    return filled if filled else None # type: ignore
