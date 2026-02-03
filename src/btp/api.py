from typing import List, Optional
from fastapi import FastAPI
from pydantic import BaseModel, Field
import pandas as pd
from .infer import ImpactCatBoost

app = FastAPI(title="Cyber Impact Inference API", version="0.1.0")
_model = ImpactCatBoost()

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

@app.get("/healthz")
def healthz():
    return {"ok": True, "model": "CatBoostRegressor", "model_path": str(_model.model_path.name)}

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
