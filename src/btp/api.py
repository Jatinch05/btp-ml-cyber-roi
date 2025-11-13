from typing import List, Optional
from fastapi import FastAPI
from pydantic import BaseModel, Field
import pandas as pd
from .infer import ImpactCatBoost

app = FastAPI(title="Cyber Impact Inference API", version="0.1.0")
_model = ImpactCatBoost()

class IncidentIn(BaseModel):
    Industry: Optional[str] = None
    Country: Optional[str] = None
    Year: Optional[int] = None
    Attack_Type: Optional[str] = None
    Data_Type: Optional[str] = None
    Records_Compromised: Optional[float] = None
    Employee_Count: Optional[float] = None
    Security_Budget_Million_USD: Optional[float] = Field(None, alias="Security_Budget_Million_USD")
    Recovery_Time_Days: Optional[float] = None
    Incident_Severity: Optional[float] = None
    Baseline_Industry_Cost_Million_USD: Optional[float] = None
    Canonical_Attack_Vector: Optional[str] = None  # handled in preprocessing

class PredictionOut(BaseModel):
    prediction_musd: float

@app.get("/healthz")
def healthz():
    return {"ok": True, "model": "CatBoostRegressor", "model_path": str(_model.model_path.name)}

@app.post("/predict", response_model=List[PredictionOut])
def predict(items: List[IncidentIn]):
    df = pd.DataFrame([x.model_dump(by_alias=True) for x in items])
    preds = _model.predict_musd(df)
    return [{"prediction_musd": float(v)} for v in preds]
