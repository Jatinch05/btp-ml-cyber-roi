from __future__ import annotations
from pathlib import Path
from typing import List
import numpy as np
import pandas as pd
import joblib

# ----- paths (repo-relative) -----
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
MODELS_DIR = DATA_DIR / "models"

# Prefer explicit CatBoost artefact, fallback to generic impact_regressor.pkl
PREFERRED_MODELS = [
    "impact_regressor_CatBoostRegressor.pkl",
    "impact_regressor.pkl",
]
META_FILE = "preproc_cat.pkl"  # saved at training

FEATURE_COLS_ORDER = [
    "Industry","Country","Year",
    "Attack_Type","Data_Type",
    "Records_Compromised","Employee_Count",
    "Security_Budget_Million_USD","Recovery_Time_Days",
    "Incident_Severity","Baseline_Industry_Cost_Million_USD",
    "Budget_per_Employee","Records_per_Employee",
]

LEAKAGE_DROP = {"Per_Record_Cost_USD", "Estimated_Financial_Impact_Million_USD"}

WINSOR_COLS = [
    "Records_Compromised","Employee_Count","Security_Budget_Million_USD",
    "Recovery_Time_Days","Baseline_Industry_Cost_Million_USD",
    "Budget_per_Employee","Records_per_Employee"
]

def _winsorize(s: pd.Series, p: float = 0.005) -> pd.Series:
    if s.dropna().empty:
        return s
    lo, hi = s.quantile([p, 1 - p])
    return s.clip(lo, hi)

def _load_model_path() -> Path:
    for name in PREFERRED_MODELS:
        p = MODELS_DIR / name
        if p.exists():
            return p
    # last resort: any CatBoost artefact
    cands = sorted(MODELS_DIR.glob("*CatBoost*.pkl"))
    if cands:
        return cands[-1]
    raise FileNotFoundError("CatBoost model not found under data/models")

def _load_meta() -> dict:
    p = MODELS_DIR / META_FILE
    return joblib.load(p) if p.exists() else {"feature_cols": FEATURE_COLS_ORDER, "cat_cols": [
        "Industry","Country","Attack_Type","Data_Type"
    ]}

def preprocess(raw: pd.DataFrame) -> pd.DataFrame:
    """Mirror training: rename, drop leakage, impute, ratios, winsorize, order."""
    df = raw.copy()

    # unify naming seen in training
    if "Canonical_Attack_Vector" in df.columns and "Attack_Vector" not in df.columns:
        df = df.rename(columns={"Canonical_Attack_Vector": "Attack_Vector"})

    # drop leakage columns
    drop_now = [c for c in LEAKAGE_DROP if c in df.columns]
    if drop_now:
        df = df.drop(columns=drop_now, errors="ignore")

    # numeric then categorical impute (median / mode)
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    for c in num_cols:
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(df[c].median())
    cat_cols = [c for c in df.columns if c not in num_cols]
    for c in cat_cols:
        s = df[c].astype(str).replace({"nan": np.nan})
        mode = s.mode().iloc[0] if not s.mode().empty else ""
        df[c] = s.fillna(mode)

    # feature ratios
    eps = 1e-9
    if {"Security_Budget_Million_USD","Employee_Count"}.issubset(df.columns):
        df["Budget_per_Employee"] = df["Security_Budget_Million_USD"] / (df["Employee_Count"] + eps)
    if {"Records_Compromised","Employee_Count"}.issubset(df.columns):
        df["Records_per_Employee"] = df["Records_Compromised"] / (df["Employee_Count"] + eps)

    # winsorize heavy tails
    for c in WINSOR_COLS:
        if c in df.columns:
            df[c] = _winsorize(pd.to_numeric(df[c], errors="coerce"))

    # select and order
    cols = [c for c in FEATURE_COLS_ORDER if c in df.columns]
    X = df[cols].copy()

    # enforce dtypes for CatBoost: cats=str, nums=float
    cats = X.select_dtypes(exclude=[np.number]).columns.tolist()
    nums = X.select_dtypes(include=[np.number]).columns.tolist()
    for c in cats:
        X[c] = X[c].astype(str)
    for c in nums:
        X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
    return X

class ImpactCatBoost:
    """Serves CatBoost model trained on log-target (log1p)."""
    def __init__(self):
        self.model_path = _load_model_path()
        self.model = joblib.load(self.model_path)
        meta = _load_meta()
        self.feature_cols = meta.get("feature_cols", FEATURE_COLS_ORDER)
        self.cat_cols = meta.get("cat_cols", ["Industry","Country","Attack_Type","Data_Type"])

    def _align(self, X: pd.DataFrame) -> pd.DataFrame:
        for c in self.feature_cols:
            if c not in X.columns:
                X[c] = np.nan
        X = X[self.feature_cols].copy()
        # CatBoost expects raw categoricals as strings
        for c in self.cat_cols:
            if c in X.columns:
                X[c] = X[c].astype(str)
        for c in [c for c in X.columns if c not in self.cat_cols]:
            X[c] = pd.to_numeric(X[c], errors="coerce").fillna(0.0)
        return X

    def predict_musd(self, raw: pd.DataFrame) -> np.ndarray:
        Xp = preprocess(raw)
        Xp = self._align(Xp)
        pred_log = self.model.predict(Xp)              # predicts log1p(impact)
        y = np.expm1(np.clip(pred_log, -20, None))     # back to M$
        return np.maximum(y, 0.0)                      # no negatives
