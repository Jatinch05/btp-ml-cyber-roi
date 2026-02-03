from __future__ import annotations
from pathlib import Path
from typing import Dict, List, Optional
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
META_FALLBACK = "preproc_cat.pkl"  # legacy; prefer model-matched meta when available

# Default feature order (used only if no meta is found). Includes engineered features
# introduced in the optimized notebook so inference stays aligned with training.
FEATURE_COLS_ORDER = [
    "Industry", "Country", "Year",
    "Attack_Type", "Data_Type",
    "Records_Compromised", "Employee_Count",
    "Security_Budget_Million_USD", "Recovery_Time_Days",
    "Incident_Severity", "Baseline_Industry_Cost_Million_USD",
    "Budget_per_Employee", "Records_per_Employee",
    # Engineered features
    "Industry_AttackType_median_loss", "Records_per_Budget_Million",
    "Severity_x_Scale", "Years_Since_Start", "Industry_Year_Trend",
    "Budget_per_Employee_log", "Breach_Scale_per_Employee",
]

LEAKAGE_DROP = {"Per_Record_Cost_USD", "Estimated_Financial_Impact_Million_USD"}

WINSOR_COLS = [
    "Records_Compromised", "Employee_Count", "Security_Budget_Million_USD",
    "Recovery_Time_Days", "Baseline_Industry_Cost_Million_USD",
    "Budget_per_Employee", "Records_per_Employee",
]

# Hard defaults so baseline filling never returns None
DEFAULT_BASELINES: Dict[str, object] = {
    "emp_by_ind": {"Healthcare": 1500, "Finance": 800, "Technology": 1200, "Retail": 400, "Public": 200, "Industrial": 500, "Education": 300},
    "emp_global": 750,
    "bud_by_ind": {"Healthcare": 15.0, "Finance": 12.0, "Technology": 10.0, "Retail": 3.0, "Public": 2.0, "Industrial": 5.0, "Education": 1.5},
    "bud_global": 6.0,
    "rtd_by_ind": {"Healthcare": 200, "Finance": 150, "Technology": 120, "Retail": 72, "Public": 96, "Industrial": 100, "Education": 80},
    "rtd_global": 120,
    "severity_qs": [1, 3, 7, 14],
}

# Training data references to keep feature engineering deterministic at inference
TRAIN_REF_PATH = DATA_DIR / "model_ready" / "combined_clean.csv"
TRAIN_REF_SYN = DATA_DIR / "model_ready" / "synthetic_samples_ctgan_v2.csv"

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
    # last resort: newest CatBoost artefact
    cands = sorted(MODELS_DIR.glob("*CatBoost*.pkl"))
    if cands:
        return cands[-1]
    raise FileNotFoundError("CatBoost model not found under data/models")


def _load_meta(model_path: Path) -> dict:
    """Load meta, preferring the file aligned to the chosen model."""
    aligned = model_path.with_name(f"{model_path.stem}_meta.pkl")
    if aligned.exists():
        return joblib.load(aligned)
    legacy = MODELS_DIR / META_FALLBACK
    if legacy.exists():
        return joblib.load(legacy)
    return {"feature_cols": FEATURE_COLS_ORDER, "cat_cols": [
        "Industry", "Country", "Attack_Type", "Data_Type",
    ]}

def _load_or_compute_baselines() -> dict:
    """Load or compute baseline/proxy data for optional field filling."""
    processed_path = DATA_DIR / "processed" / "combined_enriched_core.csv"
    if not processed_path.exists():
        return DEFAULT_BASELINES
    try:
        df = pd.read_csv(processed_path)
        baselines = {}
        baselines["emp_by_ind"] = df.groupby("Industry", dropna=False)["Employee_Count"].median().to_dict()
        baselines["emp_global"] = pd.to_numeric(df["Employee_Count"], errors="coerce").median()
        baselines["bud_by_ind"] = df.groupby("Industry", dropna=False)["Security_Budget_Million_USD"].median().to_dict()
        baselines["bud_global"] = pd.to_numeric(df["Security_Budget_Million_USD"], errors="coerce").median()
        baselines["rtd_by_ind"] = df.groupby("Industry", dropna=False)["Recovery_Time_Days"].median().to_dict()
        baselines["rtd_global"] = pd.to_numeric(df["Recovery_Time_Days"], errors="coerce").median()
        rtd = pd.to_numeric(df["Recovery_Time_Days"], errors="coerce")
        qs = rtd.quantile([0.2, 0.4, 0.6, 0.8]).values.tolist() if rtd.notna().sum() >= 5 else DEFAULT_BASELINES["severity_qs"]
        baselines["severity_qs"] = qs
        return baselines
    except Exception as e:
        print(f"WARNING: Could not load baselines from {processed_path}: {e}. Using hardcoded defaults.")
        return DEFAULT_BASELINES

def _fill_optional_fields(df: pd.DataFrame, baselines: dict) -> pd.DataFrame:
    """Fill optional fields using industry baselines and IBM/DBIR-style anchors."""
    df = df.copy()
    eps = 1e-9
    
    # Fill Employee_Count (high friction field)
    if "Employee_Count" in df.columns:
        mask = df["Employee_Count"].isna() | (df["Employee_Count"] == 0)
        if mask.any() and "Industry" in df.columns:
            emp_by_ind = baselines.get("emp_by_ind", {})
            df.loc[mask, "Employee_Count"] = df.loc[mask, "Industry"].map(
                lambda x: emp_by_ind.get(str(x), baselines.get("emp_global", 750))
            )
        df.loc[df["Employee_Count"].isna() | (df["Employee_Count"] == 0), "Employee_Count"] = baselines.get("emp_global", 750)
    
    # Fill Security_Budget_Million_USD (high friction field)
    if "Security_Budget_Million_USD" in df.columns:
        mask = df["Security_Budget_Million_USD"].isna() | (df["Security_Budget_Million_USD"] <= 0)
        if mask.any() and "Industry" in df.columns:
            bud_by_ind = baselines.get("bud_by_ind", {})
            df.loc[mask, "Security_Budget_Million_USD"] = df.loc[mask, "Industry"].map(
                lambda x: bud_by_ind.get(str(x), baselines.get("bud_global", 6.0))
            )
        df.loc[df["Security_Budget_Million_USD"].isna() | (df["Security_Budget_Million_USD"] <= 0), "Security_Budget_Million_USD"] = baselines.get("bud_global", 6.0)
    
    # Fill Recovery_Time_Days (high friction field)
    if "Recovery_Time_Days" in df.columns:
        mask = df["Recovery_Time_Days"].isna() | (df["Recovery_Time_Days"] <= 0)
        if mask.any() and "Industry" in df.columns:
            rtd_by_ind = baselines.get("rtd_by_ind", {})
            df.loc[mask, "Recovery_Time_Days"] = df.loc[mask, "Industry"].map(
                lambda x: rtd_by_ind.get(str(x), baselines.get("rtd_global", 120))
            )
        df.loc[df["Recovery_Time_Days"].isna() | (df["Recovery_Time_Days"] <= 0), "Recovery_Time_Days"] = baselines.get("rtd_global", 120)
    
    # Derive Incident_Severity from Recovery_Time_Days if not provided
    if "Incident_Severity" in df.columns or "Recovery_Time_Days" in df.columns:
        mask = df.get("Incident_Severity", pd.Series(index=df.index, dtype=object)).isna()
        if mask.any() and "Recovery_Time_Days" in df.columns:
            qs = baselines.get("severity_qs", [1, 3, 7, 14])
            q1, q2, q3, q4 = qs
            def _severity(x):
                x = pd.to_numeric(x, errors="coerce")
                if pd.isna(x):
                    return 3  # default to medium
                if x <= q1:
                    return 1
                if x <= q2:
                    return 2
                if x <= q3:
                    return 3
                if x <= q4:
                    return 4
                return 5
            if "Incident_Severity" not in df.columns:
                df["Incident_Severity"] = df["Recovery_Time_Days"].apply(_severity).astype("int64")
            else:
                df.loc[mask, "Incident_Severity"] = df.loc[mask, "Recovery_Time_Days"].apply(_severity).astype("int64")
    
    # Baseline_Industry_Cost_Million_USD: Load from IBM reference or use global median
    # This is harder to compute at inference time, so we provide a fallback
    if "Baseline_Industry_Cost_Million_USD" in df.columns:
        mask = df["Baseline_Industry_Cost_Million_USD"].isna() | (df["Baseline_Industry_Cost_Million_USD"] <= 0)
        if mask.any():
            # Try to load IBM baseline
            ibm_ind_path = DATA_DIR / "reference" / "IBM_2025_Industry_Breach_Cost_Baselines.csv"
            if ibm_ind_path.exists():
                try:
                    ibm_ind = pd.read_csv(ibm_ind_path)
                    # Normalize column names
                    ibm_ind.columns = [c.strip().replace(" ", "_") for c in ibm_ind.columns]
                    if "Cost_MillionUSD" in ibm_ind.columns:
                        ibm_ind = ibm_ind.rename(columns={"Cost_MillionUSD": "Cost"})
                    if "Cost" in ibm_ind.columns:
                        # Merge on Industry and Year if available
                        if "Industry" in df.columns and "Year" in df.columns and "Year" in ibm_ind.columns:
                            merged = df.loc[mask].merge(ibm_ind[["Year", "Industry", "Cost"]], 
                                                          on=["Industry", "Year"], 
                                                          how="left")
                            if not merged.empty and "Cost" in merged.columns:
                                df.loc[mask, "Baseline_Industry_Cost_Million_USD"] = merged["Cost"].values
                        # Fallback: use industry median from IBM
                        still_missing = df["Baseline_Industry_Cost_Million_USD"].isna() | (df["Baseline_Industry_Cost_Million_USD"] <= 0)
                        if still_missing.any() and "Industry" in df.columns:
                            ibm_by_ind = ibm_ind.groupby("Industry")["Cost"].median().to_dict()
                            df.loc[still_missing, "Baseline_Industry_Cost_Million_USD"] = df.loc[still_missing, "Industry"].map(
                                lambda x: ibm_by_ind.get(str(x), ibm_ind["Cost"].median())
                            )
                except Exception as e:
                    print(f"WARNING: Could not load IBM baseline: {e}")
            # Fallback: use global default
            df.loc[df["Baseline_Industry_Cost_Million_USD"].isna() | (df["Baseline_Industry_Cost_Million_USD"] <= 0), "Baseline_Industry_Cost_Million_USD"] = 4.5
    
    return df


def _load_training_reference() -> dict:
    """Load training data (real + synthetic) to compute stable aggregates for features."""
    try:
        df_real = pd.read_csv(TRAIN_REF_PATH)
        df_syn: Optional[pd.DataFrame] = None
        if TRAIN_REF_SYN.exists():
            df_syn = pd.read_csv(TRAIN_REF_SYN)
        df = pd.concat([df_real, df_syn], ignore_index=True) if df_syn is not None else df_real
        stats = {
            "base_year": int(pd.to_numeric(df["Year"], errors="coerce").min()),
            "median_loss": pd.to_numeric(df["Financial_Impact_Million_USD"], errors="coerce").median(),
        }
        stats["industry_attack_median"] = df.groupby(["Industry", "Attack_Type"], dropna=False)["Financial_Impact_Million_USD"].median().to_dict()
        stats["industry_year_mean"] = df.groupby(["Industry", "Year"], dropna=False)["Financial_Impact_Million_USD"].mean().to_dict()
        return stats
    except Exception as e:
        print(f"WARNING: Training reference load failed: {e}. Using empty stats.")
        return {
            "base_year": 2010,
            "median_loss": 1.0,
            "industry_attack_median": {},
            "industry_year_mean": {},
        }


TRAIN_STATS = _load_training_reference()


def engineer_features(df: pd.DataFrame, stats: dict) -> pd.DataFrame:
    """Mirror notebook feature engineering using cached training aggregates."""
    X = df.copy()

    # Industry × Attack Type median loss (lookup from training stats)
    if {"Industry", "Attack_Type"}.issubset(X.columns):
        med = stats.get("industry_attack_median", {})
        global_med = stats.get("median_loss", np.nan)
        X["Industry_AttackType_median_loss"] = X.apply(
            lambda r: med.get((r.get("Industry"), r.get("Attack_Type")), global_med), axis=1
        )

    # Records per dollar of security budget
    if {"Records_Compromised", "Security_Budget_Million_USD"}.issubset(X.columns):
        X["Records_per_Budget_Million"] = X["Records_Compromised"] / (X["Security_Budget_Million_USD"].clip(lower=0.1) * 1_000_000)

    # Severity × Records (compound severity measure)
    if {"Incident_Severity", "Records_Compromised"}.issubset(X.columns):
        X["Severity_x_Scale"] = X["Incident_Severity"] * np.log1p(X["Records_Compromised"])

    # Temporal features
    if "Year" in X.columns:
        base_year = stats.get("base_year", pd.to_numeric(X["Year"], errors="coerce").min())
        X["Years_Since_Start"] = pd.to_numeric(X["Year"], errors="coerce") - base_year
        mean_map = stats.get("industry_year_mean", {})
        global_mean = stats.get("median_loss", np.nan)
        if "Industry" in X.columns:
            X["Industry_Year_Trend"] = X.apply(
                lambda r: mean_map.get((r.get("Industry"), r.get("Year")), global_mean), axis=1
            )

    # Robustness ratios
    eps = 1e-9
    if {"Security_Budget_Million_USD", "Employee_Count"}.issubset(X.columns):
        X["Budget_per_Employee_log"] = np.log1p(
            X["Security_Budget_Million_USD"] * 1_000_000 / (X["Employee_Count"].clip(lower=1) + eps)
        )

    if {"Records_Compromised", "Employee_Count"}.issubset(X.columns):
        X["Breach_Scale_per_Employee"] = X["Records_Compromised"] / (X["Employee_Count"].clip(lower=1) + eps)

    return X

def preprocess(raw: pd.DataFrame, baselines: Optional[dict] = None, stats: Optional[dict] = None) -> pd.DataFrame:
    """Mirror training: baseline fill, leakage drop, impute, ratios, engineered feats."""
    df = raw.copy()

    # Fill optional fields with baselines first (before other imputations)
    df = _fill_optional_fields(df, baselines or DEFAULT_BASELINES)

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
    if {"Security_Budget_Million_USD", "Employee_Count"}.issubset(df.columns):
        df["Budget_per_Employee"] = df["Security_Budget_Million_USD"] / (df["Employee_Count"] + eps)
    if {"Records_Compromised", "Employee_Count"}.issubset(df.columns):
        df["Records_per_Employee"] = df["Records_Compromised"] / (df["Employee_Count"] + eps)

    # winsorize heavy tails
    for c in WINSOR_COLS:
        if c in df.columns:
            df[c] = _winsorize(pd.to_numeric(df[c], errors="coerce"))

    # engineered features to match notebook
    df = engineer_features(df, stats or TRAIN_STATS)

    return df

class ImpactCatBoost:
    """Serves CatBoost model trained on log-target (log1p), with optional field filling."""
    def __init__(self):
        self.model_path = _load_model_path()
        self.model = joblib.load(self.model_path)
        meta = _load_meta(self.model_path)
        self.feature_cols = meta.get("feature_cols", FEATURE_COLS_ORDER)
        self.cat_cols = meta.get("cat_cols", ["Industry", "Country", "Attack_Type", "Data_Type"])
        self.baselines = _load_or_compute_baselines()
        self.train_stats = TRAIN_STATS

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
        Xp = preprocess(raw, baselines=self.baselines, stats=self.train_stats)
        Xp = self._align(Xp)
        pred_log = self.model.predict(Xp)              # predicts log1p(impact)
        y = np.expm1(np.clip(pred_log, -20, None))     # back to M$
        return np.maximum(y, 0.0)                      # no negatives
