
from pathlib import Path
import re
import sys
import numpy as np
import pandas as pd


LEAN_CSV = Path("data/raw/67f14f304bfae.csv")
RICH_CSV = Path("data/raw/Cybersecurity Incidents and Data Breaches 2024.csv")
IBM_INDUSTRY = Path("data/reference/IBM_2025_Industry_Breach_Cost_Baselines.csv")
IBM_PERRECORD = Path("data/reference/IBM_2025_Per-Record_Breach_Costs.csv")

OUTDIR = Path("data/processed")
OUT_CSV = OUTDIR / "combined_enriched_core.csv"
OUT_PARQUET = OUTDIR / "combined_enriched_core.parquet"


IND_MULT = {
    "Healthcare": 2.0, "Financial": 1.5, "Industrial": 1.1,
    "Technology": 1.2, "Retail": 0.9, "Hospitality": 0.9,
    "Public": 0.8, "Education": 0.8,
}

CORE_COLS = [
    "Industry","Country","Year",
    "Attack_Type","Canonical_Attack_Vector","Data_Type",
    "Records_Compromised","Employee_Count","Security_Budget_Million_USD",
    "Financial_Impact_Million_USD","Recovery_Time_Days","Incident_Severity",
    "Baseline_Industry_Cost_Million_USD","Per_Record_Cost_USD","Estimated_Financial_Impact_Million_USD",
    "Baseline_Source","PerRecord_Source","Source_Tag"
]


def _read_csv(p: Path) -> pd.DataFrame:
    if not p.exists():
        raise FileNotFoundError(f"Missing file: {p}")
    return pd.read_csv(p)

def _norm(name: str) -> str:
    if not isinstance(name, str): return name
    return re.sub(r"\s+", " ", name.strip()).replace("—", "-").replace("–", "-")

def _standardize(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [_norm(c) for c in df.columns]
    aliases = {
        "Attack Type": "Attack_Type",
        "Target Industry": "Industry",
        "Number of Affected Users": "Records_Compromised",
        "Financial Loss (in Million $)": "Financial_Impact_Million_USD",
        "Incident Resolution Time (in Hours)": "Recovery_Time_Days",
        "Data_Types_Stolen": "Data_Type",
        "Security Vulnerability Type": "Security_Vulnerability_Type",
        "Attack Vector": "Attack_Vector",
    }
    for src, dst in aliases.items():
        if src in df.columns and dst not in df.columns:
            df = df.rename(columns={src: dst})
    for col in ["Attack_Vector","Security_Vulnerability_Type","Data_Type","Recovery_Time_Days"]:
        if col not in df.columns:
            df[col] = pd.NA
    return df

def _coerce(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    float_cols = [
        "Financial_Impact_Million_USD","Security_Budget_Million_USD",
        "Recovery_Time_Days","Records_Compromised",
        "Per_Record_Cost_USD","Baseline_Industry_Cost_Million_USD",
        "Estimated_Financial_Impact_Million_USD"
    ]
    int_cols = ["Employee_Count","Year","Incident_Severity"]
    for c in float_cols:
        if c in df.columns: df[c] = pd.to_numeric(df[c], errors="coerce")
    for c in int_cols:
        if c in df.columns: df[c] = pd.to_numeric(df[c], errors="coerce").astype("Int64")
    return df

# ---------- IBM references ----------
def _load_ibm_industry(p: Path) -> pd.DataFrame:
    df = _standardize(_read_csv(p))
    if "Cost_MillionUSD" in df.columns:
        df = df.rename(columns={"Cost_MillionUSD":"IBM_Baseline_Industry_Cost_Million_USD"})
    need = {"Year","Industry","IBM_Baseline_Industry_Cost_Million_USD"}
    if not need.issubset(df.columns):
        raise ValueError(f"IBM industry ref missing columns: {need - set(df.columns)}")
    df["Year"] = pd.to_numeric(df["Year"], errors="coerce").astype("Int64")
    return df[list(need)]

def _load_ibm_perrecord(p: Path) -> pd.DataFrame:
    df = _standardize(_read_csv(p))
    if "Cost_Per_RecordUSD" in df.columns:
        df = df.rename(columns={"Cost_Per_RecordUSD":"IBM_Per_Record_Cost_USD"})
    need = {"Year","Data_Type","IBM_Per_Record_Cost_USD"}
    if not need.issubset(df.columns):
        raise ValueError(f"IBM per-record ref missing columns: {need - set(df.columns)}")
    df["Year"] = pd.to_numeric(df["Year"], errors="coerce").astype("Int64")
    return df[list(need)]

# ---------- Attack_Vector normalization ----------
def _map_vuln_to_vector(v):
    if pd.isna(v): return np.nan
    v2 = str(v).lower().strip()
    mapping = {
        "phishing": "phishing", "spear phishing": "phishing", "whaling": "phishing",
        "ransomware": "ransomware", "malware": "malware",
        "sql injection": "web exploit", "xss": "web exploit",
        "misconfiguration": "misconfiguration", "cloud": "misconfiguration",
        "unpatched": "vulnerability exploit", "exploit": "vulnerability exploit",
        "third party": "supply chain", "insider": "insider", "ddos": "ddos"
    }
    for k, val in mapping.items():
        if k in v2: return val
    return "unknown"

def _build_attack_vector(df: pd.DataFrame) -> pd.Series:
    av = df.get("Attack_Vector")
    sv = df.get("Security_Vulnerability_Type")
    if av is not None and sv is not None:
        raw = av.combine_first(sv)
    elif av is not None:
        raw = av
    elif sv is not None:
        raw = sv
    else:
        raw = pd.Series(np.nan, index=df.index)
    return raw.apply(_map_vuln_to_vector).fillna("unknown")

def _learn_proxies(rich: pd.DataFrame) -> dict:
    req = ["Industry","Employee_Count","Security_Budget_Million_USD",
           "Recovery_Time_Days","Data_Type","Records_Compromised","Financial_Impact_Million_USD"]
    missing = [c for c in req if c not in rich.columns]
    if missing:
        raise ValueError(f"RICH dataset missing columns: {missing}")

    p = {}
    p["emp_by_ind"] = rich.groupby("Industry", dropna=False)["Employee_Count"].median()
    p["emp_global"] = pd.to_numeric(rich["Employee_Count"], errors="coerce").median()

    p["bud_by_ind"] = rich.groupby("Industry", dropna=False)["Security_Budget_Million_USD"].median()
    p["bud_global"] = pd.to_numeric(rich["Security_Budget_Million_USD"], errors="coerce").median()

    with np.errstate(divide="ignore", invalid="ignore"):
        bpe = (rich["Security_Budget_Million_USD"] * 1_000_000) / pd.to_numeric(rich["Employee_Count"], errors="coerce")
    p["bpe_by_ind"] = pd.Series(bpe).groupby(rich["Industry"]).median()
    p["bpe_global"] = pd.Series(bpe).median()

    rtd = pd.to_numeric(rich["Recovery_Time_Days"], errors="coerce")
    qs = rtd.quantile([0.2,0.4,0.6,0.8]).values.tolist() if rtd.notna().sum() >= 5 else [1,3,7,14]
    p["severity_qs"] = qs

    with np.errstate(divide="ignore", invalid="ignore"):
        pr_obs = (rich["Financial_Impact_Million_USD"] * 1_000_000) / pd.to_numeric(rich["Records_Compromised"], errors="coerce")
    p["pr_obs_by_dtype"] = pd.Series(pr_obs).groupby(rich["Data_Type"]).median()
    p["pr_obs_global"] = pd.Series(pr_obs).median()

    p["fin_med_by_ind"] = rich.groupby("Industry", dropna=False)["Financial_Impact_Million_USD"].median()
    p["fin_med_global"] = pd.to_numeric(rich["Financial_Impact_Million_USD"], errors="coerce").median()
    return p


def _enrich_lean_core(lean_df, proxies, ibm_ind, ibm_pr):
    df = lean_df.copy()

    # Ensure all core columns exist
    for col in ["Industry","Country","Year","Attack_Type",
                "Attack_Vector","Security_Vulnerability_Type",
                "Data_Type","Records_Compromised","Employee_Count",
                "Security_Budget_Million_USD","Financial_Impact_Million_USD",
                "Recovery_Time_Days"]:
        if col not in df.columns:
            df[col] = pd.NA

    # unify vector + data type
    df["Canonical_Attack_Vector"] = _build_attack_vector(df)
    if "Data_Type" not in df or df["Data_Type"].isna().all():
        df["Data_Type"] = df["Canonical_Attack_Vector"].map({
            "phishing": "credentials", "ransomware": "mixed_operational",
            "malware": "endpoints_data", "web exploit": "pii_customer",
            "vulnerability exploit": "pii_customer", "misconfiguration": "pii_customer",
            "supply chain": "pii_customer", "insider": "pii_employee",
            "ddos": "availability_only", "unknown": "pii_customer"
        })


    idx = df["Employee_Count"].isna() & df["Industry"].notna()
    df.loc[idx, "Employee_Count"] = df.loc[idx, "Industry"].map(proxies["emp_by_ind"])
    df.loc[df["Employee_Count"].isna(), "Employee_Count"] = proxies["emp_global"]


    idx = df["Security_Budget_Million_USD"].isna() & df["Industry"].notna()
    df.loc[idx, "Security_Budget_Million_USD"] = df.loc[idx, "Industry"].map(proxies["bud_by_ind"])
    df.loc[df["Security_Budget_Million_USD"].isna(), "Security_Budget_Million_USD"] = proxies["bud_global"]

   
    q1,q2,q3,q4 = proxies["severity_qs"]
    def sev(x):
        x = pd.to_numeric(x, errors="coerce")
        if pd.isna(x): return pd.NA
        if x <= q1: return 1
        if x <= q2: return 2
        if x <= q3: return 3
        if x <= q4: return 4
        return 5
    df["Incident_Severity"] = df["Recovery_Time_Days"].apply(sev).astype("Int64")

  
    merged = df.merge(ibm_ind, on=["Industry","Year"], how="left")
    global_ibm = ibm_ind["IBM_Baseline_Industry_Cost_Million_USD"].median()
    miss = merged["IBM_Baseline_Industry_Cost_Million_USD"].isna() & merged["Industry"].notna()
    if miss.any():
        mult = merged.loc[miss, "Industry"].map(lambda s: IND_MULT.get(str(s), 1.0))
        merged.loc[miss, "IBM_Baseline_Industry_Cost_Million_USD"] = mult.values * global_ibm
        merged.loc[miss, "Baseline_Source"] = "IBM_Global×Multiplier"
    merged["Baseline_Industry_Cost_Million_USD"] = merged["IBM_Baseline_Industry_Cost_Million_USD"]


    merged = merged.merge(ibm_pr, on=["Data_Type","Year"], how="left")
    pr_miss = merged["IBM_Per_Record_Cost_USD"].isna()
    if pr_miss.any():
        merged.loc[pr_miss, "IBM_Per_Record_Cost_USD"] = merged.loc[pr_miss, "Data_Type"].map(proxies["pr_obs_by_dtype"])
    merged["Per_Record_Cost_USD"] = merged["IBM_Per_Record_Cost_USD"].fillna(proxies["pr_obs_global"])

  
    def est_fin(r):
        if pd.notna(r["Financial_Impact_Million_USD"]):
            return r["Financial_Impact_Million_USD"]
        rc, pr = r["Records_Compromised"], r["Per_Record_Cost_USD"]
        if pd.notna(rc) and rc > 0 and pd.notna(pr):
            return (pr * rc) / 1_000_000.0
        return r["Baseline_Industry_Cost_Million_USD"]
    merged["Estimated_Financial_Impact_Million_USD"] = merged.apply(est_fin, axis=1)

    merged["Source_Tag"] = "LEAN"
    merged = merged.drop(columns=[c for c in merged.columns if c.startswith("IBM_")], errors="ignore")
    for c in CORE_COLS:
        if c not in merged.columns:
            merged[c] = pd.NA
    return merged[CORE_COLS]



def run() -> None:
    lean_raw = _standardize(_read_csv(LEAN_CSV))
    rich_raw = _standardize(_read_csv(RICH_CSV))

    lean = _coerce(lean_raw)
    rich = _coerce(rich_raw)

    proxies = _learn_proxies(rich)
    ibm_ind = _load_ibm_industry(IBM_INDUSTRY)
    ibm_pr  = _load_ibm_perrecord(IBM_PERRECORD)

    lean_enriched = _enrich_lean_core(lean, proxies, ibm_ind, ibm_pr)

   
    rich["Canonical_Attack_Vector"] = _build_attack_vector(rich)
    rich["Source_Tag"] = "RICH"
    for c in CORE_COLS:
        if c not in rich.columns: rich[c] = pd.NA
    rich = rich[CORE_COLS]

    combined = pd.concat([rich, lean_enriched], ignore_index=True, sort=False)
    combined = _coerce(combined)

    OUTDIR.mkdir(parents=True, exist_ok=True)
    combined.to_csv(OUT_CSV, index=False)
    try:
        combined.to_parquet(OUT_PARQUET, index=False, engine="pyarrow")
    except Exception:
        try:
            combined.to_parquet(OUT_PARQUET, index=False, engine="fastparquet")
        except Exception as e:
            sys.stderr.write(f"WARNING: Failed to write parquet: {e}\n")

    print("INFO: Combined dataset saved:", OUT_CSV)
    print("INFO: Final shape:", combined.shape)
    print("INFO: Columns:", list(combined.columns))

if __name__ == "__main__":
    run()
