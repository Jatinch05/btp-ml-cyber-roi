import pandas as pd
from scanner_core import parse_and_enrich, run_nmap
from mapping import service_to_attack, normalize_vuln
import os
import difflib

BASE_DIR = os.path.dirname(__file__)
RAW_XML = os.path.join(BASE_DIR, "data/raw/scan.xml")
MAPPED = os.path.join(BASE_DIR, "data/processed/scanner_mapped.csv")
MERGED = os.path.join(BASE_DIR, "data/processed/scanner_mapped_with_controls.csv")
REMEDIATION = os.path.join(BASE_DIR, "data/raw/remediation_tools.csv")

def full_scan(target: str):
    """Server-side scan (kept for backward compatibility)"""
    xml_path = run_nmap(target, local=False)
    results = parse_and_enrich(xml_path)
    df = pd.DataFrame(results)
    return attach_remediation(df)

def attach_remediation(df: pd.DataFrame) -> pd.DataFrame:
    """Your original enrichment logic (unchanged)"""
    rem = pd.read_csv(REMEDIATION)
    df["key"] = df["Security_Vulnerability_Type"].astype(str).str.lower().str.strip().replace({"0":"", "none":""}).fillna("")
    rem["key"] = rem["Vulnerability_Type"].astype(str).str.lower().str.strip().replace({"0":"", "none":""}).fillna("")
    
    merged = df.merge(rem, on="key", how="left", suffixes=("", "_rem"))
    
    missing_idx = merged[merged["Recommended_Control"].isna()].index
    for i in missing_idx:
        sv = str(merged.at[i, "Security_Vulnerability_Type"]).lower().strip()
        if not sv: continue
        for j, r in rem.iterrows():
            rv = str(r["Vulnerability_Type"]).lower()
            if rv and (rv in sv or sv in rv):
                for col in ["Recommended_Control", "Mitigation_Tool", "Control_Cost_USD", "Effectiveness_percent", "ROI_Tag"]:
                    merged.at[i, col] = r.get(col)
                break

    rem_keys = rem["key"].unique().tolist()
    missing_idx = merged[merged["Recommended_Control"].isna()].index
    for i in missing_idx:
        sv = str(merged.at[i, "Security_Vulnerability_Type"]).lower().strip()
        if not sv: continue
        matches = difflib.get_close_matches(sv, rem_keys, n=1, cutoff=0.6)
        if matches:
            r = rem[rem["key"] == matches[0]].iloc[0]
            for col in ["Recommended_Control", "Mitigation_Tool", "Control_Cost_USD", "Effectiveness_percent", "ROI_Tag"]:
                merged.at[i, col] = r.get(col)

    defaults = {"Recommended_Control": "General Hardening", "Mitigation_Tool": "Manual Review", "Control_Cost_USD": 1000, "Effectiveness_percent": 60, "ROI_Tag": "Medium"}
    merged = merged.fillna(defaults)
    merged["Control_Cost_USD"] = merged["Control_Cost_USD"].astype(int)
    merged["Effectiveness_percent"] = merged["Effectiveness_percent"].astype(int)

    text_cols = ["Service", "Product", "Version", "Security_Vulnerability_Type", "Recommended_Control", "Mitigation_Tool"]
    for c in text_cols:
        if c in merged.columns:
            merged[c] = merged[c].astype(str).str.strip().replace({"": "Unknown", "nan": "Unknown", "None": "Unknown"})

    merged.to_csv(MERGED, index=False)
    return merged