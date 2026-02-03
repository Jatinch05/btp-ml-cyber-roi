import sys, json, pandas as pd
from .infer import ImpactCatBoost

def _read_stdin_df() -> pd.DataFrame:
    """
    Read JSON from stdin. Accepts:
    - Single object: {"Industry": "Finance", "Year": 2024, ...}
    - Array of objects: [{"Industry": "Finance", ...}, ...]
    - JSONL (one JSON per line)
    
    Mandatory fields: Industry, Year, Attack_Type, Data_Type, Records_Compromised
    Optional fields (auto-filled with baselines): Employee_Count, Security_Budget_Million_USD, Recovery_Time_Days, etc.
    """
    buf = sys.stdin.read().strip()
    if not buf:
        raise SystemExit("no stdin input")
    try:
        obj = json.loads(buf)
        if isinstance(obj, dict):  # single row
            return pd.DataFrame([obj])
        elif isinstance(obj, list):  # batch
            return pd.DataFrame(obj)
    except json.JSONDecodeError:
        rows = [json.loads(line) for line in buf.splitlines() if line.strip()]
        return pd.DataFrame(rows)

if __name__ == "__main__":
    df = _read_stdin_df()
    model = ImpactCatBoost()
    y = model.predict_musd(df)
    for i, v in enumerate(y):
        print(json.dumps({"row": i, "prediction_musd": float(v)}))
