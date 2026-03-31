"""
Streamlit dashboard for BTP.

Analytics source is the same combined dataset pattern used in model_optimization.ipynb:
- data/model_ready/combined_clean.csv
- data/model_ready/synthetic_samples_ctgan_v2.csv (if present)
"""

import os
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from pathlib import Path

st.set_page_config(page_title="Cyber Risk & ROI Dashboard", layout="wide")

ROOT = Path(__file__).resolve().parents[2]
REAL_DATA_PATH = ROOT / "data" / "model_ready" / "combined_clean.csv"
SYN_DATA_PATH = ROOT / "data" / "model_ready" / "synthetic_samples_ctgan_v2.csv"
COMBINED_EXPORT_PATH = ROOT / "data" / "processed" / "combined_generated_frontend.csv"
API_URL = os.getenv("API_URL", "http://localhost:8000/predict")
st.title("Cyber Risk & ROI Dashboard — BTP (Prototype)")

# --- helper: load notebook-aligned analytics dataset ---
@st.cache_data
def load_combined_generated(real_path: Path, syn_path: Path, export_path: Path) -> pd.DataFrame:
    if not real_path.exists():
        raise FileNotFoundError(f"Required dataset not found: {real_path}")

    df_real = pd.read_csv(real_path)
    df_real["Source_Tag"] = "real"

    if syn_path.exists():
        df_syn = pd.read_csv(syn_path)
        df_syn["Source_Tag"] = "synthetic"
        df_all = pd.concat([df_real, df_syn], ignore_index=True)
    else:
        df_all = df_real.copy()

    export_path.parent.mkdir(parents=True, exist_ok=True)
    df_all.to_csv(export_path, index=False)
    return df_all

try:
    df = load_combined_generated(REAL_DATA_PATH, SYN_DATA_PATH, COMBINED_EXPORT_PATH)
except Exception as e:
    st.error(f"Failed to load generated analytics dataset: {e}")
    st.stop()

# Resolve actual schema names used by generated datasets
loss_col = "Financial_Impact_Million_USD" if "Financial_Impact_Million_USD" in df.columns else "Financial_Loss_Million_USD"
time_col = "Recovery_Time_Days" if "Recovery_Time_Days" in df.columns else "Resolution_Time_Hours"
vuln_col = next((c for c in ["Canonical_Attack_Vector", "Attack_Vector", "Security_Vulnerability_Type", "Vulnerability_Type"] if c in df.columns), None)


ACRONYM_MAP = {
    "api": "API",
    "ddos": "DDoS",
    "iot": "IoT",
    "ot": "OT",
    "pii": "PII",
    "phi": "PHI",
    "ip": "IP",
    "gps": "GPS",
    "scada": "SCADA",
    "pos": "POS",
}


def _normalize_token(text: str) -> str:
    t = text.strip().replace("_", " ").replace("-", " ")
    parts = [p for p in t.split() if p]
    normalized = []
    for p in parts:
        key = p.lower()
        normalized.append(ACRONYM_MAP.get(key, p.capitalize()))
    return " ".join(normalized)


def _normalize_label(value: object) -> str:
    s = str(value).strip()
    if s in {"", "Select Data Type", "All"}:
        return s
    if "," in s:
        parts = [_normalize_token(p) for p in s.split(",") if p.strip()]
        return " + ".join(parts)
    return _normalize_token(s)


def _build_display_maps(values: list[str]) -> tuple[list[str], dict[str, str]]:
    display_to_raw: dict[str, str] = {}
    for raw in values:
        disp = _normalize_label(raw)
        if disp not in display_to_raw:
            display_to_raw[disp] = raw
    display_values = sorted(display_to_raw.keys())
    return display_values, display_to_raw

# --- Sidebar: filters and prediction input ---
st.sidebar.header("Controls & Predict")
industry_options = ["All"] + sorted(df["Industry"].unique().tolist())
attack_raw_values = sorted(df["Attack_Type"].dropna().astype(str).str.strip().unique().tolist())
attack_display_values, attack_display_to_raw = _build_display_maps(attack_raw_values)
attack_options = ["All"] + attack_display_values
if "Data_Type" in df.columns:
    data_type_values = sorted(
        {
            str(v).strip()
            for v in df["Data_Type"].dropna().tolist()
            if str(v).strip()
        }
    )
else:
    data_type_values = []

if not data_type_values:
    data_type_values = [
        "PII",
        "Financial",
        "Credentials",
        "PHI",
        "Intellectual Property",
    ]

data_type_display_values, data_type_display_to_raw = _build_display_maps(data_type_values)
data_type_options = ["Select Data Type"] + data_type_display_values
selected_industry = st.sidebar.selectbox("Industry", industry_options, index=0)
selected_attack = st.sidebar.selectbox("Attack Type", attack_options, index=0)

# Prediction form (calls backend; optional fields can be left blank)
st.sidebar.markdown("---")
st.sidebar.subheader("Predict (API)")
with st.sidebar.form("predict_form"):
    in_industry = st.selectbox("Industry (required)", industry_options[1:] if len(industry_options)>1 else ["Finance"])
    in_attack = st.selectbox("Attack Type (required)", attack_options[1:] if len(attack_options)>1 else ["Phishing"])
    in_data_type = st.selectbox("Data Type (required)", data_type_options, index=0)
    in_emp = st.number_input("Employee count (optional)", min_value=0, value=0, step=1)
    in_records = st.number_input("Records Compromised (required)", min_value=1, value=1)
    in_severity = st.selectbox("Incident Severity (optional)", ["Auto (fill baseline)", "Low","Medium","High","Critical"], index=0)
    in_budget = st.text_input("Security Budget (M$) (optional)", value="", placeholder="leave blank to auto-fill")
    in_year = st.text_input("Year (required)", value="", placeholder="e.g., 2025")
    in_country = st.text_input("Country (optional)", value="", placeholder="leave blank to auto-fill")
    in_recovery = st.text_input("Recovery Time (days) (optional)", value="", placeholder="leave blank to auto-fill")
    submitted = st.form_submit_button("Predict")
if submitted:
    severity_map = {
        "Auto (fill baseline)": None,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4,
    }
    def _to_float(val):
        try:
            return float(val)
        except Exception:
            return None

    missing = []
    year_txt = str(in_year).strip()
    data_type_txt = str(in_data_type).strip()

    if not year_txt:
        missing.append("Year")
    if not data_type_txt or data_type_txt == "Select Data Type":
        missing.append("Data Type")

    if missing:
        st.sidebar.error(f"Missing required fields: {', '.join(missing)}")
    else:
        try:
            year_val = int(year_txt)
        except ValueError:
            st.sidebar.error("Year must be a valid integer (e.g., 2025)")
            year_val = None

        if year_val is not None:
            payload = [{
                "Industry": in_industry,
                "Year": year_val,
                # Send readable labels; backend canonicalizes to model categories.
                "Attack_Type": in_attack,
                "Data_Type": data_type_txt,
                "Records_Compromised": float(in_records),
                "Employee_Count": float(in_emp) if in_emp else None,
                "Security_Budget_Million_USD": _to_float(in_budget) if in_budget.strip() else None,
                "Incident_Severity": severity_map.get(in_severity),
                "Recovery_Time_Days": _to_float(in_recovery) if in_recovery.strip() else None,
                "Country": in_country.strip() or None,
                "Baseline_Industry_Cost_Million_USD": None,
                "Canonical_Attack_Vector": None,
            }]

            try:
                resp = requests.post(API_URL, json=payload, timeout=10)
                resp.raise_for_status()
                preds = resp.json()
                if preds:
                    st.sidebar.success(f"Predicted Loss: ${preds[0]['prediction_musd']:.2f}M")
                    if preds[0].get("fields_filled"):
                        st.sidebar.caption(f"Filled from baselines: {', '.join(preds[0]['fields_filled'])}")
            except requests.exceptions.ConnectionError:
                # Fallback to deterministic mock if API is truly unreachable
                base = 4.44
                industry_multiplier = {
                    "Healthcare": 2.0,
                    "Finance": 1.5,
                    "Technology":1.2,
                    "Retail":0.9,
                    "Public":0.8
                }.get(in_industry, 1.0)
                sev_key = in_severity if in_severity != "Auto (fill baseline)" else "Medium"
                severity_multiplier = {"Low":0.5,"Medium":1.0,"High":1.8,"Critical":3.0}.get(sev_key,1.0)
                emp_factor = (float(in_emp or 0) / 1000 + 1e-6) ** 0.5
                predicted = round(base * industry_multiplier * severity_multiplier * emp_factor, 2)
                st.sidebar.warning("API unavailable; showing mock estimate")
                st.sidebar.success(f"Predicted Loss: ${predicted}M")
            except requests.exceptions.HTTPError:
                msg = ""
                try:
                    msg = resp.text
                except Exception:
                    msg = "No response body"
                st.sidebar.error(f"API request failed ({resp.status_code}): {msg}")
            except Exception as e:
                st.sidebar.error(f"Unexpected prediction error: {e}")

# --- Data filtering ---
df_view = df.copy()
if selected_industry != "All":
    df_view = df_view[df_view["Industry"] == selected_industry]
if selected_attack != "All":
    selected_attack_raw = attack_display_to_raw.get(selected_attack, selected_attack)
    df_view = df_view[df_view["Attack_Type"] == selected_attack_raw]

# --- KPIs row ---
avg_loss = df_view[loss_col].mean()
median_loss = df_view[loss_col].median()
total_incidents = len(df_view)
col1, col2, col3 = st.columns(3)
col1.metric("Avg Loss (M USD)", f"${avg_loss:.2f}" if not pd.isna(avg_loss) else "n/a")
col2.metric("Median Loss (M USD)", f"${median_loss:.2f}" if not pd.isna(median_loss) else "n/a")
col3.metric("Incidents (count)", f"{total_incidents}")

st.markdown("---")

# --- Main visuals ---
left, right = st.columns([2,1])

with left:
    st.subheader("Industry — Average Breach Cost")
    industry_df = df_view.groupby("Industry", as_index=False)[loss_col].mean().sort_values(loss_col, ascending=False)
    if not industry_df.empty:
        fig1 = px.bar(industry_df, x="Industry", y=loss_col, labels={loss_col:"Avg Loss (M USD)"}, title="Avg Loss by Industry")
        st.plotly_chart(fig1, width='stretch')
    else:
        st.info("No data for selected filters.")

    st.subheader("Recovery Time vs Financial Impact")
    if not df_view.empty and time_col in df_view.columns:
        hover_cols = [c for c in ["Industry", "Attack_Type", "Data_Type", vuln_col] if c and c in df_view.columns]
        fig2 = px.scatter(df_view, x=time_col, y=loss_col,
                          hover_data=hover_cols,
                          labels={time_col:"Recovery Time (days)", loss_col:"Impact (M USD)"})
        st.plotly_chart(fig2, width='stretch')
    else:
        st.info("No recovery-time data to plot")

with right:
    st.subheader("Attack Type Distribution")
    attack_counts = (
        df_view["Attack_Type"]
        .astype(str)
        .value_counts(dropna=False)
        .rename_axis("Attack_Type")
        .reset_index(name="count")
    )
    if not attack_counts.empty:
        # Improve readability: keep top categories and group long tail into "Other".
        top_n = 8
        if len(attack_counts) > top_n:
            top_attack = attack_counts.head(top_n).copy()
            other_count = int(attack_counts["count"].iloc[top_n:].sum())
            attack_plot = pd.concat(
                [
                    top_attack,
                    pd.DataFrame([{"Attack_Type": "Other", "count": other_count}]),
                ],
                ignore_index=True,
            )
        else:
            attack_plot = attack_counts

        attack_plot = attack_plot.copy()
        attack_plot["Attack_Type_Display"] = attack_plot["Attack_Type"].map(_normalize_label)
        fig3 = px.pie(attack_plot, names="Attack_Type_Display", values="count", title="Attack Type Share")
        fig3.update_traces(textposition="inside", textinfo="percent")
        fig3.update_layout(legend_title_text="Attack Type")
        st.plotly_chart(fig3, width='stretch')
    else:
        st.info("No data to plot")

    table_col = vuln_col if vuln_col else "Data_Type"
    st.subheader(f"Top {table_col.replace('_', ' ')}")
    vuln_counts = (
        df_view[table_col]
        .astype(str)
        .value_counts(dropna=False)
        .rename_axis(table_col)
        .reset_index(name="count")
    )
    if not vuln_counts.empty:
        top_vals = vuln_counts.head(8).copy()
        top_vals[table_col] = top_vals[table_col].map(_normalize_label)
        st.table(top_vals)
    else:
        st.write("No values available for selection")

st.markdown("---")
st.caption(
    f"Analytics dataset: {REAL_DATA_PATH} + {SYN_DATA_PATH.name if SYN_DATA_PATH.exists() else 'no synthetic file found'}; "
    f"combined snapshot saved to {COMBINED_EXPORT_PATH}. Predictions call FastAPI at API_URL."
)
