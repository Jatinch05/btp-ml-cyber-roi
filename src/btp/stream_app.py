"""
frontend/app.py
Streamlit dashboard for BTP: visualizes processed/enriched dataset and provides a mock predict form.

Run:
  cd frontend
  streamlit run app.py
"""

import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from pathlib import Path

st.set_page_config(page_title="Cyber Risk & ROI Dashboard", layout="wide")

DATA_PATH = Path("../data/processed/combined_enriched_core.csv")  # relative to frontend/
API_URL = os.getenv("API_URL", "http://localhost:8000/predict")
st.title("Cyber Risk & ROI Dashboard — BTP (Prototype)")

# --- helper: load or create sample dataset ---
@st.cache_data
def load_or_make_sample(path: Path):
    if path.exists():
        df = pd.read_csv(path)
        return df
    # create a small sample dataset with realistic columns
    data = [
        {"Industry":"Finance","Attack_Type":"Phishing","Employee_Count":800,"Financial_Loss_Million_USD":7.2,"Incident_Severity":"High","Resolution_Time_Hours":120,"Vulnerability_Type":"Weak Authentication"},
        {"Industry":"Healthcare","Attack_Type":"Ransomware","Employee_Count":1500,"Financial_Loss_Million_USD":22.1,"Incident_Severity":"Critical","Resolution_Time_Hours":200,"Vulnerability_Type":"Unpatched Software"},
        {"Industry":"Retail","Attack_Type":"Web Exploit","Employee_Count":400,"Financial_Loss_Million_USD":1.8,"Incident_Severity":"Medium","Resolution_Time_Hours":48,"Vulnerability_Type":"SQL Injection"},
        {"Industry":"Technology","Attack_Type":"Insider","Employee_Count":1200,"Financial_Loss_Million_USD":3.6,"Incident_Severity":"Medium","Resolution_Time_Hours":72,"Vulnerability_Type":"Data Exfiltration"},
        {"Industry":"Finance","Attack_Type":"Phishing","Employee_Count":300,"Financial_Loss_Million_USD":2.9,"Incident_Severity":"High","Resolution_Time_Hours":96,"Vulnerability_Type":"Credential Theft"},
        {"Industry":"Public","Attack_Type":"Phishing","Employee_Count":200,"Financial_Loss_Million_USD":0.9,"Incident_Severity":"Low","Resolution_Time_Hours":36,"Vulnerability_Type":"User Awareness"},
    ]
    df = pd.DataFrame(data)
    return df

df = load_or_make_sample(DATA_PATH)

# --- Sidebar: filters and prediction input ---
st.sidebar.header("Controls & Predict")
industry_options = ["All"] + sorted(df["Industry"].unique().tolist())
attack_options = ["All"] + sorted(df["Attack_Type"].unique().tolist())
selected_industry = st.sidebar.selectbox("Industry", industry_options, index=0)
selected_attack = st.sidebar.selectbox("Attack Type", attack_options, index=0)

# Prediction form (calls backend; optional fields can be left blank)
st.sidebar.markdown("---")
st.sidebar.subheader("Predict (API)")
with st.sidebar.form("predict_form"):
    in_industry = st.selectbox("Industry (required)", industry_options[1:] if len(industry_options)>1 else ["Finance"])
    in_attack = st.selectbox("Attack Type (required)", attack_options[1:] if len(attack_options)>1 else ["Phishing"])
    in_data_type = st.text_input("Data Type (required)", value="", placeholder="e.g., pii_customer")
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

    payload = [{
        "Industry": in_industry,
        "Year": int(in_year) if str(in_year).strip() else None,
        "Attack_Type": in_attack,
        "Data_Type": in_data_type or None,
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
    except Exception:
        # Fallback to deterministic mock if API unavailable
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

# --- Data filtering ---
df_view = df.copy()
if selected_industry != "All":
    df_view = df_view[df_view["Industry"] == selected_industry]
if selected_attack != "All":
    df_view = df_view[df_view["Attack_Type"] == selected_attack]

# --- KPIs row ---
avg_loss = df_view["Financial_Loss_Million_USD"].mean()
median_loss = df_view["Financial_Loss_Million_USD"].median()
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
    industry_df = df_view.groupby("Industry", as_index=False)["Financial_Loss_Million_USD"].mean().sort_values("Financial_Loss_Million_USD", ascending=False)
    if not industry_df.empty:
        fig1 = px.bar(industry_df, x="Industry", y="Financial_Loss_Million_USD", labels={"Financial_Loss_Million_USD":"Avg Loss (M USD)"}, title="Avg Loss by Industry")
        st.plotly_chart(fig1, width='stretch')
    else:
        st.info("No data for selected filters.")

    st.subheader("Resolution Time vs Financial Loss")
    if not df_view.empty:
        fig2 = px.scatter(df_view, x="Resolution_Time_Hours", y="Financial_Loss_Million_USD",
                          hover_data=["Industry","Attack_Type","Vulnerability_Type"],
                          labels={"Resolution_Time_Hours":"Resolution Time (hrs)","Financial_Loss_Million_USD":"Loss (M USD)"})
        st.plotly_chart(fig2, width='stretch')
    else:
        st.info("No data to plot")

with right:
    st.subheader("Attack Type Distribution")
    attack_counts = df_view["Attack_Type"].value_counts().reset_index()
    attack_counts.columns = ["Attack_Type","count"]
    if not attack_counts.empty:
        fig3 = px.pie(attack_counts, names="Attack_Type", values="count", title="Attack Type Share")
        st.plotly_chart(fig3, width='stretch')
    else:
        st.info("No data to plot")

    st.subheader("Top Vulnerability Types")
    vuln_counts = (df_view["Vulnerability_Type"].value_counts().reset_index().rename(columns={"index": "Vulnerability_Type", "Vulnerability_Type": "Frequency"}))    
    if not vuln_counts.empty:
        st.table(vuln_counts.head(8))
    else:
        st.write("No vulnerabilities available for selection")

st.markdown("---")
st.caption("Notes: Dashboard reads `data/processed/combined_enriched_core.csv` or falls back to a sample dataset. Predictions call the FastAPI backend when `API_URL` is reachable.")
