"""
Modern Streamlit frontend for Prediction -> Controls -> ROSI flow.

Run:
  cd d:/btp-ml-cyber-roi/src/btp
  streamlit run stream_app_v2.py
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

st.set_page_config(page_title="Cyber Risk Decision Studio", layout="wide")

ROOT = Path(__file__).resolve().parents[2]
REAL_DATA_PATH = ROOT / "data" / "model_ready" / "combined_clean.csv"
SYN_DATA_PATH = ROOT / "data" / "model_ready" / "synthetic_samples_ctgan_v2.csv"

PREDICT_RECOMMEND_API_URL = os.getenv("PREDICT_RECOMMEND_API_URL", "http://localhost:8000/predict-and-recommend")
HEALTH_API_URL = os.getenv("HEALTH_API_URL", "http://localhost:8000/healthz")

ATTACK_TYPE_EXCLUDED = {
    "Claims_Fraud",
    "Connected_Car",
    "Content_Piracy",
    "Gaming_Hack",
    "Passenger_Data",
    "Payment_Fraud",
    "Precision_Ag",
    "Property_Fraud",
    "Research_Theft",
    "Wallet_Hack",
}

DATA_TYPE_EXCLUDED = {
    "Call_Records,PII",
    "Citizen_Data,Sensor_Data",
    "Content,Subscriber_Data",
    "Cryptocurrency",
    "Farm_Data,GPS_Coordinates",
    "Financial,Property_Data",
    "Financial,Transaction_Data",
    "Gaming_Data,PII",
    "Legal_Documents,PII",
    "Location_Data,PII",
    "PHI,Device_Data",
    "PII,Academic_Records",
    "PII,Business_Data",
    "PII,Claims_Data",
    "PII,Messages",
    "PII,Travel_Data",
    "Research_Data,IP",
    "SCADA_Data,Grid_Info",
    "Trade_Secrets,Designs",
    "Vehicle_Data,Location",
}

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
    "sql": "SQL",
}


def _inject_css() -> None:
    st.markdown(
        """
        <style>
        .main {background: radial-gradient(circle at 20% 20%, #10203d 0%, #0b1220 45%, #050811 100%);} 
        .block-container {padding-top: 1.4rem; padding-bottom: 2rem;}
        h1, h2, h3, h4, p, label {color: #e6edf3 !important;}
        div[data-testid="stMetric"] {
            background: linear-gradient(140deg, rgba(17, 30, 57, 0.9), rgba(17, 24, 39, 0.8));
            border: 1px solid rgba(99, 179, 237, 0.25);
            border-radius: 14px;
            padding: 12px 14px;
        }
        .glass-card {
            background: linear-gradient(150deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.6));
            border: 1px solid rgba(148, 163, 184, 0.25);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 12px;
        }
        .flow-chip {
            display: inline-block;
            padding: 6px 10px;
            border: 1px solid rgba(125, 211, 252, 0.35);
            border-radius: 999px;
            margin-right: 8px;
            margin-bottom: 8px;
            color: #bae6fd;
            font-size: 12px;
            letter-spacing: 0.2px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _normalize_token(text: str) -> str:
    t = text.strip().replace("_", " ").replace("-", " ")
    out: list[str] = []
    for part in [p for p in t.split() if p]:
        out.append(ACRONYM_MAP.get(part.lower(), part.capitalize()))
    return " ".join(out)


def _pretty(value: str) -> str:
    if "," in value:
        return ", ".join(_normalize_token(v) for v in value.split(",") if v.strip())
    return _normalize_token(value)


@st.cache_data
def _load_data(real_path: Path, syn_path: Path) -> pd.DataFrame:
    if not real_path.exists():
        raise FileNotFoundError(f"Missing required file: {real_path}")
    df_real = pd.read_csv(real_path)
    if syn_path.exists():
        df_syn = pd.read_csv(syn_path)
        return pd.concat([df_real, df_syn], ignore_index=True)
    return df_real


@st.cache_data
def _build_option_maps(df: pd.DataFrame) -> tuple[dict[str, str], dict[str, str], list[str], list[str], list[str]]:
    industries = sorted(df["Industry"].dropna().astype(str).str.strip().unique().tolist())

    attack_raw = sorted(df["Attack_Type"].dropna().astype(str).str.strip().unique().tolist())
    attack_raw = [v for v in attack_raw if v not in ATTACK_TYPE_EXCLUDED] or attack_raw
    attack_display_to_raw: dict[str, str] = {}
    for raw in attack_raw:
        disp = _pretty(raw)
        if disp not in attack_display_to_raw:
            attack_display_to_raw[disp] = raw

    data_raw = sorted(df["Data_Type"].dropna().astype(str).str.strip().unique().tolist())
    data_raw = [v for v in data_raw if v not in DATA_TYPE_EXCLUDED] or data_raw
    data_display_to_raw: dict[str, str] = {}
    for raw in data_raw:
        disp = _pretty(raw)
        if disp not in data_display_to_raw:
            data_display_to_raw[disp] = raw

    attack_display = sorted(attack_display_to_raw.keys())
    data_display = sorted(data_display_to_raw.keys())
    return attack_display_to_raw, data_display_to_raw, industries, attack_display, data_display


def _company_size(employee_count: float) -> str:
    if employee_count <= 0:
        return "medium"
    if employee_count < 200:
        return "small"
    if employee_count > 1500:
        return "large"
    return "medium"


def _call_predict_and_recommend(payload: list[dict[str, Any]], endpoint: str) -> dict[str, Any]:
    resp = requests.post(endpoint, json=payload, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    if not isinstance(data, list) or not data:
        raise ValueError("Unexpected API response format")
    first = data[0]
    if not isinstance(first, dict):
        raise ValueError("Unexpected API response item format")
    return first


def _render_formula_and_definitions() -> None:
    st.subheader("How the Business Case Is Calculated")

    with st.expander("Key Terms", expanded=False):
        st.markdown(
            """
            - Expected Business Loss: Estimated incident cost before any new safeguards, in USD.
            - Annual Safeguard Cost: Total yearly implementation and operating cost for the selected safeguards, in USD.
            - Control Impact ($E_i$): Reduction contributed by one safeguard after contextual adjustments.
            - Portfolio Impact: Total reduction when multiple safeguards are combined.
            - Residual Business Loss: Expected loss remaining after the safeguard bundle is applied, in USD.
            - Expected Return: Net benefit divided by annual safeguard cost.
            """
        )

    with st.expander("Formulas Used", expanded=False):
        st.markdown("Safeguard impact per control:")
        st.latex(r"E_i = \text{Effectiveness} \times \text{Coverage} \times \text{ImplementationQuality}")
        st.markdown("How the safeguard bundle works together (multiplicative, not additive):")
        st.latex(r"\text{PortfolioImpact} = 1 - \prod_i(1 - E_i)")
        st.markdown("Residual business loss after safeguards:")
        st.latex(r"\text{ResidualLoss} = \text{ExpectedLoss} \times (1 - \text{PortfolioImpact})")
        st.markdown("Annual cost standardization:")
        st.latex(r"\text{AnnualCost} = \text{MonthlyCost} \times 12")
        st.markdown("Expected return from safeguards:")
        st.latex(r"\text{ROSI} = \frac{\text{ExpectedLoss} - \text{ResidualLoss} - \text{AnnualCost}}{\text{AnnualCost}}")
        st.caption("A value of 1.0 means the net benefit equals the annual safeguard cost. A value of 10 means about $10 of net benefit for every $1 spent.")


def _render_data_metrics(df: pd.DataFrame) -> None:
    st.header("Data Metrics")
    st.caption("Dataset profile, distribution diagnostics, and segment-level behavior from model-ready data.")

    loss_col = "Financial_Impact_Million_USD" if "Financial_Impact_Million_USD" in df.columns else "Financial_Loss_Million_USD"
    time_col = "Recovery_Time_Days" if "Recovery_Time_Days" in df.columns else "Resolution_Time_Hours"
    impact_unit = "USD M"

    r1c1, r1c2, r1c3 = st.columns(3)
    r1c1.metric("Records", f"{len(df):,}")
    r1c2.metric("Business Segments", f"{df['Industry'].nunique() if 'Industry' in df.columns else 0}")
    r1c3.metric("Avg Impact (USD M)", f"${pd.to_numeric(df[loss_col], errors='coerce').mean():.2f}M")

    r2c1, r2c2, r2c3 = st.columns(3)
    r2c1.metric("Median Impact (USD M)", f"${pd.to_numeric(df[loss_col], errors='coerce').median():.2f}M")
    r2c2.metric("Threat Scenarios", f"{df['Attack_Type'].astype(str).str.strip().nunique() if 'Attack_Type' in df.columns else 0}")
    r2c3.metric("Sensitive Data Categories", f"{df['Data_Type'].astype(str).str.strip().nunique() if 'Data_Type' in df.columns else 0}")

    st.markdown("---")

    left, right = st.columns([1.25, 1])
    with left:
        if "Industry" in df.columns:
            industry_df = (
                df.groupby("Industry")[loss_col]
                .mean()
                .reset_index(name="avg_impact")
                .sort_values("avg_impact", ascending=False)
            )
            fig_ind = px.bar(
                industry_df,
                x="Industry",
                y="avg_impact",
                color="avg_impact",
                title="Average Business Impact by Segment",
                color_continuous_scale="Turbo",
                labels={"avg_impact": f"Average Impact ({impact_unit})"},
            )
            fig_ind.update_layout(margin=dict(l=20, r=20, t=45, b=20), height=350)
            st.plotly_chart(fig_ind, use_container_width=True)
            st.caption("This chart shows average business impact by segment. Higher bars mean that segment tends to be more costly in the dataset.")

        if time_col in df.columns:
            fig_sc = px.scatter(
                df,
                x=time_col,
                y=loss_col,
                color="Incident_Severity" if "Incident_Severity" in df.columns else None,
                hover_data=[c for c in ["Industry", "Attack_Type", "Data_Type"] if c in df.columns],
                title="Recovery Time vs Business Impact",
                color_continuous_scale="Viridis",
                labels={time_col: "Recovery Time (days)", loss_col: f"Business Impact ({impact_unit})"},
            )
            fig_sc.update_layout(margin=dict(l=20, r=20, t=45, b=20), height=350)
            st.plotly_chart(fig_sc, use_container_width=True)
            st.caption("Each point is one incident. The x-axis is recovery time in days; the y-axis is business impact in USD millions.")

    with right:
        if "Attack_Type" in df.columns:
            atk_counts = (
                df["Attack_Type"].astype(str).str.strip().value_counts().head(10)
                .rename_axis("Threat Scenario").reset_index(name="count")
            )
            fig_pie = px.pie(
                atk_counts,
                names="Threat Scenario",
                values="count",
                title="Top Threat Scenario Share",
                color_discrete_sequence=px.colors.qualitative.Bold,
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label")
            fig_pie.update_layout(margin=dict(l=20, r=20, t=45, b=20), height=350)
            st.plotly_chart(fig_pie, use_container_width=True)
            st.caption("The pie chart shows how the most common threat scenarios are distributed across the dataset.")

        loss_vals = pd.to_numeric(df[loss_col], errors="coerce").dropna()
        if not loss_vals.empty:
            fig_hist = px.histogram(
                x=loss_vals,
                nbins=40,
                title="Business Impact Distribution",
                labels={"x": f"Business Impact ({impact_unit})", "y": "Frequency"},
                color_discrete_sequence=["#38bdf8"],
            )
            fig_hist.update_layout(margin=dict(l=20, r=20, t=45, b=20), height=350)
            st.plotly_chart(fig_hist, use_container_width=True)
            st.caption("This histogram shows how business impacts are spread. A long right tail means a few incidents are much more expensive than the rest.")

    st.markdown("---")
    with st.expander("Data Notes", expanded=False):
        st.markdown(
            """
            - Source: model-ready combined real dataset (+ synthetic if available).
            - Metrics here are descriptive and do not apply safeguard-effect simulation.
            - Decision page is where prediction and return formulas are executed.
            """
        )


def _render_recommendations(rec: dict[str, Any], prediction_usd: float) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Mapped Threat Scenario", rec.get("mapped_vulnerability", "n/a"))
    c2.metric("Expected Business Loss (USD)", f"${prediction_usd:,.0f}")
    c3.metric("Business Loss After Safeguards (USD)", f"${rec.get('loss_after', 0):,.0f}")
    rosi_value = rec.get("rosi")
    c4.metric("Expected Return", f"{rosi_value:.2f}x" if isinstance(rosi_value, (int, float)) else "n/a")

    before = float(prediction_usd)
    after = float(rec.get("loss_after", 0.0))
    cost = float(rec.get("control_cost", 0.0))
    delta = before - after

    wf = go.Figure(
        go.Waterfall(
            orientation="v",
            measure=["relative", "relative", "total"],
            x=["Risk Reduction", "Control Cost", "Net Position"],
            y=[delta, -cost, delta - cost],
            connector={"line": {"color": "rgba(148, 163, 184, 0.4)"}},
        )
    )
    wf.update_layout(
        title="Business Impact Waterfall (USD)",
        yaxis_title="USD",
        margin=dict(l=20, r=20, t=40, b=20),
        height=320,
    )
    st.plotly_chart(wf, use_container_width=True)
    st.caption("Risk Reduction is the estimated annual savings from safeguards. Control Cost is the annual implementation + operating cost in USD. Net Position is savings minus cost.")

    items = rec.get("recommendations", [])
    if items:
        df_rec = pd.DataFrame(items)
        for col in ["cost", "risk_reduction", "loss_after", "rosi"]:
            if col in df_rec.columns:
                df_rec[col] = pd.to_numeric(df_rec[col], errors="coerce")
        df_rec = df_rec.rename(
            columns={
                "control": "business_control",
                "tool_examples": "example_tools",
                "control_type": "control_category",
                "effort": "implementation_effort",
                "cost": "annual_cost_usd",
                "risk_reduction": "annual_loss_reduction",
                "loss_after": "residual_business_loss_usd",
                "rosi": "expected_return",
                "priority": "business_priority",
            }
        )
        st.subheader("Recommended Safeguards")
        st.dataframe(
            df_rec[[c for c in ["business_control", "example_tools", "control_category", "implementation_effort", "annual_cost_usd", "annual_loss_reduction", "residual_business_loss_usd", "expected_return", "business_priority"] if c in df_rec.columns]],
            use_container_width=True,
            hide_index=True,
        )

        if "expected_return" in df_rec.columns and "business_control" in df_rec.columns:
            chart_df = df_rec.dropna(subset=["expected_return"]).copy().sort_values("expected_return", ascending=False).head(8)
            if not chart_df.empty:
                fig = px.bar(
                    chart_df,
                    x="expected_return",
                    y="business_control",
                    orientation="h",
                    title="Expected Return by Safeguard",
                    color="expected_return",
                    labels={"expected_return": "Expected Return"},
                )
                fig.update_layout(height=320, margin=dict(l=20, r=20, t=40, b=20))
                st.plotly_chart(fig, use_container_width=True)
                st.caption("Higher expected return means the safeguard bundle reduces more expected loss per dollar of annual cost spent.")


def _render_decision_page(df: pd.DataFrame, attack_map: dict[str, str], data_map: dict[str, str], industries: list[str], attacks: list[str], data_types: list[str]) -> None:
    _inject_css()
    st.title("Cyber Risk Decision Studio")
    st.caption("From incident profile to expected business loss, safeguard portfolio, and return in one flow.")

    chips = "".join(
        [
            '<span class="flow-chip">1. Business Inputs</span>',
            '<span class="flow-chip">2. Estimate Loss</span>',
            '<span class="flow-chip">3. Recommend Safeguards</span>',
            '<span class="flow-chip">4. Estimate Return</span>',
        ]
    )
    st.markdown(chips, unsafe_allow_html=True)

    _render_formula_and_definitions()

    with st.form("decision_form"):
        r1c1, r1c2, r1c3 = st.columns(3)
        industry = r1c1.selectbox("Business Segment", industries, index=0)
        vulnerability = r1c2.selectbox("Threat Scenario", attacks, index=0)
        data_type = r1c3.selectbox("Sensitive Data Category", data_types, index=0)

        r2c1, r2c2, r2c3 = st.columns(3)
        year = r2c1.number_input("Calendar Year", min_value=2010, max_value=2035, value=2025, step=1)
        records = r2c2.number_input("Records Exposed", min_value=1.0, value=25000.0, step=1000.0)
        employee_count = r2c3.number_input("Workforce Size", min_value=0.0, value=800.0, step=50.0)

        r3c1, r3c2, r3c3 = st.columns(3)
        severity = r3c1.selectbox("Incident Severity", ["Auto", "Low", "Medium", "High", "Critical"], index=0)
        budget = r3c2.text_input("Annual Security Spend (USD M)", value="", placeholder="Optional")
        recovery_days = r3c3.text_input("Recovery Time (days)", value="", placeholder="Optional")

        r4c1, r4c2 = st.columns(2)
        country = r4c1.text_input("Country", value="", placeholder="Optional")
        run = r4c2.form_submit_button("Run Business Case", use_container_width=True)

    if run:
        sev_map = {"Auto": None, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

        def to_float(v: str) -> float | None:
            v = str(v).strip()
            if not v:
                return None
            try:
                return float(v)
            except Exception:
                return None

        payload = [
            {
                "Industry": industry,
                "Year": int(year),
                "Attack_Type": attack_map.get(vulnerability, vulnerability),
                "Data_Type": data_map.get(data_type, data_type),
                "Records_Compromised": float(records),
                "Employee_Count": float(employee_count) if employee_count > 0 else None,
                "Security_Budget_Million_USD": to_float(budget),
                "Incident_Severity": sev_map.get(severity),
                "Recovery_Time_Days": to_float(recovery_days),
                "Country": country.strip() or None,
                "Baseline_Industry_Cost_Million_USD": None,
                "Canonical_Attack_Vector": None,
            }
        ]

        with st.spinner("Running prediction and ROI simulation..."):
            try:
                out = _call_predict_and_recommend(payload, PREDICT_RECOMMEND_API_URL)
                prediction_musd = float(out.get("prediction_musd", 0.0))
                prediction_usd = prediction_musd * 1_000_000.0
                st.session_state["decision_output"] = out
                st.session_state["prediction_usd"] = prediction_usd
            except Exception as e:
                st.error(f"Analysis failed: {e}")

    if st.session_state.get("decision_output"):
        st.markdown("---")
        st.header("Business Case Output")
        out = st.session_state["decision_output"]
        prediction_usd = float(st.session_state.get("prediction_usd", 0.0))

        rec = out.get("recommendation", {})
        if rec:
            _render_recommendations(rec, prediction_usd)

        filled = out.get("fields_filled")
        if filled:
            st.caption("Auto-filled baseline fields: " + ", ".join(filled))


def main() -> None:
    _inject_css()

    try:
        health = requests.get(HEALTH_API_URL, timeout=5)
        health.raise_for_status()
        h = health.json()
        st.success(f"Backend connected • Model: {h.get('model', 'n/a')} ({h.get('model_path', 'n/a')})")
    except Exception as e:
        st.warning(f"Backend health check failed: {e}")

    try:
        df = _load_data(REAL_DATA_PATH, SYN_DATA_PATH)
    except Exception as e:
        st.error(f"Dataset load failed: {e}")
        st.stop()

    attack_map, data_map, industries, attacks, data_types = _build_option_maps(df)

    st.sidebar.title("Navigate")
    page = st.sidebar.radio("Page", ["Decision Studio", "Data Metrics"], index=0)

    if page == "Decision Studio":
        _render_decision_page(df, attack_map, data_map, industries, attacks, data_types)
    else:
        _render_data_metrics(df)


if __name__ == "__main__":
    main()
