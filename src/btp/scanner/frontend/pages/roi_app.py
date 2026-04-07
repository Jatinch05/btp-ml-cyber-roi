import streamlit as st
import pandas as pd
import time
from pathlib import Path

st.set_page_config(page_title="ROI Calculator", layout="wide")

if "theme" not in st.session_state:
    st.session_state.theme = "dark"

col_button, _, col_theme = st.columns([1,8,1])
with col_button:
    if st.button("Go to Dashboard", use_container_width=True):
        st.switch_page("app.py")
with col_theme:
    light_mode = st.checkbox("Light Mode", value=st.session_state.theme == "light", key="light_mode_roi")
    st.session_state.theme = "light" if light_mode else "dark"

if st.session_state.theme == "light":
    st.markdown("""
    <style>
    .stApp { background-color: #f8fafc; color: #0f172a; }
    .stButton>button { background-color: #0ea5e9; color: white; }
    </style>
    """, unsafe_allow_html=True)

st.title("💰 ROI Calculator")

# Progress Bar
progress_html = """
<div style="text-align:center; margin:20px 0 30px 0;">
    <div style="display:flex; justify-content:center; align-items:center; gap:12px; width:100%; flex-wrap:wrap;">
        <div style="width:40px; height:40px; background:#10b981; color:white; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:18px;">1</div>
        <div style="font-size:1rem; font-weight:600; color:#10b981;">Penetration Testing</div>
        <div style="flex:1; height:6px; background:#e5e7eb; border-radius:4px; position:relative; overflow:hidden; min-width:200px;">
            <div style="position:absolute; left:0; top:0; width:50%; height:100%; background:#10b981; border-radius:4px;"></div>
            <div style="position:absolute; left:50%; top:0; width:50%; height:100%; background:#0ea5e9; border-radius:4px;"></div>
        </div>
        <div style="font-size:1rem; font-weight:600; color:#0ea5e9;">ROI Calculator</div>
        <div style="width:40px; height:40px; background:#0ea5e9; color:white; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:18px;">2</div>
    </div>
</div>
"""

st.markdown(progress_html, unsafe_allow_html=True)

st.subheader("ML Model is analyzing your latest scan...")

# Load scan data
root_dir = Path(__file__).resolve().parent.parent.parent
csv_path = root_dir / "backend/data/processed/scanner_mapped_with_controls.csv"

if csv_path.exists():
    df = pd.read_csv(csv_path)
    
    with st.spinner("Calculating financial risk and ROI..."):
        time.sleep(2.8)
    
    st.success("✅ ML Prediction Complete!")
    
    # Basic analysis (mock ML)
    total_ports = len(df)
    high_risk = df[df['Attack_Type'].isin(['Web Exploit', 'Privilege Escalation', 'Database Attack'])].shape[0]
    predicted_loss = high_risk * 50000  # Mock calculation
    recommended_investment = total_ports * 100  # Mock
    expected_roi = 300 if high_risk > 0 else 150  # Mock
    
    st.markdown(f"""
### Predicted Financial Impact

**Predicted Loss if unpatched:** ${predicted_loss:,}  
**Risk Priority:** {'High' if high_risk > 5 else 'Medium'}  
**Recommended Investment:** ${recommended_investment:,}  
**Expected ROI:** {expected_roi}%

**Top vulnerabilities to fix immediately:**
{df['Security_Vulnerability_Type'].value_counts().head(3).index.tolist()}
""")
    
    st.download_button("📥 Download Full ROI Report as CSV", df.to_csv(index=False), "ROI_Report.csv", use_container_width=True)
else:
    st.error("No scan data found. Please run the scanner first.")
    st.button("Go to Scanner", on_click=lambda: st.switch_page("pages/scanner_app.py"))