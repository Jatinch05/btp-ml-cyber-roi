import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

st.set_page_config(page_title="Cyber Risk & ROI", layout="wide")

if "theme" not in st.session_state:
    st.session_state.theme = "dark"

col_left, col_theme = st.columns([9,1])
with col_theme:
    light_mode = st.checkbox("Light Mode", value=st.session_state.theme == "light", key="light_mode_app")
    st.session_state.theme = "light" if light_mode else "dark"

if st.session_state.theme == "light":
    st.markdown("""
    <style>
    .stApp { background-color: #f8fafc; color: #0f172a; }
    .stButton>button { background-color: #0ea5e9; color: white; }
    </style>
    """, unsafe_allow_html=True)

# Hero Section
st.markdown("""
<div style="text-align:center; padding:20px 0;">
    <h1 style="font-size:3rem; margin-bottom:0;">🔐 SecureScope</h1>
    <h2 style="color:#0ea5e9;">Cyber Risk & ROI Intelligence Platform</h2>
    <p style="font-size:1.2rem; color:#64748b;">Identify vulnerabilities • Predict financial loss • Maximize ROI on security investment</p>
</div>
""", unsafe_allow_html=True)

col1, col2 = st.columns([7, 2])
with col2:
    if st.button("🚀 Start New Scan", type="primary", use_container_width=True):
        st.switch_page("pages/scanner_app.py")

st.divider()

DATA_PATH = Path("../data/processed/enriched.csv")
@st.cache_data
def load_or_make_sample(path: Path):
    if path.exists():
        return pd.read_csv(path)
    data = [ ... ]  
    return pd.DataFrame(data)

df = load_or_make_sample(DATA_PATH)

st.sidebar.header("Controls & Predict")
