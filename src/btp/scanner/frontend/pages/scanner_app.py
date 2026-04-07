import streamlit as st
import pandas as pd
from pathlib import Path
import os
import hashlib

st.set_page_config(page_title="SecureScope Scanner", layout="wide")

if "theme" not in st.session_state:
    st.session_state.theme = "dark"

# Tracking if this is the first time entering scanner page in this session
if "scanner_page_visited" not in st.session_state:
    st.session_state.scanner_page_visited = True
    root_dir = Path(__file__).resolve().parent.parent.parent
    csv_path = root_dir / "backend/data/processed/scanner_mapped_with_controls.csv"
    # Clearing on first visit to scanner page (fresh start)
    if csv_path.exists():
        os.remove(csv_path)
else:
    # Defining paths for subsequent loads
    root_dir = Path(__file__).resolve().parent.parent.parent
    csv_path = root_dir / "backend/data/processed/scanner_mapped_with_controls.csv"

col_left, col_button, col_theme = st.columns([8,1,1])
with col_button:
    if st.button("Go to Dashboard", use_container_width=True):
        st.switch_page("app.py")
with col_theme:
    light_mode = st.checkbox("Light Mode", value=st.session_state.theme == "light", key="light_mode_scanner")
    st.session_state.theme = "light" if light_mode else "dark"

if st.session_state.theme == "light":
    st.markdown("""
    <style>
    .stApp { background-color: #f8fafc; color: #0f172a; }
    .stButton>button { background-color: #0ea5e9; color: white; }
    </style>
    """, unsafe_allow_html=True)

# Defining script path
script_path = root_dir / "local_scanner.py"

st.title("🔍 SecureScope Scanner")

# To check if scan results exist
scan_completed = csv_path.exists()

if "script_downloaded" not in st.session_state:
    st.session_state.script_downloaded = False

# Progress Bar
if scan_completed:
    circle1_color = "#10b981"  # GREEN when scan done
    text1_color = "#10b981"
    first_half_color = "#10b981"  # GREEN bar when done
else:
    circle1_color = "#0ea5e9"  # BLUE while on this page
    text1_color = "#0ea5e9"
    first_half_color = "#0ea5e9" if st.session_state.script_downloaded else "#e5e7eb"

progress_html = f"""
<div style="text-align:center; margin:20px 0 30px 0;">
    <div style="display:flex; justify-content:center; align-items:center; gap:12px; width:100%; flex-wrap:wrap;">
        <div style="width:40px; height:40px; background:{circle1_color}; color:white; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:18px;">1</div>
        <div style="font-size:1rem; font-weight:600; color:{text1_color};">Penetration Testing</div>
        <div style="flex:1; height:6px; background:#e5e7eb; border-radius:4px; position:relative; overflow:hidden; min-width:200px;">
            <div style="position:absolute; left:0; top:0; width:50%; height:100%; background:{first_half_color}; border-radius:4px;"></div>
            <div style="position:absolute; left:50%; top:0; width:50%; height:100%; background:#e5e7eb; border-radius:4px;"></div>
        </div>
        <div style="font-size:1rem; font-weight:600; color:#9ca3af;">ROI Calculator</div>
        <div style="width:40px; height:40px; background:#9ca3af; color:white; border-radius:50%; display:flex; align-items:center; justify-content:center; font-weight:bold; font-size:18px;">2</div>
    </div>
</div>
"""

st.markdown(progress_html, unsafe_allow_html=True)

st.divider()

st.subheader("Download Local Agent")

if script_path.exists():
    script_content = script_path.read_text(encoding="utf-8")
    script_sha256 = hashlib.sha256(script_content.encode("utf-8")).hexdigest()
    if st.download_button("Download SecureScope Agent", script_content, "secure_scope_local_scanner.py", "text/x-python", use_container_width=True):
        st.session_state.script_downloaded = True
        st.success("Agent downloaded successfully! Run it on the target machine.")
        st.rerun()

    st.caption("You may verify the downloaded agent with SHA-256 for integrity check.")
    st.code(script_sha256, language="text")
    st.download_button(
        "Download SHA256",
        data=f"{script_sha256}  secure_scope_local_scanner.py\n".encode("utf-8"),
        file_name="secure_scope_local_scanner.py.sha256",
        mime="text/plain",
        use_container_width=True,
    )
else:
    st.error("local_scanner.py not found in project root.")


# 1. Penetration Testing Results
st.subheader("1. Penetration Testing Results")

col_refresh, col_space = st.columns([1, 4])
with col_refresh:
    if st.button("Refresh Results", type="primary"):
        st.rerun()

if scan_completed:
    df = pd.read_csv(csv_path)

    total_rows = len(df)
    nvd_hits = df["CVE"].astype(str).str.strip().ne("N/A").sum() if "CVE" in df.columns else 0
    cvss_hits = df["CVSS_Score"].notna().sum() if "CVSS_Score" in df.columns else 0
    specific_remediation = (
        df["Recommended_Control"].astype(str).str.strip().ne("General Hardening").sum()
        if "Recommended_Control" in df.columns else 0
    )
    unknown_remediation = (
        df["Mitigation_Tool"].astype(str).str.strip().eq("Manual Review").sum()
        if "Mitigation_Tool" in df.columns else 0
    )

    st.markdown("### Coverage Quality")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("CVE Coverage", f"{(nvd_hits / total_rows * 100) if total_rows else 0:.1f}%", f"{nvd_hits}/{total_rows}")
    m2.metric("CVSS Coverage", f"{(cvss_hits / total_rows * 100) if total_rows else 0:.1f}%", f"{cvss_hits}/{total_rows}")
    m3.metric("Specific Remediation", f"{(specific_remediation / total_rows * 100) if total_rows else 0:.1f}%", f"{specific_remediation}/{total_rows}")
    m4.metric("Fallback Remediation", f"{(unknown_remediation / total_rows * 100) if total_rows else 0:.1f}%", f"{unknown_remediation}/{total_rows}")

    if total_rows and (nvd_hits / total_rows) < 0.5:
        st.warning("Low NVD match rate detected. This can happen with ambiguous service fingerprints or missing CPE/version data.")
    if total_rows and (specific_remediation / total_rows) < 0.6:
        st.warning("Remediation coverage relies on fallback controls for many rows. Consider expanding remediation_tools.csv.")

    st.divider()

    #nmap details + remediation + NVD/CVSS.
    preferred_columns = [
        "scan_timestamp",
        "Host",
        "Port",
        "Service",
        "Product",
        "Version",
        "CVE",
        "CVSS_Score",
        "NVD_Severity",
        "Recommended_Control",
        "Mitigation_Tool",
    ]
    display_columns = [c for c in preferred_columns if c in df.columns]
    display_df = df[display_columns] if display_columns else df

    st.dataframe(display_df, use_container_width=True, height=380)
    
    st.download_button(
        label="Download Scan Results as CSV",
        data=display_df.to_csv(index=False).encode("utf-8"),
        file_name=f"SecureScope_Scan_{pd.Timestamp.now().strftime('%Y%m%d_%H%M')}.csv",
        mime="text/csv",
        use_container_width=True
    )
    
    st.divider()
    
    # ROI Button - enabled after scan
    col1, col2, col3 = st.columns([5, 1, 1])
    with col3:
        if st.button("Calculate ROI", type="primary"):
            st.switch_page("pages/roi_app.py")
else:
    st.info("Run the Local Agent to generate scan results.")
    col1, col2, col3 = st.columns([5, 1, 1])
    with col3:
        st.button("Calculate ROI", type="secondary", disabled=True)


st.caption("Note: Click **Refresh Results** after running the agent if the table doesn't appear immediately.")