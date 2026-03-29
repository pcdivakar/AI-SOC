import streamlit as st
import os
import tempfile
import re
import random
import pandas as pd
from dotenv import load_dotenv
import utils
from pcap_analyzer import analyze_pcap
from asset_classifier import classify_asset
from vulnerability import fetch_nvd, fetch_epss, fetch_kev_status
from vulnerability_enrichment import enrich_assets_with_vulnerabilities, fetch_cves_by_keyword
from chatbot import ask_ai
from chart_generator import generate_chart

load_dotenv()
utils.init_db()

# ---- Custom CSS for Deloitte dark green theme ----
st.markdown("""
<style>
    /* Sidebar */
    section[data-testid="stSidebar"] {
        background-color: #0A2F2F;
        border-right: 1px solid #1E3A3A;
    }
    /* Main content background */
    .stApp {
        background-color: #0A2F2F;
    }
    /* Headers */
    h1, h2, h3, h4, h5, h6 {
        color: #86BC25 !important;
    }
    /* Buttons */
    .stButton > button {
        background-color: #86BC25;
        color: #0A2F2F;
        border: none;
        border-radius: 0.5rem;
        font-weight: 600;
        transition: 0.2s;
    }
    .stButton > button:hover {
        background-color: #6FA31C;
        color: white;
    }
    /* DataFrames */
    .dataframe {
        background-color: #1E3A3A;
        color: #FFFFFF;
    }
    /* Expander headers */
    .streamlit-expanderHeader {
        background-color: #1E3A3A;
        color: #86BC25;
        border-radius: 0.5rem;
    }
    /* Tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1E3A3A;
        border-radius: 0.5rem;
        color: #FFFFFF;
        padding: 0.5rem 1rem;
    }
    .stTabs [aria-selected="true"] {
        background-color: #86BC25;
        color: #0A2F2F;
    }
    /* Success/Error/Warning messages */
    .stAlert {
        background-color: #1E3A3A;
        border-left-color: #86BC25;
    }
    /* Dashboard container (iframe) */
    .dashboard-container {
        background-color: #0A2F2F;
        border-radius: 1rem;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="AI PCAP Analyzer - Deloitte OT Intelligence", layout="wide")
st.title("🛡️ Deloitte OT Security Analyzer")

# API keys
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
groq_api_key = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY"))

# Logo URL (optional)
logo_url = st.secrets.get("LOGO_URL", None)

with st.sidebar:
    if logo_url:
        st.image(logo_url, width=150)
    else:
        st.markdown("## 📊 Deloitte OT Dashboard")
    st.markdown("---")
    max_packets = st.slider(
        "Max packets to analyze",
        min_value=1000,
        max_value=200000,
        value=50000,
        step=5000,
        help="Larger values give better coverage but use more memory/time."
    )
    st.markdown("---")
    st.markdown("Upload a PCAP file to classify OT assets and discover vulnerabilities.")
    st.markdown("**Supported OT protocols:** Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC 104, OPC UA, CODESYS, Profinet, EtherCAT, MQTT, IEC 61850, and more.")
    st.markdown("**AI Assistant:** Powered by Groq.")

# Session state
if 'assets_df' not in st.session_state:
    st.session_state.assets_df = None
if 'cve_data' not in st.session_state:
    st.session_state.cve_data = {}
if 'keyword_cves' not in st.session_state:
    st.session_state.keyword_cves = {}
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'dashboard_definition' not in st.session_state:
    st.session_state.dashboard_definition = None
if 'protocol_counts' not in st.session_state:
    st.session_state.protocol_counts = {}

# Helper functions (prepare_chart_data, map_column, parse_chart_spec, render_chart) remain unchanged.
# (Copy them from your previous code – they are the same as before.)
# ... (Insert the helper functions here – they are long but unchanged) ...

# Main app flow (unchanged except for the dashboard container styling)
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file and not st.session_state.analysis_complete:
    # ... (file upload and analysis code unchanged) ...
    pass

if st.session_state.analysis_complete:
    df_assets = st.session_state.assets_df

    # Vulnerability enrichment (unchanged)
    if nvd_api_key and "vulnerabilities" not in df_assets.columns:
        with st.spinner("Enriching assets with vulnerability data..."):
            df_assets = enrich_assets_with_vulnerabilities(df_assets, nvd_api_key)
            st.session_state.assets_df = df_assets

    tab_assets, tab_vuln = st.tabs(["📊 Asset Tables", "🔍 Vulnerability Lookup"])

    with tab_assets:
        st.subheader("🏭 OT/ICS Assets")
        ot_mask = df_assets["ot_protocols"].apply(lambda x: len(x) > 0)
        ot_assets = df_assets[ot_mask]
        if not ot_assets.empty:
            st.dataframe(ot_assets, use_container_width=True)
        else:
            st.info("No OT/ICS protocols detected.")

        st.subheader("📡 All Detected Assets")
        st.dataframe(df_assets, use_container_width=True)

    with tab_vuln:
        # Embed the CVE dashboard (with dark green theme)
        html_path = os.path.join(os.path.dirname(__file__), "cve_dashboard.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            # Wrap in a container with custom class
            st.markdown('<div class="dashboard-container">', unsafe_allow_html=True)
            st.components.v1.html(html_content, height=1000, scrolling=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("Dashboard HTML file not found. Please add 'cve_dashboard.html' to the app directory.")

    # AI Assistant (unchanged)
    if groq_api_key:
        # ... (rest of AI assistant code unchanged) ...
        pass
    else:
        st.error("Groq API key not configured. Add GROQ_API_KEY to secrets to use the AI assistant.")
