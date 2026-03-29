import streamlit as st
import os
import tempfile
import re
import pandas as pd
from dotenv import load_dotenv
import utils
from pcap_analyzer import analyze_pcap
from asset_classifier import classify_asset
from vulnerability import fetch_nvd, fetch_epss, fetch_kev_status
from vulnerability_enrichment import enrich_assets_with_vulnerabilities
from chatbot import ask_ai

load_dotenv()
utils.init_db()

st.set_page_config(page_title="AI PCAP Analyzer - OT Asset Intelligence", layout="wide")
st.title("🛡️ AI PCAP Analyzer with OT Asset Classification & Vulnerability Intelligence")

nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
groq_api_key = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY"))

with st.sidebar:
    st.header("Configuration")
    if not nvd_api_key:
        st.warning("NVD API key not set. NVD queries may fail.")
    if not groq_api_key:
        st.info("Groq API key not set. AI classification and chatbot disabled.")
    st.markdown("---")
    st.markdown("Upload a PCAP file to see asset classification and vulnerability data.")
    st.markdown("**Supported OT protocols:** Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC 104, OPC UA, CODESYS, Profinet, EtherCAT, MQTT, IEC 61850, and more.")
    st.markdown("**AI Assistant:** Powered by Groq's fast inference (free tier).")

if 'assets_df' not in st.session_state:
    st.session_state.assets_df = None
if 'cve_data' not in st.session_state:
    st.session_state.cve_data = {}
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False

uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file and not st.session_state.analysis_complete:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    with st.spinner("Analyzing PCAP..."):
        ip_data = analyze_pcap(tmp_path)

    with st.spinner("Classifying assets..."):
        classified = []
        for ip, data in ip_data.items():
            classified.append(classify_asset(data, groq_api_key))

    st.session_state.assets_df = pd.DataFrame(classified)
    cols = ["ip", "asset_type", "confidence", "vendor", "ports", "hostnames", "ot_protocols", "http_user_agents", "dns_queries", "snmp_communities", "cves"]
    st.session_state.assets_df = st.session_state.assets_df[cols]

    st.session_state.analysis_complete = True
    os.unlink(tmp_path)
    st.rerun()

if st.session_state.analysis_complete:
    df_assets = st.session_state.assets_df

    # Vulnerability enrichment
    if nvd_api_key and "vulnerabilities" not in df_assets.columns:
        with st.spinner("Enriching assets with vulnerability data (this may take a moment)..."):
            df_assets = enrich_assets_with_vulnerabilities(df_assets, nvd_api_key)
            st.session_state.assets_df = df_assets

    st.subheader("🏭 OT/ICS Assets")
    ot_mask = df_assets["ot_protocols"].apply(lambda x: len(x) > 0)
    ot_assets = df_assets[ot_mask]
    if not ot_assets.empty:
        st.dataframe(ot_assets, use_container_width=True)
    else:
        st.info("No OT/ICS protocols detected.")

    st.subheader("📡 All Detected Assets")
    st.dataframe(df_assets, use_container_width=True)

    if nvd_api_key:
        st.subheader("🔍 Vulnerability Lookup")
        cve_input = st.text_input("Enter a CVE ID to fetch details (e.g., CVE-2021-44228):")
        if cve_input and re.match(r'CVE-\d{4}-\d{4,7}', cve_input, re.IGNORECASE):
            with st.spinner(f"Fetching data for {cve_input}..."):
                cve_data = fetch_nvd(cve_input, nvd_api_key)
                epss = fetch_epss(cve_input)
                kev = fetch_kev_status(cve_input)
                st.session_state.cve_data[cve_input] = {
                    "description": cve_data.get("descriptions", [{}])[0].get("value", "N/A") if cve_data else "N/A",
                    "epss": epss if epss is not None else "N/A",
                    "kev": kev
                }
            info = st.session_state.cve_data[cve_input]
            st.write(f"**CVE:** {cve_input}")
            st.write(f"**Description:** {info['description']}")
            st.write(f"**EPSS Score:** {info['epss']}")
            st.write(f"**KEV (Known Exploited):** {'Yes' if info['kev'] else 'No'}")

    if groq_api_key:
        st.subheader("🤖 AI Assistant (Powered by Groq)")
        st.markdown("Ask about the assets, vulnerabilities, or general questions related to the PCAP analysis.")

        asset_summary = []
        for _, row in df_assets.iterrows():
            vuln_text = ""
            if "vulnerabilities" in row and row["vulnerabilities"]:
                vuln_text = " ; Vulnerabilities: " + ", ".join([f"{v['cve_id']} (EPSS={v['epss']}, KEV={v['kev']})" for v in row["vulnerabilities"]])
            asset_summary.append(f"- {row['ip']}: {row['asset_type']} (ports: {', '.join(map(str, row['ports']))}, vendor: {row['vendor']}){vuln_text}")
        context = "PCAP Analysis Results:\n" + "\n".join(asset_summary)

        if st.session_state.cve_data:
            context += "\n\nKnown Vulnerability Data (fetched by user):\n"
            for cve, info in st.session_state.cve_data.items():
                context += f"- {cve}: EPSS={info['epss']}, KEV={info['kev']}, Desc={info['description'][:100]}...\n"

        user_question = st.text_area("Ask a question (e.g., 'What assets are web servers?' or 'Show me all CVEs with EPSS > 0.5')")
        if st.button("Ask AI") and user_question:
            with st.spinner("Thinking..."):
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', user_question, re.IGNORECASE)
                if cve_matches and nvd_api_key:
                    for cve in cve_matches:
                        if cve not in st.session_state.cve_data:
                            cve_data = fetch_nvd(cve, nvd_api_key)
                            epss = fetch_epss(cve)
                            kev = fetch_kev_status(cve)
                            st.session_state.cve_data[cve] = {
                                "description": cve_data.get("descriptions", [{}])[0].get("value", "N/A") if cve_data else "N/A",
                                "epss": epss if epss is not None else "N/A",
                                "kev": kev
                            }
                    for cve in cve_matches:
                        info = st.session_state.cve_data[cve]
                        context += f"\n- {cve}: EPSS={info['epss']}, KEV={info['kev']}, Desc={info['description'][:100]}..."

                ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', user_question)
                if ip_matches:
                    ip_context = []
                    for ip in ip_matches:
                        asset_row = df_assets[df_assets['ip'] == ip]
                        if not asset_row.empty:
                            ip_context.append(f"- {ip}: {asset_row.iloc[0]['asset_type']} (ports: {asset_row.iloc[0]['ports']})")
                    if ip_context:
                        context += "\n\nSpecific asset details:\n" + "\n".join(ip_context)

                answer = ask_ai(user_question, context, groq_api_key=groq_api_key)
                st.markdown("**AI Response:**")
                st.write(answer)
    else:
        st.error("Groq API key not configured. Add GROQ_API_KEY to secrets to use the AI chatbot.")
