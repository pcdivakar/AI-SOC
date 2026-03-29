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
from vulnerability_enrichment import enrich_assets_with_vulnerabilities, fetch_cves_by_keyword
from chatbot import ask_ai
from chart_generator import generate_chart

load_dotenv()
utils.init_db()

st.set_page_config(page_title="AI PCAP Analyzer - OT Asset Intelligence", layout="wide")
st.title("🛡️ AI PCAP Analyzer with OT Asset Classification & Vulnerability Intelligence")

# API keys
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
groq_api_key = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY"))

with st.sidebar:
    st.header("Configuration")
    if not nvd_api_key:
        st.warning("Using public NVD endpoint (rate‑limited). For better performance, add a free API key.")
    if not groq_api_key:
        st.info("Groq API key not set. AI classification and chatbot disabled.")
    st.markdown("---")
    st.markdown("Upload a PCAP file to see asset classification and vulnerability data.")
    st.markdown("**Supported OT protocols:** Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC 104, OPC UA, CODESYS, Profinet, EtherCAT, MQTT, IEC 61850, and more.")
    st.markdown("**AI Assistant:** Powered by Groq's fast inference (free tier).")

# Session state
if 'assets_df' not in st.session_state:
    st.session_state.assets_df = None
if 'cve_data' not in st.session_state:
    st.session_state.cve_data = {}
if 'keyword_cves' not in st.session_state:
    st.session_state.keyword_cves = {}
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False

# File upload
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
    cols = [
        "ip", "asset_type", "confidence", "vendor", "ports", "hostnames",
        "ot_protocols", "os", "firmware_version", "model_number",
        "http_user_agents", "dns_queries", "snmp_communities", "cves"
    ]
    st.session_state.assets_df = st.session_state.assets_df[cols]

    st.session_state.analysis_complete = True
    os.unlink(tmp_path)
    st.rerun()

if st.session_state.analysis_complete:
    df_assets = st.session_state.assets_df

    # Vulnerability enrichment (per asset)
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

    # Vulnerability lookup section – tabs
    tab1, tab2 = st.tabs(["Search by CVE ID", "Search by Keyword"])

    with tab1:
        st.markdown("Enter a single CVE ID to fetch its details.")
        cve_input = st.text_input("CVE ID (e.g., CVE-2021-44228):")
        if cve_input and re.match(r'CVE-\d{4}-\d{4,7}', cve_input, re.IGNORECASE):
            with st.spinner(f"Fetching data for {cve_input}..."):
                cve_data = fetch_nvd(cve_input, nvd_api_key)
                epss = fetch_epss(cve_input)
                kev = fetch_kev_status(cve_input)
                if cve_data:
                    description = cve_data.get("descriptions", [{}])[0].get("value", "N/A")
                    st.session_state.cve_data[cve_input] = {
                        "description": description,
                        "epss": epss if epss is not None else "N/A",
                        "kev": kev
                    }
                    st.success(f"Fetched data for {cve_input}")
                    st.write(f"**CVE:** {cve_input}")
                    st.write(f"**Description:** {description}")
                    st.write(f"**EPSS Score:** {st.session_state.cve_data[cve_input]['epss']}")
                    st.write(f"**KEV (Known Exploited):** {'Yes' if st.session_state.cve_data[cve_input]['kev'] else 'No'}")
                else:
                    st.error(f"Could not retrieve data for {cve_input}. Please check the CVE ID and try again.")

    with tab2:
        st.markdown("Enter a keyword (e.g., product name, vendor) to get a list of recent CVEs.")
        keyword_input = st.text_input("Keyword (e.g., Apache, Windows 10, Modbus):")
        if st.button("Search CVEs by Keyword") and keyword_input:
            if not nvd_api_key:
                st.info("No API key – using public endpoint. Searches may be slow; please wait.")
            with st.spinner(f"Searching NVD for '{keyword_input}'..."):
                results = fetch_cves_by_keyword(keyword_input, nvd_api_key, limit=15)
                if results:
                    st.session_state.keyword_cves[keyword_input] = results
                    df_keyword = pd.DataFrame(results)
                    display_cols = ["cve_id", "published", "epss", "kev", "description"]
                    df_keyword = df_keyword[display_cols]
                    st.dataframe(df_keyword, use_container_width=True)
                    st.success(f"Found {len(results)} CVEs")
                else:
                    st.warning(f"No CVEs found for keyword '{keyword_input}'. Try a different term.")

        if keyword_input in st.session_state.keyword_cves and st.button("Clear Keyword Results"):
            del st.session_state.keyword_cves[keyword_input]
            st.rerun()

    # AI Assistant (Groq) with chart capabilities
    if groq_api_key:
        st.subheader("🤖 AI Assistant (Powered by Groq)")
        st.markdown("Ask about the assets, vulnerabilities, or request charts (e.g., 'Show me a bar chart of asset types' or 'Create a pie chart of vendors').")

        # Build context
        asset_summary = []
        for _, row in df_assets.iterrows():
            vuln_text = ""
            if "vulnerabilities" in row and row["vulnerabilities"]:
                vuln_text = " ; Vulnerabilities: " + ", ".join([f"{v['cve_id']} (EPSS={v['epss']}, KEV={v['kev']})" for v in row["vulnerabilities"]])
            asset_summary.append(
                f"- {row['ip']}: {row['asset_type']} (ports: {', '.join(map(str, row['ports']))}, "
                f"vendor: {row['vendor']}, OS: {row['os']}, firmware: {row['firmware_version']}, model: {row['model_number']}){vuln_text}"
            )
        context = "PCAP Analysis Results:\n" + "\n".join(asset_summary)

        if st.session_state.cve_data:
            context += "\n\nManually fetched CVE details:\n"
            for cve, info in st.session_state.cve_data.items():
                context += f"- {cve}: EPSS={info['epss']}, KEV={info['kev']}, Desc={info['description'][:100]}...\n"

        if st.session_state.keyword_cves:
            context += "\n\nKeyword Search Results (from NVD):\n"
            for keyword, cves in st.session_state.keyword_cves.items():
                context += f"\n**Keyword: {keyword}**\n"
                for cve in cves[:10]:
                    context += f"- {cve['cve_id']}: EPSS={cve['epss']}, KEV={cve['kev']}, Desc={cve['description'][:100]}...\n"

        user_question = st.text_area("Ask a question or request a chart (e.g., 'Create a bar chart of asset types')")
        if st.button("Ask AI") and user_question:
            with st.spinner("Thinking..."):
                # Auto‑fetch CVEs mentioned in the question
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

                # Debug: show the raw AI response
                with st.expander("Debug: Raw AI response"):
                    st.code(answer)

                # Look for a line starting with "CHART:"
                chart_line = None
                for line in answer.split('\n'):
                    if line.strip().upper().startswith('CHART:'):
                        chart_line = line.strip()
                        break

                if chart_line:
                    # Remove "CHART:" and split by '|'
                    parts = chart_line[6:].split('|')
                    if len(parts) >= 2:
                        chart_type = parts[0].strip().lower()
                        if chart_type == 'heatmap' and len(parts) >= 4:
                            # Format: CHART: heatmap|x|y|z|title
                            x_axis = parts[1].strip() if len(parts) > 1 else None
                            y_axis = parts[2].strip() if len(parts) > 2 else None
                            z_axis = parts[3].strip() if len(parts) > 3 else None
                            title = parts[4].strip() if len(parts) > 4 else None
                            try:
                                fig = generate_chart('heatmap', df_assets, x_col=x_axis, y_col=y_axis, z_col=z_axis, title=title)
                            except Exception as e:
                                st.error(f"Heatmap generation failed: {e}")
                                fig = None
                        else:
                            # General case: bar, pie, line, scatter
                            x_axis = parts[1].strip() if len(parts) > 1 else None
                            y_axis = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
                            title = parts[3].strip() if len(parts) > 3 else None

                            try:
                                if chart_type == 'bar':
                                    fig = generate_chart('bar', df_assets, x_col=x_axis, y_col=y_axis, title=title)
                                elif chart_type == 'pie':
                                    fig = generate_chart('pie', df_assets, names_col=x_axis, values_col=y_axis, title=title)
                                elif chart_type == 'line':
                                    fig = generate_chart('line', df_assets, x_col=x_axis, y_col=y_axis, title=title)
                                elif chart_type == 'scatter':
                                    fig = generate_chart('scatter', df_assets, x_col=x_axis, y_col=y_axis, color_col=y_axis, title=title)
                                else:
                                    st.error(f"Unknown chart type: {chart_type}")
                                    fig = None
                            except Exception as e:
                                st.error(f"Chart generation failed: {e}")
                                fig = None

                        if fig:
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.write(answer)
                    else:
                        st.write(answer)
                else:
                    st.markdown("**AI Response:**")
                    st.write(answer)
    else:
        st.error("Groq API key not configured. Add GROQ_API_KEY to secrets to use the AI chatbot.")
