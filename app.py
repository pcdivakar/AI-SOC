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

# ------------------ Custom CSS for Deloitte dark green theme ------------------
st.markdown("""
<style>
    section[data-testid="stSidebar"] { background-color: #0A2F2F; border-right: 1px solid #1E3A3A; }
    .stApp { background-color: #0A2F2F; }
    h1, h2, h3, h4, h5, h6 { color: #86BC25 !important; }
    .stButton > button { background-color: #86BC25; color: #0A2F2F; border: none; border-radius: 0.5rem; font-weight: 600; transition: 0.2s; }
    .stButton > button:hover { background-color: #6FA31C; color: white; }
    .dataframe { background-color: #1E3A3A; color: #FFFFFF; }
    .streamlit-expanderHeader { background-color: #1E3A3A; color: #86BC25; border-radius: 0.5rem; }
    .stTabs [data-baseweb="tab-list"] { gap: 8px; }
    .stTabs [data-baseweb="tab"] { background-color: #1E3A3A; border-radius: 0.5rem; color: #FFFFFF; padding: 0.5rem 1rem; }
    .stTabs [aria-selected="true"] { background-color: #86BC25; color: #0A2F2F; }
    .stAlert { background-color: #1E3A3A; border-left-color: #86BC25; }
</style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="AI PCAP Analyzer - Deloitte OT Intelligence", layout="wide")
st.title("🛡️ Deloitte OT Security Analyzer")

# API keys (NVD + Gemini)
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
gemini_api_key = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))
logo_url = st.secrets.get("LOGO_URL", None)

with st.sidebar:
    if logo_url: st.image(logo_url, width=150)
    else: st.markdown("## 📊 Deloitte OT Dashboard")
    st.markdown("---")
    max_packets = st.slider("Max packets to analyze", 1000, 200000, 50000, 5000)
    st.markdown("---")
    st.markdown("Upload a PCAP file to classify OT assets and discover vulnerabilities.")
    st.markdown("**Supported OT protocols:** Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC 104, OPC UA, CODESYS, Profinet, EtherCAT, MQTT, IEC 61850, and more.")
    st.markdown("**AI Assistant:** Integrated AI assistant (Gemini).")

# Session state
for key in ['assets_df', 'cve_data', 'keyword_cves', 'analysis_complete', 'dashboard_definition', 'protocol_counts', 'ics_advisory_df']:
    if key not in st.session_state:
        st.session_state[key] = None if key != 'analysis_complete' else False
        if key in ['cve_data', 'keyword_cves']: st.session_state[key] = {}

# ------------------ Helper functions ------------------
def prepare_chart_data(df, *cols):
    data = df.copy()
    for col in cols:
        if col and col in data.columns and data[col].apply(lambda x: isinstance(x, list)).any():
            data[col] = data[col].apply(len)
    return data

def map_column(label, df_columns):
    if not label or not isinstance(label, str): return None
    label_clean = label.lower().replace(' ', '_').replace('-', '_')
    if ',' in label_clean: return None
    if label_clean in df_columns: return label_clean
    for col in df_columns:
        if label_clean in col or col in label_clean: return col
    special = {
        'ip_address': 'ip', 'ipaddr': 'ip', 'ip': 'ip',
        'asset_type': 'asset_type', 'assettype': 'asset_type',
        'vendor': 'vendor',
        'ports': 'ports', 'port': 'ports', 'port_number': 'ports', 'portnumber': 'ports',
        'os': 'os', 'operating_system': 'os',
        'cves': 'cves', 'cve': 'cves',
        'hostnames': 'hostnames', 'hostname': 'hostnames',
        'ot_protocols': 'ot_protocols', 'protocol': 'ot_protocols',
        'http_user_agents': 'http_user_agents', 'user_agent': 'http_user_agents',
        'dns_queries': 'dns_queries', 'dns': 'dns_queries',
        'snmp_communities': 'snmp_communities', 'snmp': 'snmp_communities',
        'firmware_version': 'firmware_version', 'firmware': 'firmware_version',
        'model_number': 'model_number', 'model': 'model_number',
        'confidence': 'confidence',
    }
    return special.get(label_clean, None)

def parse_chart_spec(spec_str):
    parts = spec_str.split('|')
    if len(parts) < 2: return None
    raw_type = parts[0].strip()
    if ',' in raw_type: raw_type = raw_type.split(',')[0].strip()
    chart_type = raw_type.lower()
    if chart_type == 'map': chart_type = 'scatter_map'
    elif chart_type == 'scattergeo': chart_type = 'scatter_map'
    return {'type': chart_type, 'params': parts[1:]}

def generate_auto_dashboard(df, protocol_counts):
    charts = []
    if 'asset_type' in df.columns and df['asset_type'].nunique() > 0:
        charts.append({'type': 'bar', 'params': ['asset_type', 'count', 'Asset Type Distribution']})
    if 'vendor' in df.columns and df['vendor'].nunique() > 0:
        charts.append({'type': 'pie', 'params': ['vendor', '', 'Vendor Distribution']})
    if 'os' in df.columns and df['os'].nunique() > 0:
        charts.append({'type': 'bar', 'params': ['os', 'count', 'Operating System Distribution']})
    if protocol_counts and len(protocol_counts) > 0:
        charts.append({'type': 'bar', 'params': ['protocol', 'count', 'OT Protocol Distribution (packet count)']})
    if 'ports' in df.columns and df['ports'].apply(lambda x: isinstance(x, list)).any():
        if df['ports'].apply(lambda x: len(x) > 0).any():
            charts.append({'type': 'bar', 'params': ['ports', 'count', 'Top Open Ports']})
    if 'cves' in df.columns and df['cves'].apply(lambda x: isinstance(x, list) and len(x) > 0).any():
        charts.append({'type': 'bar', 'params': ['cves', 'count', 'CVEs per Asset (count)']})
    return charts

def render_chart(spec, df, protocol_counts=None):
    chart_type = spec['type']
    params = spec['params']
    try:
        # Protocol distribution special case
        if chart_type in ['bar', 'pie'] and params and ('protocol' in params[0].lower() or 'distribution' in params[0].lower()):
            if protocol_counts and len(protocol_counts) > 0:
                proto_df = pd.DataFrame(list(protocol_counts.items()), columns=['Protocol', 'Count'])
                title = params[2].strip() if len(params) > 2 else 'Protocol Distribution'
                if chart_type == 'bar':
                    fig = generate_chart('bar', proto_df, x_col='Protocol', y_col='Count', title=title)
                else:
                    fig = generate_chart('pie', proto_df, names_col='Protocol', values_col='Count', title=title)
                return fig
            else:
                return None

        use_count = False
        y_param = None
        if len(params) >= 2:
            y_val = params[1].strip().lower()
            if y_val in ['count', 'counts', 'number', 'frequency']:
                use_count = True
            else:
                y_param = params[1].strip()

        if chart_type in ['bar', 'pie', 'line', 'scatter', 'area']:
            x_col = map_column(params[0].strip(), df.columns)
            if x_col is None: return None
            y_col = map_column(y_param, df.columns) if y_param else None
            title = params[2].strip() if len(params) > 2 else None

            if (chart_type in ['bar', 'pie']) and (y_col is None or use_count):
                if x_col in df.columns and df[x_col].apply(lambda x: isinstance(x, list)).any():
                    exploded = df.explode(x_col)[x_col].dropna()
                    if exploded.empty: return None
                    counts = exploded.value_counts().reset_index()
                    counts.columns = [x_col, 'count']
                else:
                    counts = df[x_col].value_counts().reset_index()
                    counts.columns = [x_col, 'count']
                if counts.empty: return None
                if chart_type == 'bar':
                    fig = generate_chart('bar', counts, x_col=x_col, y_col='count', title=title)
                else:
                    fig = generate_chart('pie', counts, names_col=x_col, values_col='count', title=title)
                return fig
            else:
                data = prepare_chart_data(df, x_col, y_col)
                if data.empty: return None
                if chart_type == 'bar':
                    fig = generate_chart('bar', data, x_col=x_col, y_col=y_col, title=title)
                elif chart_type == 'pie':
                    if y_col and data[y_col].dtype in ['int64', 'float64']:
                        fig = generate_chart('pie', data, names_col=x_col, values_col=y_col, title=title)
                    else:
                        counts = data[x_col].value_counts().reset_index()
                        counts.columns = [x_col, 'count']
                        fig = generate_chart('pie', counts, names_col=x_col, values_col='count', title=title)
                elif chart_type == 'line':
                    fig = generate_chart('line', data, x_col=x_col, y_col=y_col, title=title)
                elif chart_type == 'scatter':
                    color_col = map_column(params[2].strip(), df.columns) if len(params) > 2 else None
                    fig = generate_chart('scatter', data, x_col=x_col, y_col=y_col, color_col=color_col, title=title)
                elif chart_type == 'area':
                    fig = generate_chart('area', data, x_col=x_col, y_col=y_col, title=title)
                else: return None
                return fig
        else:
            # Other chart types not used in auto dashboard; return None
            return None
    except Exception:
        return None

# ------------------ Main app flow ------------------
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file and not st.session_state.analysis_complete:
    file_size_mb = uploaded_file.size / (1024 * 1024)
    if file_size_mb > 500:
        st.error(f"File too large ({file_size_mb:.1f} MB). Please use a smaller file.")
        st.stop()
    if file_size_mb > 200:
        st.warning(f"Large file ({file_size_mb:.1f} MB). Processing limited to {max_packets} packets.")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    with st.spinner(f"Analyzing PCAP (max {max_packets} packets)..."):
        ip_data = analyze_pcap(tmp_path, max_packets=max_packets)

    with st.spinner("Classifying assets..."):
        classified = []
        for ip, data in ip_data.items():
            classified.append(classify_asset(data, None))
    st.session_state.assets_df = pd.DataFrame(classified)
    cols = ["ip", "asset_type", "confidence", "vendor", "ports", "hostnames", "ot_protocols",
            "os", "firmware_version", "model_number", "http_user_agents", "dns_queries",
            "snmp_communities", "cves"]
    st.session_state.assets_df = st.session_state.assets_df[cols]

    protocol_counts = {}
    for ip, data in ip_data.items():
        for proto in data["ot_protocols"]:
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    st.session_state.protocol_counts = protocol_counts

    st.session_state.analysis_complete = True
    os.unlink(tmp_path)
    st.rerun()

if st.session_state.analysis_complete:
    df_assets = st.session_state.assets_df

    if nvd_api_key and "vulnerabilities" not in df_assets.columns:
        with st.spinner("Enriching assets with vulnerability data (NVD, EPSS, KEV)..."):
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
        # ICS Advisory Upload (replaces the HTML dashboard)
        st.subheader("📄 ICS‑CERT Advisory Upload")
        ics_file = st.file_uploader("Upload ICS Advisory Excel/CSV file", type=["csv", "xlsx"])
        if ics_file:
            try:
                if ics_file.name.endswith('.csv'):
                    df_ics = pd.read_csv(ics_file)
                else:
                    df_ics = pd.read_excel(ics_file, engine='openpyxl')
                st.session_state.ics_advisory_df = df_ics
                st.success(f"Loaded {len(df_ics)} advisories.")
            except Exception as e:
                st.error(f"Failed to parse file: {e}")

        if st.session_state.ics_advisory_df is not None:
            df_ics = st.session_state.ics_advisory_df
            st.subheader("🔍 Search ICS Advisories")
            search_term = st.text_input("Search by CVE, Vendor, Product, or Title")
            if search_term:
                mask = df_ics.apply(lambda row: row.astype(str).str.contains(search_term, case=False).any(), axis=1)
                filtered = df_ics[mask]
                st.dataframe(filtered, use_container_width=True)
            else:
                st.dataframe(df_ics, use_container_width=True)

    # AI Assistant and Auto Dashboard
    st.markdown("---")
    st.subheader("🤖 AI Assistant")
    st.markdown("Ask about the assets, vulnerabilities, or request a chart or dashboard.")

    # Build context (includes EPSS/KEV data from asset enrichment)
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

    if st.session_state.protocol_counts:
        proto_text = "\n\nProtocol Distribution (packet count per detected OT protocol):\n"
        for proto, count in st.session_state.protocol_counts.items():
            proto_text += f"- {proto}: {count} packets\n"
        context += proto_text

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

    if st.session_state.ics_advisory_df is not None:
        ics_df = st.session_state.ics_advisory_df
        if not ics_df.empty:
            ics_sample = ics_df.head(20)
            ics_text = "\n\nICS‑CERT Advisories (first 20):\n"
            for _, row in ics_sample.iterrows():
                cve = row.get('CVE_Number', '')
                title = row.get('ICS-CERT_Advisory_Title', '')
                vendor = row.get('Vendor', '')
                product = row.get('Product', '')
                severity = row.get('CVSS_Severity', '')
                ics_text += f"- {cve}: {title} (Vendor: {vendor}, Product: {product}, Severity: {severity})\n"
            context += ics_text

    # Auto Dashboard button
    if st.button("📊 Generate Auto Dashboard"):
        auto_charts = generate_auto_dashboard(df_assets, st.session_state.protocol_counts)
        if auto_charts:
            st.session_state.dashboard_definition = {
                'title': 'Auto‑Generated Dashboard',
                'charts': auto_charts
            }
            st.success("Dashboard generated! Scroll down to view.")
        else:
            st.warning("Not enough data to generate a dashboard. Try uploading a PCAP with more assets.")

    # Manual AI query
    user_question = st.text_area("Ask a question, request a chart, or ask for a dashboard (e.g., 'Show me protocol distribution')")
    if st.button("Ask AI") and user_question:
        with st.spinner("Thinking..."):
            # Auto‑fetch CVEs mentioned in the question (using NVD, EPSS, KEV)
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

            answer = ask_ai(user_question, context, gemini_api_key=gemini_api_key)

            # Check for DASHBOARD command
            if answer.strip().upper().startswith("DASHBOARD:"):
                parts = answer.split('|', 1)
                if len(parts) >= 2:
                    title = parts[0].replace("DASHBOARD:", "").strip()
                    charts_str = parts[1]
                    chart_specs = [spec.strip() for spec in charts_str.split(';') if spec.strip()]
                    dashboard_charts = []
                    for spec in chart_specs:
                        parsed = parse_chart_spec(spec)
                        if parsed:
                            dashboard_charts.append(parsed)
                    st.session_state.dashboard_definition = {
                        'title': title,
                        'charts': dashboard_charts
                    }
                    st.success(f"Dashboard '{title}' created! It will appear below.")
                else:
                    st.write(answer)
            else:
                # Check for single CHART command
                chart_line = None
                for line in answer.split('\n'):
                    if line.strip().upper().startswith('CHART:'):
                        chart_line = line.strip()
                        break
                if chart_line:
                    spec_str = chart_line[6:].strip()
                    chart_spec = parse_chart_spec(spec_str)
                    if chart_spec:
                        fig = render_chart(chart_spec, df_assets, st.session_state.protocol_counts)
                        if fig:
                            st.plotly_chart(fig, use_container_width=True)
                        else:
                            st.write("Could not generate chart (missing data or invalid columns).")
                    else:
                        st.write(answer)
                else:
                    st.markdown("**AI Response:**")
                    st.write(answer)

    # Display the dashboard if it exists (after AI or auto‑generated)
    if st.session_state.dashboard_definition:
        st.markdown("---")
        dash = st.session_state.dashboard_definition
        if not logo_url:
            st.header(f"📊 {dash['title']} Dashboard")
        else:
            st.markdown("### Dashboard")
        if logo_url:
            st.image(logo_url, width=200)

        if st.button("🗑️ Clear Dashboard"):
            st.session_state.dashboard_definition = None
            st.rerun()

        if not dash['charts']:
            st.warning("Dashboard definition contains no charts.")
        else:
            cols = st.columns(2)
            rendered_count = 0
            for i, chart_spec in enumerate(dash['charts']):
                with cols[i % 2]:
                    fig = render_chart(chart_spec, df_assets, st.session_state.protocol_counts)
                    if fig:
                        st.plotly_chart(fig, use_container_width=True)
                        rendered_count += 1
            if rendered_count == 0:
                st.info("No charts could be rendered from the dashboard definition. Try generating an auto dashboard.")
