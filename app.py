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
from chatbot import ask_ai  # Now using Gemini version (chatbot.py)
from chart_generator import generate_chart

load_dotenv()
utils.init_db()

# ------------------ Custom CSS for Deloitte dark green theme ------------------
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
    /* Dashboard container */
    .dashboard-container {
        background-color: #0A2F2F;
        border-radius: 1rem;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="AI PCAP Analyzer - Deloitte OT Intelligence", layout="wide")
st.title("🛡️ Deloitte OT Security Analyzer")

# API keys (NVD + Gemini)
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
gemini_api_key = st.secrets.get("GEMINI_API_KEY", os.getenv("GEMINI_API_KEY"))

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
    st.markdown("**AI Assistant:** Powered by Google Gemini (free tier).")

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
if 'ics_advisory_df' not in st.session_state:
    st.session_state.ics_advisory_df = None

# ------------------ Helper functions (unchanged) ------------------
def prepare_chart_data(df, *cols):
    data = df.copy()
    for col in cols:
        if col and col in data.columns and data[col].apply(lambda x: isinstance(x, list)).any():
            data[col] = data[col].apply(len)
    return data

def map_column(label, df_columns):
    if not label or not isinstance(label, str):
        return None
    label_clean = label.lower().replace(' ', '_').replace('-', '_')
    if ',' in label_clean:
        return None
    if label_clean in df_columns:
        return label_clean
    for col in df_columns:
        if label_clean in col or col in label_clean:
            return col
    special = {
        'ip_address': 'ip', 'ipaddr': 'ip', 'ip': 'ip',
        'asset_type': 'asset_type', 'assettype': 'asset_type',
        'vendor': 'vendor', 'ports': 'ports', 'port': 'ports',
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
    if len(parts) < 2:
        return None
    raw_type = parts[0].strip()
    if ',' in raw_type:
        raw_type = raw_type.split(',')[0].strip()
    chart_type = raw_type.lower()
    if chart_type == 'map':
        chart_type = 'scatter_map'
    elif chart_type == 'scattergeo':
        chart_type = 'scatter_map'
    return {'type': chart_type, 'params': parts[1:]}

def render_chart(spec, df, protocol_counts=None):
    chart_type = spec['type']
    params = spec['params']
    try:
        # Special handling for protocol distribution
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
                st.warning("No protocol data available for this chart.")
                return None

        # General case
        use_count = False
        y_param = None
        if len(params) >= 2:
            y_val = params[1].strip().lower()
            if y_val in ['count', 'counts', 'number']:
                use_count = True
            else:
                y_param = params[1].strip()

        if chart_type in ['bar', 'pie', 'line', 'scatter', 'area']:
            x_col = map_column(params[0].strip(), df.columns)
            if x_col is None:
                raise ValueError(f"Column '{params[0]}' not found.")
            y_col = map_column(y_param, df.columns) if y_param else None
            title = params[2].strip() if len(params) > 2 else None

            if (chart_type in ['bar', 'pie']) and (y_col is None or use_count):
                counts = df[x_col].value_counts().reset_index()
                counts.columns = [x_col, 'count']
                if chart_type == 'bar':
                    fig = generate_chart('bar', counts, x_col=x_col, y_col='count', title=title)
                else:
                    fig = generate_chart('pie', counts, names_col=x_col, values_col='count', title=title)
                return fig
            else:
                data = prepare_chart_data(df, x_col, y_col)
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
                else:
                    return None
                return fig

        elif chart_type == 'histogram':
            column = map_column(params[0].strip(), df.columns)
            if column is None:
                raise ValueError(f"Column '{params[0]}' not found.")
            bins = int(params[1]) if len(params) > 1 and params[1].strip().isdigit() else 30
            title = params[2].strip() if len(params) > 2 else None
            data = prepare_chart_data(df, column)
            fig = generate_chart('histogram', data, column=column, bins=bins, title=title)
            return fig

        elif chart_type == 'box':
            column = map_column(params[0].strip(), df.columns)
            if column is None:
                raise ValueError(f"Column '{params[0]}' not found.")
            group = map_column(params[1].strip(), df.columns) if len(params) > 1 else None
            title = params[2].strip() if len(params) > 2 else None
            data = prepare_chart_data(df, column, group)
            fig = generate_chart('box', data, column=column, group_col=group, title=title)
            return fig

        elif chart_type == 'violin':
            column = map_column(params[0].strip(), df.columns)
            if column is None:
                raise ValueError(f"Column '{params[0]}' not found.")
            group = map_column(params[1].strip(), df.columns) if len(params) > 1 else None
            title = params[2].strip() if len(params) > 2 else None
            data = prepare_chart_data(df, column, group)
            fig = generate_chart('violin', data, column=column, group_col=group, title=title)
            return fig

        elif chart_type == 'heatmap':
            if len(params) >= 3:
                x_axis = map_column(params[0].strip(), df.columns)
                y_axis = map_column(params[1].strip(), df.columns)
                z_axis = map_column(params[2].strip(), df.columns)
                if None in (x_axis, y_axis, z_axis):
                    raise ValueError("One or more columns not found.")
                title = params[3].strip() if len(params) > 3 else None
                data = prepare_chart_data(df, x_axis, y_axis, z_axis)
                fig = generate_chart('heatmap', data, x_col=x_axis, y_col=y_axis, z_col=z_axis, title=title)
                return fig

        elif chart_type == 'density_heatmap':
            if len(params) >= 2:
                x_axis = map_column(params[0].strip(), df.columns)
                y_axis = map_column(params[1].strip(), df.columns)
                if None in (x_axis, y_axis):
                    raise ValueError("One or more columns not found.")
                title = params[2].strip() if len(params) > 2 else None
                data = prepare_chart_data(df, x_axis, y_axis)
                fig = generate_chart('density_heatmap', data, x_col=x_axis, y_col=y_axis, title=title)
                return fig

        elif chart_type == 'bubble':
            if len(params) >= 3:
                x_axis = map_column(params[0].strip(), df.columns)
                y_axis = map_column(params[1].strip(), df.columns)
                size_col = map_column(params[2].strip(), df.columns)
                if None in (x_axis, y_axis, size_col):
                    raise ValueError("One or more columns not found.")
                color_col = map_column(params[3].strip(), df.columns) if len(params) > 3 else None
                title = params[4].strip() if len(params) > 4 else None
                data = prepare_chart_data(df, x_axis, y_axis, size_col, color_col)
                fig = generate_chart('bubble', data, x_col=x_axis, y_col=y_axis, size_col=size_col,
                                     color_col=color_col, title=title)
                return fig

        elif chart_type == 'sunburst':
            if len(params) >= 1:
                path_str = params[0].strip()
                path = [map_column(p.strip(), df.columns) for p in path_str.split(',') if p.strip()]
                path = [p for p in path if p is not None]
                if not path:
                    raise ValueError("No valid path columns found.")
                values = map_column(params[1].strip(), df.columns) if len(params) > 1 else None
                title = params[2].strip() if len(params) > 2 else None
                data = prepare_chart_data(df, *path, values)
                fig = generate_chart('sunburst', data, path=path, values=values, title=title)
                return fig

        elif chart_type == 'treemap':
            if len(params) >= 1:
                path_str = params[0].strip()
                path = [map_column(p.strip(), df.columns) for p in path_str.split(',') if p.strip()]
                path = [p for p in path if p is not None]
                if not path:
                    raise ValueError("No valid path columns found.")
                values = map_column(params[1].strip(), df.columns) if len(params) > 1 else None
                title = params[2].strip() if len(params) > 2 else None
                data = prepare_chart_data(df, *path, values)
                fig = generate_chart('treemap', data, path=path, values=values, title=title)
                return fig

        elif chart_type == 'scatter_map':
            if len(params) >= 2:
                lat_col = map_column(params[0].strip(), df.columns)
                lon_col = map_column(params[1].strip(), df.columns)
                if None in (lat_col, lon_col):
                    if 'ip' in df.columns and (lat_col is None or lon_col is None):
                        df_temp = df.copy()
                        df_temp['lat'] = df_temp['ip'].apply(lambda x: random.uniform(-90, 90))
                        df_temp['lon'] = df_temp['ip'].apply(lambda x: random.uniform(-180, 180))
                        lat_col, lon_col = 'lat', 'lon'
                        st.info("Using random coordinates for map demonstration. For actual geolocation, integrate an IP geolocation service.")
                    else:
                        raise ValueError("Latitude/Longitude columns not found.")
                else:
                    df_temp = df
                color_col = map_column(params[2].strip(), df.columns) if len(params) > 2 else None
                size_col = map_column(params[3].strip(), df.columns) if len(params) > 3 else None
                title = params[4].strip() if len(params) > 4 else None
                data = prepare_chart_data(df_temp, lat_col, lon_col, color_col, size_col)
                fig = generate_chart('scatter_map', data, lat_col=lat_col, lon_col=lon_col,
                                     color_col=color_col, size_col=size_col, title=title)
                return fig

        elif chart_type == 'choropleth':
            raise ValueError("Choropleth maps require geographic location codes. The current data does not contain such columns. Try using a scatter_map for IP-based locations.")

        else:
            return None

    except Exception as e:
        st.error(f"Chart generation failed: {e}")
        return None

# ------------------ Main app flow ------------------
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file and not st.session_state.analysis_complete:
    # File size check
    file_size_mb = uploaded_file.size / (1024 * 1024)
    if file_size_mb > 200:
        st.warning(f"File size is {file_size_mb:.1f} MB. Processing will be limited to {max_packets} packets. For full analysis, consider reducing packet limit or using a smaller PCAP.")
    if file_size_mb > 500:
        st.error(f"File size {file_size_mb:.1f} MB exceeds recommended limit (500 MB). The app may crash. Please use a smaller file or increase packet limit at your own risk.")
        st.stop()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    with st.spinner(f"Analyzing PCAP (max {max_packets} packets)..."):
        ip_data = analyze_pcap(tmp_path, max_packets=max_packets)

    with st.spinner("Classifying assets..."):
        classified = []
        for ip, data in ip_data.items():
            classified.append(classify_asset(data, None))  # No AI fallback needed
    st.session_state.assets_df = pd.DataFrame(classified)
    cols = [
        "ip", "asset_type", "confidence", "vendor", "ports", "hostnames",
        "ot_protocols", "os", "firmware_version", "model_number",
        "http_user_agents", "dns_queries", "snmp_communities", "cves"
    ]
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

    # Vulnerability enrichment (per asset)
    if nvd_api_key and "vulnerabilities" not in df_assets.columns:
        with st.spinner("Enriching assets with vulnerability data (this may take a moment)..."):
            df_assets = enrich_assets_with_vulnerabilities(df_assets, nvd_api_key)
            st.session_state.assets_df = df_assets

    # Tabs: Asset Tables, Vulnerability Lookup
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
        # 1) Interactive CVE Dashboard (HTML)
        html_path = os.path.join(os.path.dirname(__file__), "cve_dashboard.html")
        if os.path.exists(html_path):
            with open(html_path, "r", encoding="utf-8") as f:
                html_content = f.read()
            st.markdown('<div class="dashboard-container">', unsafe_allow_html=True)
            st.components.v1.html(html_content, height=1000, scrolling=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.warning("Dashboard HTML file not found. Please add 'cve_dashboard.html' to the app directory.")

        # 2) ICS Advisory Upload and Search
        st.markdown("---")
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

    # AI Assistant (using Google Gemini)
    st.markdown("---")
    st.subheader("🤖 AI Assistant (Powered by Google Gemini)")
    st.markdown("Ask about the assets, vulnerabilities, or request a chart or dashboard.")

    # Build context (same as before)
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

    # Add ICS advisory data to context if present
    if st.session_state.ics_advisory_df is not None:
        ics_df = st.session_state.ics_advisory_df
        if not ics_df.empty:
            # Limit to first 20 to avoid huge context
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

    user_question = st.text_area("Ask a question, request a chart, or ask for a dashboard (e.g., 'Show me protocol distribution')")
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

            # Use Gemini
            answer = ask_ai(user_question, context, model="gemini-1.5-flash", gemini_api_key=gemini_api_key)

            with st.expander("Debug: Raw AI response"):
                st.code(answer)

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
                            st.write("Could not generate chart.")
                    else:
                        st.write(answer)
                else:
                    st.markdown("**AI Response:**")
                    st.write(answer)

    # Display the dashboard if it exists (after AI)
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
            with st.expander("Raw definition"):
                st.code(dash, language='json')
        else:
            cols = st.columns(2)
            rendered_count = 0
            for i, chart_spec in enumerate(dash['charts']):
                with cols[i % 2]:
                    fig = render_chart(chart_spec, df_assets, st.session_state.protocol_counts)
                    if fig:
                        st.plotly_chart(fig, use_container_width=True)
                        rendered_count += 1
                    else:
                        st.warning(f"Could not render chart: {chart_spec}")
            if rendered_count == 0:
                st.error("No charts could be rendered. Please request a new dashboard with columns that exist in the asset data (e.g., 'asset_type', 'vendor', 'os').")
