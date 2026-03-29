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

st.set_page_config(page_title="AI PCAP Analyzer - OT Asset Intelligence", layout="wide")
st.title("🛡️ AI PCAP Analyzer with OT Asset Classification & Vulnerability Intelligence")

# API keys
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
groq_api_key = st.secrets.get("GROQ_API_KEY", os.getenv("GROQ_API_KEY"))

# Logo URL (optional)
logo_url = st.secrets.get("LOGO_URL", None)

# Sidebar settings
with st.sidebar:
    if logo_url:
        st.image(logo_url, width=150)
    else:
        st.markdown("## 📊 OT Security Dashboard")
    st.markdown("---")
    max_packets = st.slider(
        "Max packets to analyze (performance control)",
        min_value=1000,
        max_value=200000,
        value=50000,
        step=5000,
        help="Larger values give better coverage but use more memory/time. For files > 200 MB, reduce to avoid memory issues."
    )
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
if 'dashboard_definition' not in st.session_state:
    st.session_state.dashboard_definition = None  # {title: str, charts: list}

# ------------------ Helper functions ------------------
def prepare_chart_data(df, *cols):
    data = df.copy()
    for col in cols:
        if col and col in data.columns and data[col].apply(lambda x: isinstance(x, list)).any():
            data[col] = data[col].apply(len)
    return data

def map_column(label, df_columns):
    if not label:
        return None
    label_clean = label.lower().replace(' ', '_').replace('-', '_')
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

def render_chart(spec, df):
    chart_type = spec['type']
    params = spec['params']
    try:
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
                if None in path:
                    raise ValueError("One or more path columns not found.")
                values = map_column(params[1].strip(), df.columns) if len(params) > 1 else None
                title = params[2].strip() if len(params) > 2 else None
                data = prepare_chart_data(df, *path, values)
                fig = generate_chart('sunburst', data, path=path, values=values, title=title)
                return fig

        elif chart_type == 'treemap':
            if len(params) >= 1:
                path_str = params[0].strip()
                path = [map_column(p.strip(), df.columns) for p in path_str.split(',') if p.strip()]
                if None in path:
                    raise ValueError("One or more path columns not found.")
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
        # Existing two‑column layout
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Search by CVE ID")
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
        with col2:
            st.markdown("#### Search by Keyword")
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

        # New: Interactive CVE Dashboard (embedded HTML)
        with st.expander("📊 Interactive CVE Dashboard (HTML)", expanded=False):
            # Full HTML content from the provided file
            # (We embed it directly as a raw string for simplicity)
            html_content = r"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Enterprise CVE Risk Dashboard | NIST NVD</title>
                <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
                <script src="https://cdn.sheetjs.com/xlsx-0.20.2/package/dist/xlsx.full.min.js"></script>
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
                <style>
                    * { margin: 0; padding: 0; box-sizing: border-box; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
                    body { background: #f0f2f5; color: #1e293b; line-height: 1.5; }
                    .dashboard { max-width: 1600px; margin: 0 auto; padding: 2rem; }
                    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; }
                    .logo h1 { font-size: 1.8rem; font-weight: 600; background: linear-gradient(135deg, #2563eb, #1e40af); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
                    .badge { background: #dbeafe; color: #1e40af; padding: 0.5rem 1rem; border-radius: 100px; font-size: 0.9rem; font-weight: 500; display: flex; align-items: center; gap: 0.5rem; }
                    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1.5rem; margin-bottom: 2rem; }
                    .stat-card { background: white; padding: 1.5rem; border-radius: 1rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); display: flex; align-items: center; gap: 1rem; }
                    .stat-icon { width: 48px; height: 48px; background: #eef2ff; border-radius: 12px; display: flex; align-items: center; justify-content: center; color: #2563eb; font-size: 1.5rem; }
                    .stat-content h3 { font-size: 0.9rem; font-weight: 500; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
                    .stat-content .value { font-size: 2rem; font-weight: 700; color: #0f172a; line-height: 1.2; }
                    .input-panel { background: white; border-radius: 1rem; padding: 2rem; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); margin-bottom: 2rem; }
                    .panel-title { font-size: 1.2rem; font-weight: 600; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 0.5rem; }
                    .input-methods { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }
                    .method { border: 1px solid #e2e8f0; border-radius: 0.75rem; padding: 1.5rem; }
                    .method h3 { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: #334155; }
                    .method textarea { width: 100%; height: 120px; padding: 0.75rem; border: 1px solid #cbd5e1; border-radius: 0.5rem; font-family: inherit; resize: vertical; margin-bottom: 1rem; }
                    .method textarea:focus { outline: none; border-color: #2563eb; ring: 2px solid #bfdbfe; }
                    .file-upload { display: flex; flex-direction: column; gap: 1rem; }
                    .file-upload label { display: flex; align-items: center; justify-content: center; gap: 0.5rem; padding: 0.75rem; background: #f8fafc; border: 2px dashed #cbd5e1; border-radius: 0.5rem; cursor: pointer; transition: all 0.2s; }
                    .file-upload label:hover { border-color: #2563eb; background: #eff6ff; }
                    .file-upload input { display: none; }
                    .api-key-row { display: flex; align-items: center; gap: 1rem; margin: 1.5rem 0 1rem; }
                    .api-key-row input { flex: 1; padding: 0.75rem 1rem; border: 1px solid #cbd5e1; border-radius: 0.5rem; font-family: inherit; }
                    .btn-primary { background: #2563eb; color: white; border: none; padding: 0.75rem 2rem; border-radius: 0.5rem; font-weight: 600; cursor: pointer; transition: background 0.2s; display: inline-flex; align-items: center; gap: 0.5rem; }
                    .btn-primary:hover { background: #1d4ed8; }
                    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
                    .chart-container { background: white; border-radius: 1rem; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); display: flex; align-items: center; gap: 2rem; }
                    .chart-box { width: 200px; height: 200px; position: relative; }
                    .severity-legend { flex: 1; display: flex; flex-direction: column; gap: 0.75rem; }
                    .legend-item { display: flex; align-items: center; gap: 0.5rem; font-size: 0.95rem; }
                    .color-dot { width: 12px; height: 12px; border-radius: 50%; }
                    .table-container { background: white; border-radius: 1rem; padding: 1.5rem; box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1); overflow-x: auto; }
                    .table-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.5rem; }
                    .table-header h2 { font-size: 1.2rem; font-weight: 600; }
                    .search-box { display: flex; align-items: center; gap: 0.5rem; border: 1px solid #e2e8f0; border-radius: 0.5rem; padding: 0.5rem 1rem; }
                    .search-box i { color: #94a3b8; }
                    .search-box input { border: none; outline: none; background: transparent; }
                    table { width: 100%; border-collapse: collapse; }
                    th { text-align: left; padding: 1rem 0.5rem; color: #64748b; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e2e8f0; }
                    td { padding: 1rem 0.5rem; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
                    .asset-tag { background: #f1f5f9; padding: 0.25rem 0.75rem; border-radius: 100px; font-size: 0.85rem; font-weight: 500; display: inline-block; }
                    .cve-id { font-weight: 600; color: #2563eb; text-decoration: none; }
                    .cve-id:hover { text-decoration: underline; }
                    .severity-badge { padding: 0.25rem 0.75rem; border-radius: 100px; font-size: 0.85rem; font-weight: 600; display: inline-block; }
                    .severity-critical { background: #7f1d1d; color: #fee2e2; }
                    .severity-high { background: #991b1b; color: #fee2e2; }
                    .severity-medium { background: #b45309; color: #fffbeb; }
                    .severity-low { background: #065f46; color: #d1fae5; }
                    .vuln-desc { max-width: 300px; max-height: 60px; overflow-y: auto; font-size: 0.9rem; color: #334155; }
                    .mitigation-link { color: #2563eb; text-decoration: none; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 0.25rem; }
                    .mitigation-link:hover { text-decoration: underline; }
                    .loading-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(255,255,255,0.8); backdrop-filter: blur(2px); z-index: 1000; justify-content: center; align-items: center; flex-direction: column; gap: 1rem; }
                    .loading-spinner { border: 4px solid #f3f3f3; border-top: 4px solid #2563eb; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; }
                    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
                    .error-message { background: #fee2e2; color: #991b1b; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }
                </style>
            </head>
            <body>
                <div class="dashboard">
                    <div class="header">
                        <div class="logo"><h1><i class="fas fa-shield-halved" style="margin-right: 0.5rem;"></i>VulnRisk Dashboard</h1></div>
                        <div class="badge"><i class="fas fa-database"></i> NIST NVD v2.0</div>
                    </div>
                    <div class="stats-grid" id="statsGrid">
                        <div class="stat-card"><div class="stat-icon"><i class="fas fa-bug"></i></div><div class="stat-content"><h3>Total CVEs</h3><div class="value" id="totalCves">0</div></div></div>
                        <div class="stat-card"><div class="stat-icon"><i class="fas fa-exclamation-triangle"></i></div><div class="stat-content"><h3>Critical</h3><div class="value" id="criticalCount">0</div></div></div>
                        <div class="stat-card"><div class="stat-icon"><i class="fas fa-chart-line"></i></div><div class="stat-content"><h3>High</h3><div class="value" id="highCount">0</div></div></div>
                        <div class="stat-card"><div class="stat-icon"><i class="fas fa-shield"></i></div><div class="stat-content"><h3>Assets Scanned</h3><div class="value" id="assetCount">0</div></div></div>
                    </div>
                    <div class="input-panel">
                        <div class="panel-title"><i class="fas fa-magnifying-glass"></i> Vulnerability Assessment</div>
                        <div class="input-methods">
                            <div class="method">
                                <h3><i class="fas fa-keyboard"></i> Manual Asset List</h3>
                                <textarea id="assetTextarea" placeholder="Enter one asset per line (e.g.,&#10;apache log4j&#10;windows server 2019&#10;CVE-2024-1234">apache log4j
windows server 2019</textarea>
                            </div>
                            <div class="method">
                                <h3><i class="fas fa-file-excel"></i> Import from File</h3>
                                <div class="file-upload"><label for="fileInput"><i class="fas fa-cloud-upload-alt"></i> Click to upload Excel or CSV</label><input type="file" id="fileInput" accept=".csv, .xls, .xlsx"><p style="font-size:0.9rem; color:#64748b;">File should contain one asset per row (first column used).</p></div>
                            </div>
                        </div>
                        <div class="api-key-row"><i class="fas fa-key"></i><input type="password" id="apiKey" placeholder="NVD API Key (optional, increases rate limit)"><button class="btn-primary" id="searchBtn"><i class="fas fa-search"></i> Find CVEs</button></div>
                        <div id="inputError" class="error-message" style="display: none;"></div>
                    </div>
                    <div class="chart-container" id="chartContainer" style="display: none;">
                        <div class="chart-box"><canvas id="severityChart"></canvas></div>
                        <div class="severity-legend" id="severityLegend"></div>
                    </div>
                    <div class="table-container">
                        <div class="table-header"><h2><i class="fas fa-list"></i> Discovered Vulnerabilities</h2><div class="search-box"><i class="fas fa-filter"></i><input type="text" id="tableFilter" placeholder="Filter by asset, CVE..."></div></div>
                        <div style="overflow-x: auto;"><table id="resultsTable"><thead><tr><th>Asset</th><th>CVE ID</th><th>Risk (CVSS)</th><th>Vulnerability</th><th>Mitigation / Advisory</th></tr></thead><tbody id="tableBody"><tr><td colspan="5" style="text-align:center; padding:3rem;">No data. Enter assets and click search.</td></tr></tbody></table></div>
                    </div>
                </div>
                <div class="loading-overlay" id="loadingOverlay"><div class="loading-spinner"></div><div style="font-weight:600;">Querying NVD, please wait...</div></div>
                <script>
                    let allResults = [];
                    let severityChart = null;
                    const assetTextarea = document.getElementById('assetTextarea');
                    const fileInput = document.getElementById('fileInput');
                    const apiKeyInput = document.getElementById('apiKey');
                    const searchBtn = document.getElementById('searchBtn');
                    const loadingOverlay = document.getElementById('loadingOverlay');
                    const inputError = document.getElementById('inputError');
                    const tableBody = document.getElementById('tableBody');
                    const totalCvesSpan = document.getElementById('totalCves');
                    const criticalCountSpan = document.getElementById('criticalCount');
                    const highCountSpan = document.getElementById('highCount');
                    const assetCountSpan = document.getElementById('assetCount');
                    const chartContainer = document.getElementById('chartContainer');
                    const tableFilter = document.getElementById('tableFilter');
                    function hideError() { inputError.style.display = 'none'; }
                    function showError(msg) { inputError.textContent = msg; inputError.style.display = 'block'; }
                    fileInput.addEventListener('change', (e) => {
                        const file = e.target.files[0];
                        if (!file) return;
                        const reader = new FileReader();
                        reader.onload = (loadEvent) => {
                            try {
                                const data = new Uint8Array(loadEvent.target.result);
                                const workbook = XLSX.read(data, { type: 'array' });
                                const firstSheet = workbook.Sheets[workbook.SheetNames[0]];
                                const rows = XLSX.utils.sheet_to_json(firstSheet, { header: 1, defval: '' });
                                const assets = [];
                                for (let i = 0; i < rows.length; i++) {
                                    if (rows[i].length > 0 && rows[i][0].toString().trim() !== '') {
                                        assets.push(rows[i][0].toString().trim());
                                    }
                                }
                                if (assets.length > 0) assetTextarea.value = assets.join('\\n');
                                else showError('No valid asset names found in file.');
                            } catch (err) { showError('Failed to parse file: ' + err.message); }
                        };
                        reader.readAsArrayBuffer(file);
                    });
                    function getSeverityInfo(metrics) {
                        if (!metrics) return { severity: 'Unknown', score: null, vector: null, class: '' };
                        let cvssData = null, version = null;
                        if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) { cvssData = metrics.cvssMetricV31[0].cvssData; version = 'V3.1'; }
                        else if (metrics.cvssMetricV30 && metrics.cvssMetricV30.length > 0) { cvssData = metrics.cvssMetricV30[0].cvssData; version = 'V3.0'; }
                        else if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) { cvssData = metrics.cvssMetricV2[0].cvssData; version = 'V2.0'; }
                        if (!cvssData) return { severity: 'N/A', score: null, vector: null, class: '' };
                        const score = cvssData.baseScore;
                        let severity = cvssData.baseSeverity || (score >= 7.0 ? 'HIGH' : (score >= 4.0 ? 'MEDIUM' : 'LOW'));
                        severity = severity ? severity.charAt(0).toUpperCase() + severity.slice(1).toLowerCase() : 'Unknown';
                        let severityClass = '';
                        if (severity === 'Critical') severityClass = 'severity-critical';
                        else if (severity === 'High') severityClass = 'severity-high';
                        else if (severity === 'Medium') severityClass = 'severity-medium';
                        else if (severity === 'Low') severityClass = 'severity-low';
                        let vector = cvssData.vectorString || '';
                        if (vector && version) vector = `${version} ${vector}`;
                        return { severity, score, vector, class: severityClass };
                    }
                    function getFirstReference(references) {
                        if (!references || references.length === 0) return null;
                        for (let ref of references) if (ref.tags && ref.tags.includes('Vendor Advisory')) return ref.url;
                        return references[0].url;
                    }
                    async function fetchForAsset(asset, apiKey) {
                        const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
                        url.searchParams.append('keywordSearch', asset);
                        url.searchParams.append('resultsPerPage', 20);
                        const headers = {};
                        if (apiKey.trim()) headers['apiKey'] = apiKey.trim();
                        const response = await fetch(url, { headers });
                        if (!response.ok) {
                            if (response.status === 403) throw new Error('Invalid API key or rate limited. Try without key.');
                            if (response.status === 429) throw new Error('Rate limit exceeded. Wait or use API key.');
                            throw new Error(`HTTP ${response.status}`);
                        }
                        const data = await response.json();
                        return (data.vulnerabilities || []).map(v => v.cve);
                    }
                    async function onSearch() {
                        hideError();
                        const rawAssets = assetTextarea.value.split('\\n').map(line => line.trim()).filter(line => line.length > 0);
                        if (rawAssets.length === 0) { showError('Please enter at least one asset.'); return; }
                        const apiKey = apiKeyInput.value;
                        loadingOverlay.style.display = 'flex';
                        searchBtn.disabled = true;
                        allResults = [];
                        for (const asset of rawAssets) {
                            try {
                                const cves = await fetchForAsset(asset, apiKey);
                                for (const cve of cves) {
                                    const id = cve.id;
                                    const description = cve.descriptions?.find(d => d.lang === 'en')?.value || 'No description';
                                    const metrics = cve.metrics;
                                    const { severity, score, vector, class: sevClass } = getSeverityInfo(metrics);
                                    const mitigationUrl = getFirstReference(cve.references);
                                    allResults.push({ asset, cveId: id, description, severity, score, vector, mitigationUrl, sevClass });
                                }
                                await new Promise(resolve => setTimeout(resolve, apiKey.trim() ? 600 : 6000));
                            } catch (err) { showError(`Asset "${asset}": ${err.message}`); }
                        }
                        loadingOverlay.style.display = 'none';
                        searchBtn.disabled = false;
                        renderResults();
                    }
                    function renderResults() {
                        const total = allResults.length;
                        const critical = allResults.filter(r => r.severity === 'Critical').length;
                        const high = allResults.filter(r => r.severity === 'High').length;
                        const assets = new Set(allResults.map(r => r.asset)).size;
                        totalCvesSpan.textContent = total;
                        criticalCountSpan.textContent = critical;
                        highCountSpan.textContent = high;
                        assetCountSpan.textContent = assets;
                        if (total === 0) {
                            tableBody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding:3rem;">No vulnerabilities found. Try different assets.</td></tr>';
                            chartContainer.style.display = 'none';
                            return;
                        }
                        let html = '';
                        allResults.forEach(r => {
                            const severityDisplay = r.vector ? `${r.severity} (${r.score})<br><small>${r.vector}</small>` : (r.severity + (r.score ? ` (${r.score})` : ''));
                            const mitigationLink = r.mitigationUrl ? `<a href="${r.mitigationUrl}" target="_blank" class="mitigation-link"><i class="fas fa-external-link-alt"></i> Advisory</a>` : 'N/A';
                            html += `<tr><td><span class="asset-tag">${escapeHtml(r.asset)}</span></td><td><a href="https://nvd.nist.gov/vuln/detail/${r.cveId}" target="_blank" class="cve-id">${r.cveId}</a></td><td><span class="severity-badge ${r.sevClass}">${severityDisplay}</span></td><td><div class="vuln-desc">${escapeHtml(r.description)}</div></td><td>${mitigationLink}</td></tr>`;
                        });
                        tableBody.innerHTML = html;
                        chartContainer.style.display = 'flex';
                        updateChart();
                        tableFilter.addEventListener('input', filterTable);
                    }
                    function escapeHtml(unsafe) { return unsafe.replace(/[&<>"']/g, function(m) { if(m === '&') return '&amp;'; if(m === '<') return '&lt;'; if(m === '>') return '&gt;'; if(m === '"') return '&quot;'; return '&#039;'; }); }
                    function filterTable() { const filter = tableFilter.value.toLowerCase(); document.querySelectorAll('#tableBody tr').forEach(row => { row.style.display = row.innerText.toLowerCase().includes(filter) ? '' : 'none'; }); }
                    function updateChart() {
                        const ctx = document.getElementById('severityChart').getContext('2d');
                        const counts = { Critical: allResults.filter(r => r.severity === 'Critical').length, High: allResults.filter(r => r.severity === 'High').length, Medium: allResults.filter(r => r.severity === 'Medium').length, Low: allResults.filter(r => r.severity === 'Low').length, Unknown: allResults.filter(r => !r.severity || r.severity === 'N/A' || r.severity === 'Unknown').length };
                        if (severityChart) severityChart.destroy();
                        severityChart = new Chart(ctx, { type: 'doughnut', data: { labels: Object.keys(counts), datasets: [{ data: Object.values(counts), backgroundColor: ['#7f1d1d', '#991b1b', '#b45309', '#065f46', '#64748b'], borderWidth: 0 }] }, options: { cutout: '70%', plugins: { legend: { display: false }, tooltip: { callbacks: { label: (ctx) => `${ctx.label}: ${ctx.raw}` } } } } });
                        const legendDiv = document.getElementById('severityLegend');
                        legendDiv.innerHTML = Object.entries(counts).map(([sev, cnt]) => `<div class="legend-item"><span class="color-dot" style="background: ${sev === 'Critical'?'#7f1d1d': sev==='High'?'#991b1b': sev==='Medium'?'#b45309': sev==='Low'?'#065f46':'#64748b'}"></span><span><strong>${sev}</strong>: ${cnt}</span></div>`).join('');
                    }
                    searchBtn.addEventListener('click', onSearch);
                </script>
            </body>
            </html>
            """
            st.components.v1.html(html_content, height=900, scrolling=True)

    # AI Assistant (chat interface) – unchanged
    if groq_api_key:
        st.markdown("---")
        st.subheader("🤖 AI Assistant (Powered by Groq)")
        st.markdown("Ask about the assets, vulnerabilities, or request a single chart or a full dashboard.")

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

        user_question = st.text_area("Ask a question, request a chart, or ask for a dashboard (e.g., 'Create a security dashboard')")
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
                            fig = render_chart(chart_spec, df_assets)
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
                        fig = render_chart(chart_spec, df_assets)
                        if fig:
                            st.plotly_chart(fig, use_container_width=True)
                            rendered_count += 1
                        else:
                            st.warning(f"Could not render chart: {chart_spec}")
                if rendered_count == 0:
                    st.error("No charts could be rendered. Please request a new dashboard with columns that exist in the asset data (e.g., 'asset_type', 'vendor', 'os').")
    else:
        st.error("Groq API key not configured. Add GROQ_API_KEY to secrets to use the AI assistant.")
