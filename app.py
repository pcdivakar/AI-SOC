import streamlit as st
import os
import tempfile
import pandas as pd
from dotenv import load_dotenv
import utils
from pcap_analyzer import analyze_pcap
from asset_classifier import classify_asset
from vulnerability import fetch_nvd, fetch_epss, fetch_kev_status

load_dotenv()
utils.init_db()

st.set_page_config(page_title="AI PCAP Analyzer - OT Asset Intelligence", layout="wide")
st.title("🛡️ AI PCAP Analyzer with OT Asset Classification & Vulnerability Intelligence")

# Get API keys
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
hf_token = st.secrets.get("HF_API_TOKEN", os.getenv("HF_API_TOKEN"))

with st.sidebar:
    st.header("Configuration")
    if not nvd_api_key:
        st.warning("NVD API key not set. NVD queries may fail.")
    if not hf_token:
        st.info("Hugging Face token not set. AI classification disabled.")
    st.markdown("---")
    st.markdown("Upload a PCAP file to see asset classification and vulnerability data.")
    st.markdown("**Supported OT protocols**: Modbus, S7, DNP3, BACnet, EtherNet/IP, IEC 104, OPC UA, CODESYS, Profinet, EtherCAT, CANopen, MQTT, IEC 61850, and more.")

uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    with st.spinner("Analyzing PCAP..."):
        ip_data = analyze_pcap(tmp_path)

    st.success(f"Analyzed {len(ip_data)} unique IPs")

    # Classify each IP
    with st.spinner("Classifying assets..."):
        classified = []
        for ip, data in ip_data.items():
            asset = classify_asset(data, hf_token)
            classified.append(asset)

    df_assets = pd.DataFrame(classified)
    # Reorder columns for readability
    cols = ["ip", "asset_type", "confidence", "vendor", "ports", "hostnames", "ot_protocols", "http_user_agents", "dns_queries", "snmp_communities"]
    df_assets = df_assets[cols]

    # Show OT assets first
    st.subheader("🏭 OT/ICS Assets")
    ot_mask = df_assets["ot_protocols"].apply(lambda x: len(x) > 0)
    ot_assets = df_assets[ot_mask]
    if not ot_assets.empty:
        st.dataframe(ot_assets, use_container_width=True)
    else:
        st.info("No OT/ICS protocols detected.")

    # Show all assets
    st.subheader("📡 All Detected Assets")
    st.dataframe(df_assets, use_container_width=True)

    # Vulnerability enrichment (optional)
    if nvd_api_key:
        st.subheader("🔍 Vulnerability Enrichment")
        all_cves = set()
        # Simple: we could search NVD for known software versions, but for demo we rely on user input
        # Alternatively, we can let user select IP to query
        selected_ip = st.selectbox("Select an IP to query CVEs for:", df_assets["ip"].tolist())
        if selected_ip:
            # Here we would need to map IP to software versions. For simplicity, just show placeholder.
            st.write(f"Showing vulnerabilities for {selected_ip}:")
            # Placeholder: You can extend to search NVD by product names from HTTP User-Agent or hostnames
            st.info("Full CVE integration requires mapping IP to software versions. This demo shows how you would query.")
            # Example: query NVD for a product from hostnames
            host = df_assets[df_assets["ip"] == selected_ip]["hostnames"].values[0]
            if host:
                st.write(f"Could query NVD for {host[0] if host else 'unknown'}")
    else:
        st.info("Add NVD API key to see vulnerability data.")

    # Cleanup
    os.unlink(tmp_path)
