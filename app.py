import streamlit as st
import os
import tempfile
import pandas as pd
from dotenv import load_dotenv
import utils
from pcap_analyzer import analyze_pcap
from vulnerability import fetch_nvd, fetch_epss, fetch_kev_status
from chatbot import ask_ai

# Load environment variables (local development)
load_dotenv()

# Initialize database
utils.init_db()

# Set page config
st.set_page_config(page_title="AI PCAP Analyzer", layout="wide")
st.title("🛡️ AI PCAP Analyzer with Vulnerability Intelligence")

# Get API keys from secrets (Streamlit Cloud) or env (local)
nvd_api_key = st.secrets.get("NVD_API_KEY", os.getenv("NVD_API_KEY"))
hf_token = st.secrets.get("HF_API_TOKEN", os.getenv("HF_API_TOKEN"))

# Sidebar for configuration
with st.sidebar:
    st.header("Configuration")
    if not nvd_api_key:
        st.warning("NVD API key not set. NVD queries may fail.")
    if not hf_token:
        st.warning("Hugging Face token not set. AI chatbot disabled.")
    st.markdown("---")
    st.markdown("### How to use")
    st.markdown("1. Upload a PCAP file.")
    st.markdown("2. The tool extracts CVEs found in packet payloads.")
    st.markdown("3. It fetches vulnerability data (NVD, EPSS, KEV).")
    st.markdown("4. Ask questions about the traffic or vulnerabilities using the AI assistant.")

# File uploader
uploaded_file = st.file_uploader("Choose a PCAP file", type=["pcap", "pcapng"])
if uploaded_file is not None:
    # Save to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.getbuffer())
        tmp_path = tmp.name

    with st.spinner("Analyzing PCAP..."):
        analysis = analyze_pcap(tmp_path)

    st.success("Analysis complete!")
    st.subheader("📊 PCAP Summary")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Unique IPs", len(analysis["ips"]))
    with col2:
        st.metric("Unique Hostnames", len(analysis["hostnames"]))
    with col3:
        st.metric("CVEs Found", len(analysis["cves"]))

    # Show packet summary in expander
    with st.expander("Packet Summaries (first 500)"):
        st.text("\n".join(analysis["summary"][:500]))

    # Show extracted CVEs
    if analysis["cves"]:
        st.subheader("🔍 Extracted CVEs")
        cve_list = analysis["cves"]
        # Fetch enrichment data
        enriched = []
        for cve in cve_list:
            with st.spinner(f"Fetching data for {cve}..."):
                nvd_data = fetch_nvd(cve, nvd_api_key) if nvd_api_key else None
                epss = fetch_epss(cve)
                kev = fetch_kev_status(cve)
                enriched.append({
                    "CVE": cve,
                    "EPSS Score": epss if epss is not None else "N/A",
                    "KEV": "Yes" if kev else "No",
                    "Description": nvd_data.get("descriptions", [{}])[0].get("value", "N/A")[:200] if nvd_data else "N/A"
                })
        df = pd.DataFrame(enriched)
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No CVE identifiers found in the packet payloads.")

    # AI Chatbot
    st.subheader("🤖 AI Assistant")
    if hf_token:
        # Build context for AI: include summary, CVEs, IPs, hostnames
        context = f"PCAP analysis result:\n"
        context += f"- Number of packets processed: {len(analysis['summary'])}\n"
        context += f"- Unique IPs: {', '.join(analysis['ips'][:20])}\n"
        context += f"- Unique hostnames: {', '.join(analysis['hostnames'][:20])}\n"
        if analysis['cves']:
            context += f"- CVEs found: {', '.join(analysis['cves'])}\n"
        else:
            context += "- No CVEs were found in packet payloads.\n"

        user_question = st.text_area("Ask a question about this PCAP (e.g., 'What are the top 3 CVEs by EPSS score?')")
        if st.button("Ask AI") and user_question:
            with st.spinner("Thinking..."):
                answer = ask_ai(user_question, context, hf_token=hf_token)
            st.markdown("**AI Response:**")
            st.write(answer)
    else:
        st.error("Hugging Face token not configured. Please add it to secrets to use the AI chatbot.")

    # Cleanup
    os.unlink(tmp_path)