import requests
from oui import lookup_vendor
from pcap_analyzer import IT_SERVICE_PORTS  # if needed, but it's imported from pcap_analyzer

def classify_asset(ip_data, hf_token=None):
    """
    Takes a single IP data dictionary (as returned by analyze_pcap)
    and returns a classification dictionary with additional fields.
    """
    ip = ip_data["ip"]
    macs = ip_data["macs"]
    ports = ip_data["ports"]
    hostnames = ip_data["hostnames"]
    ot_protocols = ip_data["ot_protocols"]
    ot_asset_types = ip_data["ot_asset_types"]
    ot_vendors = ip_data["ot_vendors"]
    http_user_agents = ip_data["http_user_agents"]
    dns_queries = ip_data["dns_queries"]
    snmp_communities = ip_data["snmp_communities"]
    cves = ip_data.get("cves", [])   # ← added

    # Vendor from MAC OUI
    vendor = "Unknown"
    for mac in macs:
        vendor = lookup_vendor(mac)
        if vendor != "Unknown":
            break
    # Override with OT vendor if known
    if ot_vendors:
        vendor = ", ".join(ot_vendors)

    # Asset type
    if ot_asset_types:
        asset_type = " / ".join(ot_asset_types)
        confidence = "high (OT protocol)"
    else:
        # Check IT service ports
        it_service = None
        for port in ports:
            if port in IT_SERVICE_PORTS:
                it_service = IT_SERVICE_PORTS[port]
                break
        if it_service:
            asset_type = it_service
            confidence = "medium (port based)"
        else:
            # AI fallback
            if hf_token:
                asset_type = ai_classify(ip, ports, hostnames, http_user_agents,
                                         dns_queries, snmp_communities, macs, hf_token)
                confidence = "low (AI estimate)"
            else:
                asset_type = "Unknown"
                confidence = "low (no data)"

    # Return all fields including cves
    return {
        "ip": ip,
        "asset_type": asset_type,
        "confidence": confidence,
        "vendor": vendor,
        "ports": ports,
        "hostnames": hostnames,
        "ot_protocols": ot_protocols,
        "http_user_agents": http_user_agents,
        "dns_queries": dns_queries,
        "snmp_communities": snmp_communities,
        "cves": cves                   # ← added
    }

def ai_classify(ip, ports, hostnames, ua, dns, snmp, macs, hf_token):
    """Use a large language model via Hugging Face to classify."""
    if not hf_token:
        return "Unknown (AI unavailable)"

    # Build detailed context
    context = f"IP: {ip}\n"
    if macs:
        context += f"MAC(s): {', '.join(macs)}\n"
    if ports:
        context += f"Open ports: {', '.join(map(str, ports))}\n"
    if hostnames:
        context += f"Hostnames: {', '.join(hostnames)}\n"
    if ua:
        context += f"HTTP User-Agents: {', '.join(ua)}\n"
    if dns:
        context += f"DNS queries: {', '.join(dns)}\n"
    if snmp:
        context += f"SNMP communities: {', '.join(snmp)}\n"
    context += "Based on this traffic, what type of device is this likely to be? Choose from: PLC, RTU, HMI, Industrial Controller, Web Server, Database Server, Router, Switch, Firewall, IoT Device, Workstation, or Other. Answer with only the device type."

    # Use a capable model (Mistral 7B via HF)
    api_url = "https://router.huggingface.co/hf-inference/models/mistralai/Mistral-7B-Instruct-v0.2"
    headers = {"Authorization": f"Bearer {hf_token}"}
    prompt = f"<s>[INST] {context} [/INST]"
    payload = {"inputs": prompt, "parameters": {"max_new_tokens": 20, "temperature": 0.1}}

    try:
        resp = requests.post(api_url, headers=headers, json=payload, timeout=15)
        if resp.status_code != 200:
            return "Error"
        result = resp.json()
        if isinstance(result, list) and len(result) > 0:
            return result[0].get("generated_text", "").strip().split("\n")[0]
        return "Unknown"
    except Exception:
        return "Unknown"
