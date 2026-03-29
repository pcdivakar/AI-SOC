import os
from groq import Groq
from oui import lookup_vendor
from pcap_analyzer import IT_SERVICE_PORTS

def classify_asset(ip_data, groq_api_key=None):
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
    cves = ip_data.get("cves", [])
    firmware_version = ip_data.get("firmware_version", "Unknown")
    model_number = ip_data.get("model_number", "Unknown")
    os_combined = ip_data.get("os_combined", "Unknown")

    # Vendor from MAC OUI
    vendor = "Unknown"
    for mac in macs:
        vendor = lookup_vendor(mac)
        if vendor != "Unknown":
            break
    if ot_vendors:
        vendor = ", ".join(ot_vendors)

    # Asset type
    if ot_asset_types:
        asset_type = " / ".join(ot_asset_types)
        confidence = "high (OT protocol)"
    else:
        it_service = None
        for port in ports:
            if port in IT_SERVICE_PORTS:
                it_service = IT_SERVICE_PORTS[port]
                break
        if it_service:
            asset_type = it_service
            confidence = "medium (port based)"
        else:
            if groq_api_key:
                asset_type = ai_classify_groq(
                    ip, ports, hostnames, http_user_agents,
                    dns_queries, snmp_communities, macs, groq_api_key
                )
                confidence = "low (AI estimate)"
            else:
                asset_type = "Unknown"
                confidence = "low (no data)"

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
        "cves": cves,
        "os": os_combined,
        "firmware_version": firmware_version,
        "model_number": model_number
    }

def ai_classify_groq(ip, ports, hostnames, ua, dns, snmp, macs, groq_api_key):
    if not groq_api_key:
        return "Unknown (AI unavailable)"
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

    client = Groq(api_key=groq_api_key)
    try:
        response = client.chat.completions.create(
            messages=[{"role": "user", "content": context}],
            model="llama-3.1-8b-instant",
            temperature=0.1,
            max_tokens=20,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return "Unknown"
