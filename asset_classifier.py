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
            model="llama-3.1-8b-instant",   # Updated model
            temperature=0.1,
            max_tokens=20,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return "Unknown"
