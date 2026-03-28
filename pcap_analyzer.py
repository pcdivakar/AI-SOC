import re
from scapy.all import rdpcap, IP, TCP, UDP, Ether, Raw, ARP, DNS
from collections import defaultdict

# OT Protocol Signatures (port + payload start)
OT_PROTOCOLS = {
    "Modbus": {"ports": [502], "signatures": [b'\x00\x00\x00\x00\x00\x06', b'\x00\x01\x00\x00\x00\x06'], "asset_type": "PLC/RTU", "vendor": None},
    "Siemens S7": {"ports": [102], "signatures": [b'\x03\x00\x00', b'\x32\x01\x00'], "asset_type": "Siemens PLC", "vendor": "Siemens"},
    "DNP3": {"ports": [20000], "signatures": [b'\x05\x64', b'\x05\x65'], "asset_type": "RTU/IED", "vendor": None},
    "BACnet": {"ports": [47808], "signatures": [b'\x81\x0a'], "asset_type": "Building Automation", "vendor": None},
    "EtherNet/IP": {"ports": [44818], "signatures": [b'\x65\x00\x04\x00'], "asset_type": "Rockwell PLC", "vendor": "Rockwell Automation"},
    "IEC 104": {"ports": [2404], "signatures": [b'\x68\x01', b'\x68\x04'], "asset_type": "SCADA RTU", "vendor": None},
    "OPC UA": {"ports": [4840], "signatures": [b'OPC', b'UA'], "asset_type": "OPC Server", "vendor": None},
    "CODESYS": {"ports": [2455], "signatures": [b'CODESYS'], "asset_type": "Industrial Controller", "vendor": None},
    "Profinet": {"ports": [34964, 34965], "signatures": [b'\xfe\xfe', b'\x01\x02'], "asset_type": "Profinet Device", "vendor": "Siemens"},
    "EtherCAT": {"ports": [34980], "signatures": [b'\x01\x00\x00\x00', b'\x02\x00\x00\x00'], "asset_type": "EtherCAT Slave", "vendor": None},
    "MQTT": {"ports": [1883, 8883], "signatures": [b'MQTT'], "asset_type": "IoT Gateway", "vendor": None},
    "OPC DA": {"ports": [135], "signatures": [b'OPC'], "asset_type": "OPC DA Server", "vendor": None},
    "IEC 61850 MMS": {"ports": [102], "signatures": [b'\x28\x01\x00', b'\x28\x02'], "asset_type": "IED (IEC 61850)", "vendor": None},
    "IEC 61850 GOOSE": {"ports": [], "signatures": [b'\x88\xb8'], "asset_type": "GOOSE Publisher", "vendor": None},
    "IEC 61850 SV": {"ports": [], "signatures": [b'\x88\xba'], "asset_type": "Sampled Values", "vendor": None}
}

IT_SERVICE_PORTS = {
    80: "Web Server (HTTP)", 443: "Web Server (HTTPS)", 22: "SSH Server", 23: "Telnet Server",
    3389: "RDP Server", 3306: "MySQL Database", 5432: "PostgreSQL Database", 1433: "MSSQL Database",
    27017: "MongoDB", 25: "SMTP Mail Server", 110: "POP3 Mail Server", 143: "IMAP Mail Server",
    53: "DNS Server", 123: "NTP Server", 161: "SNMP Agent", 162: "SNMP Trap", 445: "SMB/CIFS",
    139: "NetBIOS", 514: "Syslog", 21: "FTP Server", 69: "TFTP Server", 5900: "VNC Server",
    8000: "HTTP Alt", 8080: "HTTP Proxy", 8443: "HTTPS Alt"
}

def detect_ot_protocol(packet):
    if not (TCP in packet or UDP in packet):
        return None, None, None
    dst_port = packet.dport if hasattr(packet, 'dport') else None
    if Raw not in packet:
        return None, None, None
    payload = bytes(packet[Raw].load)
    for proto, info in OT_PROTOCOLS.items():
        if info["ports"] and dst_port not in info["ports"]:
            continue
        for sig in info["signatures"]:
            if payload.startswith(sig):
                return proto, info["asset_type"], info["vendor"]
        if info["ports"] and dst_port in info["ports"]:
            return proto, info["asset_type"], info["vendor"]
    return None, None, None

def analyze_pcap(pcap_path, max_packets=10000):
    packets = rdpcap(pcap_path)
    if len(packets) > max_packets:
        packets = packets[:max_packets]

    ip_data = defaultdict(lambda: {
        "ip": None,
        "macs": set(),
        "ports": set(),
        "hostnames": set(),
        "ot_protocols": set(),
        "ot_asset_types": set(),
        "ot_vendors": set(),
        "http_user_agents": set(),
        "dns_queries": set(),
        "snmp_communities": set(),
        "cves": set()
    })

    # Build IP-MAC mapping
    ip_mac = {}
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 2:
            ip_mac[pkt[ARP].psrc] = pkt[ARP].hwsrc
        elif Ether in pkt and IP in pkt:
            ip_mac[pkt[IP].src] = pkt[Ether].src

    for pkt in packets:
        if IP not in pkt:
            continue
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        for ip in [src_ip, dst_ip]:
            if ip_data[ip]["ip"] is None:
                ip_data[ip]["ip"] = ip
            if ip in ip_mac:
                ip_data[ip]["macs"].add(ip_mac[ip])

        if TCP in pkt or UDP in pkt:
            sport = pkt.sport if hasattr(pkt, 'sport') else None
            dport = pkt.dport if hasattr(pkt, 'dport') else None
            if sport:
                ip_data[src_ip]["ports"].add(sport)
                ip_data[dst_ip]["ports"].add(dport)
            if dport:
                ip_data[src_ip]["ports"].add(dport)
                ip_data[dst_ip]["ports"].add(dport)

        proto, asset_type, vendor = detect_ot_protocol(pkt)
        if proto:
            ip_data[dst_ip]["ot_protocols"].add(proto)
            if asset_type:
                ip_data[dst_ip]["ot_asset_types"].add(asset_type)
            if vendor:
                ip_data[dst_ip]["ot_vendors"].add(vendor)

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            # HTTP Host
            host_match = re.search(rb'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
            if host_match:
                ip_data[dst_ip]["hostnames"].add(host_match.group(1).decode(errors='ignore'))
            # HTTP User-Agent
            ua_match = re.search(rb'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
            if ua_match:
                ip_data[src_ip]["http_user_agents"].add(ua_match.group(1).decode(errors='ignore'))
            # TLS SNI (simplified)
            if TCP in pkt and pkt.dport == 443 and payload.startswith(b'\x16'):
                sni_match = re.search(rb'\x00\x00\x00([^\x00]+)', payload)
                if sni_match:
                    ip_data[dst_ip]["hostnames"].add(sni_match.group(1).decode(errors='ignore'))
            # SNMP community
            if UDP in pkt and pkt.dport == 161 and payload.startswith(b'\x30'):
                parts = payload.split(b'\x04')
                if len(parts) >= 2:
                    community = parts[1].split(b'\x00')[0].decode(errors='ignore')
                    ip_data[dst_ip]["snmp_communities"].add(community)
            # CVEs
            payload_str = payload.decode(errors='ignore')
            cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', payload_str, re.IGNORECASE)
            for cve in cve_matches:
                ip_data[dst_ip]["cves"].add(cve.upper())

        if DNS in pkt and pkt[DNS].qr == 0:
            for q in pkt[DNS].qd:
                if q.qname:
                    ip_data[src_ip]["dns_queries"].add(q.qname.decode(errors='ignore').rstrip('.'))

    for ip, data in ip_data.items():
        data["macs"] = list(data["macs"])
        data["ports"] = sorted(data["ports"])
        data["hostnames"] = list(data["hostnames"])
        data["ot_protocols"] = list(data["ot_protocols"])
        data["ot_asset_types"] = list(data["ot_asset_types"])
        data["ot_vendors"] = list(data["ot_vendors"])
        data["http_user_agents"] = list(data["http_user_agents"])
        data["dns_queries"] = list(data["dns_queries"])
        data["snmp_communities"] = list(data["snmp_communities"])
        data["cves"] = list(data["cves"])

    return ip_data
