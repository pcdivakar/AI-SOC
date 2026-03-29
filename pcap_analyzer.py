import re
from scapy.all import rdpcap, IP, TCP, UDP, Ether, Raw, ARP, DNS, PcapReader
from collections import defaultdict, Counter

# OT Protocol Signatures (same as before)
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

def extract_strings(payload):
    try:
        text = payload.decode('utf-8', errors='ignore')
    except:
        text = payload.decode('ascii', errors='ignore')
    strings = re.findall(r'[A-Za-z0-9._\-][A-Za-z0-9._\- ]{3,}', text)
    return strings

def extract_ot_metadata(payload, protocol):
    strings = extract_strings(payload)
    metadata = {}
    if protocol in ("Siemens S7", "Modbus", "BACnet", "EtherNet/IP", "DNP3"):
        for s in strings:
            if 'firmware' in s.lower() or 'version' in s.lower():
                metadata['firmware_version'] = s
            elif 'model' in s.lower() or 'type' in s.lower():
                metadata['model_number'] = s
    if protocol == "Siemens S7" and payload.startswith(b'\x03\x02'):
        try:
            ascii_part = payload[10:50].decode('ascii', errors='ignore')
            metadata['model_number'] = ascii_part.strip()
        except:
            pass
    if protocol == "Modbus" and payload.startswith(b'\x2b\x0e'):
        try:
            decoded = payload[6:].decode('ascii', errors='ignore')
            if 'vendor' in decoded.lower():
                metadata['vendor'] = decoded.split('vendor')[1].split('\x00')[0]
            if 'product' in decoded.lower():
                metadata['model_number'] = decoded.split('product')[1].split('\x00')[0]
            if 'version' in decoded.lower():
                metadata['firmware_version'] = decoded.split('version')[1].split('\x00')[0]
        except:
            pass
    return metadata

def detect_windows_version(payload):
    if payload.startswith(b'\xff\x53\x4d\x42'):
        strings = extract_strings(payload)
        for s in strings:
            if 'Windows' in s:
                return s
    return None

def guess_os_from_ttl(ttl):
    if ttl <= 64:
        if ttl == 64:
            return "Linux/Unix (TTL=64)"
        else:
            return f"Linux/Unix-like (TTL={ttl})"
    elif ttl <= 128:
        if ttl == 128:
            return "Windows (TTL=128)"
        else:
            return f"Windows-like (TTL={ttl})"
    elif ttl <= 255:
        if ttl == 255:
            return "Network Device (TTL=255)"
        else:
            return f"Network Device-like (TTL={ttl})"
    else:
        return "Unknown"

def analyze_pcap(pcap_path, max_packets=50000):
    """
    Stream PCAP file using PcapReader to avoid loading everything into memory.
    Returns a dictionary of aggregated data per IP.
    """
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
        "cves": set(),
        "ttl_values": [],
        "os_from_ua": None,
        "os_from_smb": None,
        "firmware_version": None,
        "model_number": None
    })

    # First pass: build IP-MAC mapping (requires full file, but we can do it on the fly)
    # We'll store mac-ip associations as we see them.
    ip_mac = {}

    packet_count = 0
    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if packet_count >= max_packets:
                break
            packet_count += 1

            # Skip non-IP packets
            if IP not in pkt:
                continue

            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Store MAC-IP mapping from Ethernet layer (if available)
            if Ether in pkt:
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst
                ip_mac[src_ip] = src_mac
                ip_mac[dst_ip] = dst_mac

            # Initialize entries
            for ip in [src_ip, dst_ip]:
                if ip_data[ip]["ip"] is None:
                    ip_data[ip]["ip"] = ip
                if ip in ip_mac:
                    ip_data[ip]["macs"].add(ip_mac[ip])

            # Ports
            if TCP in pkt or UDP in pkt:
                sport = pkt.sport if hasattr(pkt, 'sport') else None
                dport = pkt.dport if hasattr(pkt, 'dport') else None
                if sport:
                    ip_data[src_ip]["ports"].add(sport)
                    ip_data[dst_ip]["ports"].add(dport)
                if dport:
                    ip_data[src_ip]["ports"].add(dport)
                    ip_data[dst_ip]["ports"].add(dport)

            # OT detection
            proto, asset_type, vendor = detect_ot_protocol(pkt)
            if proto:
                ip_data[dst_ip]["ot_protocols"].add(proto)
                if asset_type:
                    ip_data[dst_ip]["ot_asset_types"].add(asset_type)
                if vendor:
                    ip_data[dst_ip]["ot_vendors"].add(vendor)

            # TTL values for OS guessing
            ttl = pkt[IP].ttl
            ip_data[src_ip]["ttl_values"].append(ttl)
            ip_data[dst_ip]["ttl_values"].append(ttl)

            # Payload extraction
            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
                # HTTP Host
                host_match = re.search(rb'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if host_match:
                    ip_data[dst_ip]["hostnames"].add(host_match.group(1).decode(errors='ignore'))
                # HTTP User-Agent
                ua_match = re.search(rb'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
                if ua_match:
                    ua = ua_match.group(1).decode(errors='ignore')
                    ip_data[src_ip]["http_user_agents"].add(ua)
                    if 'Windows' in ua:
                        ip_data[src_ip]["os_from_ua"] = ua.split('Windows')[1].split(';')[0].strip()
                    elif 'Linux' in ua:
                        ip_data[src_ip]["os_from_ua"] = 'Linux'
                    elif 'Mac' in ua:
                        ip_data[src_ip]["os_from_ua"] = 'macOS'
                # TLS SNI
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
                # CVEs from payload
                payload_str = payload.decode(errors='ignore')
                cve_matches = re.findall(r'CVE-\d{4}-\d{4,7}', payload_str, re.IGNORECASE)
                for cve in cve_matches:
                    ip_data[dst_ip]["cves"].add(cve.upper())
                # OT metadata
                if proto:
                    metadata = extract_ot_metadata(payload, proto)
                    if 'firmware_version' in metadata:
                        ip_data[dst_ip]["firmware_version"] = metadata['firmware_version']
                    if 'model_number' in metadata:
                        ip_data[dst_ip]["model_number"] = metadata['model_number']
                    if 'vendor' in metadata:
                        ip_data[dst_ip]["ot_vendors"].add(metadata['vendor'])
                # SMB Windows version
                if 445 in [pkt.dport, pkt.sport] and payload.startswith(b'\xff\x53\x4d\x42'):
                    win_ver = detect_windows_version(payload)
                    if win_ver:
                        ip_data[dst_ip]["os_from_smb"] = win_ver
                        ip_data[dst_ip]["os_from_ua"] = win_ver

            # DNS queries
            if DNS in pkt and pkt[DNS].qr == 0:
                for q in pkt[DNS].qd:
                    if q.qname:
                        ip_data[src_ip]["dns_queries"].add(q.qname.decode(errors='ignore').rstrip('.'))

    # Post-process TTL to guess OS
    for ip, data in ip_data.items():
        if data["ttl_values"]:
            ttl_counts = Counter(data["ttl_values"])
            most_common_ttl = ttl_counts.most_common(1)[0][0]
            data["os_from_ttl"] = guess_os_from_ttl(most_common_ttl)
        else:
            data["os_from_ttl"] = "Unknown"
        if data["os_from_smb"]:
            data["os_combined"] = data["os_from_smb"]
        elif data["os_from_ua"]:
            data["os_combined"] = data["os_from_ua"]
        else:
            data["os_combined"] = data["os_from_ttl"]

    # Convert sets to lists
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
        data.setdefault("firmware_version", None)
        data.setdefault("model_number", None)
        data.setdefault("os_combined", None)

    return ip_data
