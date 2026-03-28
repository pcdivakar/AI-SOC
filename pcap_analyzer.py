import re
from scapy.all import rdpcap, IP, TCP, UDP, Raw
from collections import defaultdict

def extract_cve_from_payload(payload):
    """Extract CVE IDs from raw packet payload using regex."""
    if not payload:
        return []
    # Pattern for CVE-YYYY-NNNN
    pattern = r'CVE-\d{4}-\d{4,7}'
    return list(set(re.findall(pattern, str(payload))))

def analyze_pcap(pcap_path, max_packets=5000):
    """
    Analyze pcap file and return:
    - packets: list of packet summaries (for display)
    - cves: set of unique CVE IDs found in payloads
    - ips: set of source/destination IPs
    - hostnames: set of HTTP Host headers or TLS SNI
    """
    packets = rdpcap(pcap_path)
    if len(packets) > max_packets:
        packets = packets[:max_packets]  # limit for performance

    summary = []
    cves = set()
    ips = set()
    hostnames = set()

    for pkt in packets:
        # Basic summary
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            ips.add(src)
            ips.add(dst)
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "Other"
            summary.append(f"{src}:{pkt.sport if hasattr(pkt, 'sport') else ''} → {dst}:{pkt.dport if hasattr(pkt, 'dport') else ''} ({proto})")
        else:
            summary.append(str(pkt.summary()))

        # Extract CVEs from raw payload
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            cves.update(extract_cve_from_payload(payload))

        # Extract hostnames from HTTP Host header
        if TCP in pkt and Raw in pkt:
            payload = pkt[Raw].load.decode(errors='ignore')
            # Simple HTTP Host detection
            match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
            if match:
                hostnames.add(match.group(1).strip())
        # Extract TLS SNI
        if TCP in pkt and Raw in pkt and pkt.dport == 443:
            # Basic SNI extraction (simplified)
            payload = pkt[Raw].load
            # TLS handshake: client hello has SNI extension
            if payload[0] == 0x16:  # handshake
                # Very rough, might need a proper parser; for demo we skip
                pass

    return {
        "summary": summary,
        "cves": list(cves),
        "ips": list(ips),
        "hostnames": list(hostnames)
    }