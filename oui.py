# oui.py
OUI_DB = {
    # OT / Industrial
    "00:01:02": "Siemens AG",
    "00:0A:0B": "Rockwell Automation",
    "00:14:22": "Schneider Electric",
    "00:1B:1C": "ABB",
    "00:50:C2": "General Electric",
    "00:80:F4": "Honeywell",
    "00:30:48": "Omron",
    "00:40:8C": "Mitsubishi Electric",
    "00:60:6E": "Emerson",
    "00:90:2D": "Yokogawa",
    "00:A0:45": "Bosch Rexroth",
    "00:0C:29": "VMware (Virtual)",
    "00:50:56": "VMware (Virtual)",
    "00:0F:FE": "Beckhoff",
    "00:1E:8F": "Phoenix Contact",
    "00:0A:CD": "Wago",
    "00:10:5A": "Siemens (Building)",
    "00:1D:09": "Rockwell (Stratix)",
    "00:02:6B": "Eaton",
    "00:0E:5E": "Advantech",
    "00:15:5D": "Hirschmann",
    "00:20:4A": "Moxa",
    "00:23:8B": "Moxa",
    "00:90:CC": "Belden",
    "00:1B:77": "HMS Networks",
    # IT / Networking
    "00:00:0C": "Cisco",
    "00:01:97": "HP",
    "00:0F:1F": "Dell",
    "00:1E:C2": "Juniper",
    "00:25:90": "Arista",
    "00:0C:41": "Aruba",
    "00:18:73": "Extreme Networks",
    "00:1A:11": "Ubiquiti",
    "00:25:9C": "MikroTik",
    "00:1B:63": "Fortinet",
    "00:0D:88": "Check Point",
    "00:30:48": "IBM",
    "00:21:5A": "Apple",
    "00:16:CB": "Samsung",
    # Add more as needed
}

def lookup_vendor(mac):
    """Return vendor name based on first 3 bytes of MAC (OUI)."""
    mac_upper = mac.upper()
    # Normalize format: strip separators, take first 6 hex digits
    mac_clean = mac_upper.replace(':', '').replace('-', '')[:6]
    # Format as XX:XX:XX
    oui = ':'.join([mac_clean[i:i+2] for i in (0,2,4)])
    return OUI_DB.get(oui, "Unknown")