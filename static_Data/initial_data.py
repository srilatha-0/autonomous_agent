IP_REPUTATION = {
    "185.220.101.45": {
        "reputation": "malacious",
        "risk_score": 95,
        "categories": "Tor exit node, scanning, suspicious activity",
        "first_seen": "2026-06-12",
    },
    "8.8.8.8": {
        "reputation": "benign",
        "risk_score": 1,
        "categories": "Public DNS",
        "first_seen": "well-known",
    },
}

WHOIS_DNS = {
    "185.220.101.45": {
        "asn": "AS9009",
        "organization": "M247 Europe SRL",
        "country": "Germany",
        "reverse_dns": "tor-exit.example.net",
    },
    "8.8.8.8": {
        "asn": "AS15169",
        "organization": "Google LLC",
        "country": "United States",
        "reverse_dns": "dns.google",
    },
}

SIEM_EVENTS = {
    "185.220.101.45": {
        "events": 17,
        "systems": "WEB-SRV-01, VPN-GW-01",
        "activity": "Multiple failed authentication attempts followed by successful VPN authentication. Port scanning observed against WEB-SRV-01.",
    },
    "8.8.8.8": {
        "events": 3,
        "systems": "DNS-SRV-01",
        "activity": "Normal DNS resolution traffic.",
    },
}

THREAT_KNOWLEDGE = """
Tor exit nodes are not automatically malicious. However, repeated
authentication failures, scanning activity, or suspicious access
originating from the same Tor exit node increase investigation priority.

A high-risk external IP combined with authentication anomalies and
port scanning should be treated as a potentially malicious intrusion
indicator until sufficient contrary evidence exists.

Recommended SOC investigation sequence:
1. Validate IP reputation.
2. Identify ownership/ASN and DNS information.
3. Search SIEM for historical and current activity.
4. Correlate multiple indicators.
5. Determine confidence and recommend containment.

An IOC alone does not prove compromise. Analysts should distinguish
between malicious infrastructure, scanning activity, attempted
intrusion, and confirmed successful compromise.
"""