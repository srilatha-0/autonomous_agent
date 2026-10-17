from crewai.tools import tool

from initial_data import (
    IP_REPUTATION,
    WHOIS_DNS,
    SIEM_EVENTS,
    THREAT_KNOWLEDGE,
)


tool_invocation_order = []


@tool("T1")
def t1(ip_address: str) -> str:
    """Retrieve IP reputation data only from initial_data.py."""

    tool_invocation_order.append("T1")

    data = IP_REPUTATION.get(ip_address)

    if data is None:
        return "No T1 data available for this IP in initial_data.py."

    return (
        f"IP Address: {ip_address}\n"
        f"Reputation: {data['reputation']}\n"
        f"Risk Score: {data['risk_score']}\n"
        f"Categories: {data['categories']}\n"
        f"First Seen: {data['first_seen']}"
    )


@tool("T2")
def t2(ip_address: str) -> str:
    """Retrieve WHOIS and DNS data only from initial_data.py."""

    tool_invocation_order.append("T2")

    data = WHOIS_DNS.get(ip_address)

    if data is None:
        return "No T2 data available for this IP in initial_data.py."

    return (
        f"IP Address: {ip_address}\n"
        f"ASN: {data['asn']}\n"
        f"Organization: {data['organization']}\n"
        f"Country: {data['country']}\n"
        f"Reverse DNS: {data['reverse_dns']}"
    )


@tool("T3")
def t3(ip_address: str) -> str:
    """Retrieve SIEM activity only from initial_data.py."""

    tool_invocation_order.append("T3")

    data = SIEM_EVENTS.get(ip_address)

    if data is None:
        return "No T3 data available for this IP in initial_data.py."

    return (
        f"IP Address: {ip_address}\n"
        f"Events: {data['events']}\n"
        f"Systems: {data['systems']}\n"
        f"Activity: {data['activity']}"
    )


@tool("T4")
def t4(ip_address: str) -> str:
    """Retrieve threat knowledge only from initial_data.py."""

    tool_invocation_order.append("T4")

    return THREAT_KNOWLEDGE