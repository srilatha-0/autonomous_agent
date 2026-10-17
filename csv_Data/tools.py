import pandas as pd
from pathlib import Path

from crewai.tools import tool


DATA_DIR = Path(__file__).parent

T1_FILE = "REPUTATION.CSV"
T2_FILE = "WHOIS_DNS.CSV"
T3_FILE = "SIEM.CSV"
T4_FILE = "THREAT_KNOWLEDGE.CSV"

IP_COLUMN_NAMES = ("ip_address", "ip", "indicator", "address")

tool_invocation_order = []


def _find_file(filename):
    for p in DATA_DIR.iterdir():
        if p.name.lower() == filename.lower():
            return p
    return None


def _normalize(header):
    return str(header).strip().lower().replace(" ", "_")


def _read_rows(filename):
    path = _find_file(filename)
    if path is None:
        return None

    df = pd.read_csv(path, encoding="utf-8-sig", dtype=str).fillna("")
    df.columns = [_normalize(k) for k in df.columns]

    return [
        {k: v.strip() for k, v in row.items() if k}
        for row in df.to_dict(orient="records")
    ]


def _rows_for_ip(filename, ip_address):
    rows = _read_rows(filename)

    if rows is None:
        return None, f"File {filename} was not found in {DATA_DIR}."

    if not rows:
        return [], None

    ip_col = next((c for c in IP_COLUMN_NAMES if c in rows[0]), None)

    if ip_col is None:
        return None, (
            f"{filename} has no IP column. Expected one of: "
            f"{', '.join(IP_COLUMN_NAMES)}."
        )

    matches = [r for r in rows if r[ip_col] == ip_address.strip()]
    return matches, None


def _format_rows(ip_address, rows):
    blocks = []

    for i, row in enumerate(rows, start=1):
        lines = [f"IP Address: {ip_address}"] if i == 1 else []

        if len(rows) > 1:
            lines.append(f"--- Record {i} ---")

        for key, value in row.items():
            if key in IP_COLUMN_NAMES:
                continue

            label = key.replace("_", " ").title()
            lines.append(f"{label}: {value}")

        blocks.append("\n".join(lines))

    return "\n".join(blocks)


def _lookup(tool_name, filename, ip_address):
    rows, error = _rows_for_ip(filename, ip_address)

    if error:
        return f"{tool_name} error: {error}"

    if not rows:
        return f"No {tool_name} data available for this IP in {filename}."

    return _format_rows(ip_address, rows)


@tool("T1")
def t1(ip_address: str) -> str:
    """Retrieve IP reputation data only from REPUTATION."""
    tool_invocation_order.append("T1")
    return _lookup("T1", T1_FILE, ip_address)


@tool("T2")
def t2(ip_address: str) -> str:
    """Retrieve WHOIS and DNS data only from WHOIS_DNS."""
    tool_invocation_order.append("T2")
    return _lookup("T2", T2_FILE, ip_address)


@tool("T3")
def t3(ip_address: str) -> str:
    """Retrieve SIEM activity only from SIEM."""
    tool_invocation_order.append("T3")
    return _lookup("T3", T3_FILE, ip_address)


@tool("T4")
def t4(ip_address: str = "") -> str:
    """Retrieve general threat knowledge only from THREAT_KNOWLEDGE."""
    tool_invocation_order.append("T4")

    rows = _read_rows(T4_FILE)

    if rows is None:
        return f"T4 error: {T4_FILE} was not found in {DATA_DIR}."

    if not rows:
        return f"No T4 data available in {T4_FILE}."

    blocks = []

    for row in rows:
        values = [v for v in row.values() if v]

        if len(row) == 1:
            blocks.append(values[0])
        else:
            blocks.append(
                "\n".join(
                    f"{k.replace('_', ' ').title()}: {v}"
                    for k, v in row.items()
                    if v
                )
            )

    return "\n\n".join(blocks)

