"""
Autonomous Threat Intelligence Investigation using CrewAI (Version 2 - Pure CSV)
================================================================================
Reads 3 structured CSV files via lookup tools and retrieves relevant knowledge
from the fourth CSV with CrewAI RagTool.
"""

import argparse
import os
import sys
from pathlib import Path
from uuid import uuid4
import pandas as pd

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

from crewai import Agent, Task, Crew, LLM, Process
from crewai.tools import tool
from crewai_tools import RagTool
from dotenv import load_dotenv


load_dotenv()


class GroqLLM(LLM):
    def _format_messages_for_provider(self, messages):
        clean_messages = [
            {key: value for key, value in message.items() if key != "cache_breakpoint"}
            for message in messages
        ]
        return super()._format_messages_for_provider(clean_messages)


GROQ_MODEL = os.getenv("GROQ_MODEL", "")
if not GROQ_MODEL.startswith("groq/"):
    raise RuntimeError("Set GROQ_MODEL in .env to an enabled groq/<model-id>.")

TOOL_SEQUENCE: list[str] = []
TOOL_LABELS = {
    "T1": "IP Reputation Lookup",
    "T2": "WHOIS and DNS Investigation",
    "T3": "SIEM Search",
    "T4": "Threat Intelligence RAG Search",
}
HIGH_RISK_THRESHOLD = 80

# CSV File Paths (Located inside Version2 folder)
DATA_DIR = Path(__file__).resolve().parent
IP_REPUTATION_CSV = DATA_DIR / "ip_reputation.csv"
WHOIS_DNS_CSV = DATA_DIR / "whois_dns.csv"
SIEM_DATA_CSV = DATA_DIR / "siem_data.csv"
RAG_KNOWLEDGE_CSV = DATA_DIR / "rag_knowledge_base.csv"
RAG_CONFIG = {
    "embedding_model": {
        "provider": "onnx",
        "config": {"preferred_providers": ["CPUExecutionProvider"]},
    }
}


# ---------------------------------------------------------------------
# 1. STRUCTURED CSV LOOKUP TOOLS (Files 1, 2, 3)
# ---------------------------------------------------------------------

@tool("IP Reputation Lookup")
def ip_reputation_lookup(ip_address: str) -> str:
    """Check the reputation of an IP address by querying ip_reputation.csv."""
    TOOL_SEQUENCE.append("T1")

    try:
        df = pd.read_csv(IP_REPUTATION_CSV)
        match = df[df["ip_address"].astype(str).str.strip() == ip_address.strip()]

        if match.empty:
            return f"IP: {ip_address}\nNo reputation data found in CSV."

        row = match.iloc[0]
        return (
            f"IP: {ip_address}\n"
            f"Reputation: {row.get('reputation', 'unknown')}\n"
            f"Risk Score: {row.get('risk_score', 50)}/100\n"
            f"Categories: {row.get('categories', 'N/A')}\n"
            f"First Seen: {row.get('first_seen', 'unknown')}"
        )
    except Exception as e:
        return f"Error reading ip_reputation.csv: {str(e)}"


@tool("WHOIS and DNS Investigation")
def whois_dns_lookup(ip_address: str) -> str:
    """Retrieve WHOIS/DNS information for an IP address by querying whois_dns.csv."""
    TOOL_SEQUENCE.append("T2")

    try:
        df = pd.read_csv(WHOIS_DNS_CSV)
        match = df[df["ip_address"].astype(str).str.strip() == ip_address.strip()]

        if match.empty:
            return f"IP: {ip_address}\nNo WHOIS/DNS data found in CSV."

        row = match.iloc[0]
        return (
            f"IP: {ip_address}\n"
            f"ASN: {row.get('asn', 'Unknown')}\n"
            f"Organization: {row.get('organization', 'Unknown')}\n"
            f"Country: {row.get('country', 'Unknown')}\n"
            f"Reverse DNS: {row.get('reverse_dns', 'Unknown')}"
        )
    except Exception as e:
        return f"Error reading whois_dns.csv: {str(e)}"


@tool("SIEM Search")
def siem_search(ip_address: str) -> str:
    """Search SIEM telemetry for activity involving the IP address by querying siem_data.csv."""
    TOOL_SEQUENCE.append("T3")

    try:
        df = pd.read_csv(SIEM_DATA_CSV)
        ip_col = "source_ip" if "source_ip" in df.columns else "ip_address"
        matches = df[df[ip_col].astype(str).str.strip() == ip_address.strip()]

        if matches.empty:
            return f"IP: {ip_address}\nNo matching SIEM events found."

        systems = ", ".join(matches["asset"].dropna().unique()) if "asset" in matches.columns else "Unknown"
        activities = "; ".join(matches["description"].dropna().unique()) if "description" in matches.columns else "Activity recorded"
        timestamps = ", ".join(matches["timestamp"].dropna().unique()) if "timestamp" in matches.columns else "N/A"

        return (
            f"IP: {ip_address}\n"
            f"Matching Events: {len(matches)}\n"
            f"Event Timestamps: {timestamps}\n"
            f"Affected Systems: {systems}\n"
            f"Observed Activity: {activities}"
        )
    except Exception as e:
        return f"Error reading siem_data.csv: {str(e)}"


# ---------------------------------------------------------------------
# 2. CREWAI RAG TOOL FOR UNSTRUCTURED KNOWLEDGE (File 4)
# ---------------------------------------------------------------------

rag_knowledge_search = RagTool(
    collection_name=f"threat_intel_csv_{uuid4().hex}", config=RAG_CONFIG
)
rag_knowledge_search.add(path=RAG_KNOWLEDGE_CSV, data_type="csv")


@tool("Threat Intelligence RAG Search")
def threat_intelligence_rag_search(query: str) -> str:
    """Retrieve relevant SOC guidance from the knowledge-base CSV."""
    TOOL_SEQUENCE.append("T4")
    return rag_knowledge_search.run(query=query)


# ---------------------------------------------------------------------
# 3. AUTONOMOUS AGENT & TASK SETUP
# ---------------------------------------------------------------------

threat_intelligence_agent = Agent(
    role="Autonomous Threat Intelligence Investigator",
    goal=(
        "Investigate suspicious IP addresses autonomously using available lookup "
        "and RAG tools to determine if the IP represents a security threat."
    ),
    backstory=(
        "You are an experienced SOC threat intelligence analyst. You decide which "
        "tools to use based on the facts gathered directly from local CSV databases."
    ),
    tools=[
        ip_reputation_lookup,
        whois_dns_lookup,
        siem_search,
        threat_intelligence_rag_search,
    ],
    llm=GroqLLM(model=GROQ_MODEL, temperature=0),
    verbose=True,
    allow_delegation=False,
)

investigation_task = Task(
    description="""
    Investigate the following suspicious IP address:

        IP ADDRESS: {ip_address}

    Always call T1 (IP Reputation Lookup) first. If the returned risk score is
    at least 80 or the reputation is Malicious, continue in this order: T2
    (WHOIS and DNS), T3 (SIEM Search), then T4 (RAG Search). Use each result to
    guide the next step. For lower-risk results, use only the additional tools
    needed to explain the evidence.

    Base factual statements only on tool results. Separate observed evidence
    from interpretation and recommendations. Use SIEM timestamps exactly as
    returned; do not call events recent or say they occurred within a time
    window unless the timestamps support that calculation. For port scanning,
    report that scanning was detected; do not infer connection success or
    failure unless a tool explicitly reports it. Do not claim lateral movement
    or data exfiltration without supporting evidence.
    Express confidence qualitatively (low, moderate, or high); do not invent a
    percentage or precise probability without a calibrated scoring method.

    Produce the final report using this structure:
    A. Investigation Target
    B. Evidence Collected
    C. Indicators of Compromise
    D. Observed Organizational Activity
    E. Risk Assessment
    F. Confidence Level
    G. Recommended SOC Actions
    H. Important Uncertainties

    Formatting: use short section headings and hyphen bullets. Do not use
    Markdown tables, HTML, box characters, or decorative borders.
    """,
    expected_output=(
        "A readable plain-text report with the eight requested sections, "
        "evidence-grounded claims, and no tables or decorative formatting."
    ),
    agent=threat_intelligence_agent,
)

crew = Crew(
    agents=[threat_intelligence_agent],
    tasks=[investigation_task],
    process=Process.sequential,
    verbose=True,
)


# ---------------------------------------------------------------------
# 4. RUN THE AGENT
# ---------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Investigate the highest-risk IP in the reputation CSV or a specified IP."
    )
    parser.add_argument(
        "--ip",
        help="Investigate this IP instead of automatically selecting the highest score.",
    )
    args = parser.parse_args()

    reputation_df = pd.read_csv(IP_REPUTATION_CSV)
    reputation_df["risk_score"] = pd.to_numeric(
        reputation_df["risk_score"], errors="coerce"
    )
    valid_scores = reputation_df.dropna(subset=["risk_score"])
    if valid_scores.empty:
        raise ValueError(f"No numeric risk scores found in {IP_REPUTATION_CSV}")

    if args.ip:
        suspicious_ip = args.ip.strip()
        matching_rows = valid_scores[
            valid_scores["ip_address"].astype(str).str.strip() == suspicious_ip
        ]
        selected_score = (
            int(matching_rows.iloc[0]["risk_score"]) if not matching_rows.empty else None
        )
    else:
        highest_risk = valid_scores.loc[valid_scores["risk_score"].idxmax()]
        suspicious_ip = str(highest_risk["ip_address"]).strip()
        selected_score = int(highest_risk["risk_score"])

    print(
        f"Target IP: {suspicious_ip} "
        f"(CSV risk score: {selected_score if selected_score is not None else 'not found'}; "
        f"high-risk threshold: {HIGH_RISK_THRESHOLD})"
    )
    result = crew.kickoff(inputs={"ip_address": suspicious_ip})
    sequence = " -> ".join(TOOL_SEQUENCE) or "No tool calls"
    project_root = Path(__file__).resolve().parents[1]
    output_directory = project_root / "outputs"
    output_directory.mkdir(parents=True, exist_ok=True)
    safe_ip = suspicious_ip.replace(".", "_").replace(":", "_")
    output_path = output_directory / f"version2_{safe_ip}.md"
    tool_key = "\n".join(
        f"- {tool_id}: {label}" for tool_id, label in TOOL_LABELS.items()
    )
    output_path.write_text(
        f"# Version 2 Investigation\n\n"
        f"**Target:** `{suspicious_ip}`\n\n"
        f"**CSV risk score:** `{selected_score if selected_score is not None else 'not found'}`\n\n"
        f"**High-risk threshold:** `{HIGH_RISK_THRESHOLD}`\n\n"
        f"**Tool sequence:** `{sequence}`\n\n"
        f"## Tool Key\n\n{tool_key}\n\n"
        f"## Final Report\n\n{result}\n",
        encoding="utf-8",
    )
    print("\nFINAL REPORT\n")
    print(result)
    print(f"\nReport saved: {output_path.relative_to(project_root)}")