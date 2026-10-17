import os
import psycopg2
from dotenv import load_dotenv
from crewai.tools import tool

from rag import search_rag


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))

POSTGRES_HOST = os.getenv("POSTGRES_HOST") or os.getenv("DB_HOST") or "localhost"
POSTGRES_PORT = os.getenv("POSTGRES_PORT") or os.getenv("DB_PORT") or "5432"
POSTGRES_DB = os.getenv("POSTGRES_DB") or os.getenv("DB_NAME") or "rhym"
POSTGRES_USER = os.getenv("POSTGRES_USER") or os.getenv("DB_USER") or "postgres"
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD") or os.getenv("DB_PASSWORD")


tool_invocation_order = []


def record_tool_call(tool_name, status="started", details=""):
    tool_invocation_order.append(tool_name)


def reset_tool_invocation_order():
    tool_invocation_order.clear()


def get_tool_invocation_order():
    return list(tool_invocation_order)


def get_db_connection():
    return psycopg2.connect(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD,
    )


# Logger labels stay "T1".."T4" so main.py and output.csv are unchanged.
# Only the names/descriptions the LLM sees are neutral and descriptive.

@tool("ip_reputation_lookup")
def t1(ip_address: str) -> str:
    """Returns reputation, risk score, categories, first-seen date and source
    for an IP address from the database. Input: the IP address."""

    record_tool_call("T1")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT ip_address, reputation, risk_score, categories,
                   first_seen, source
            FROM ip_reputation
            WHERE ip_address = %s;
            """,
            (ip_address,),
        )
        row = cursor.fetchone()

        if not row:
            return f"No IP reputation data found for {ip_address}."

        return (
            f"IP Address: {row[0]}\n"
            f"Reputation: {row[1]}\n"
            f"Risk Score: {row[2]}\n"
            f"Categories: {row[3]}\n"
            f"First Seen: {row[4]}\n"
            f"Source: {row[5]}"
        )

    except Exception as e:
        return f"PostgreSQL T1 error: {e}"

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@tool("whois_dns_lookup")
def t2(ip_address: str) -> str:
    """Returns ASN, organization, country, reverse DNS and notes for an IP
    address from the database. Input: the IP address."""

    record_tool_call("T2")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT ip_address, asn, organization, country, reverse_dns, notes
            FROM whois_dns
            WHERE ip_address = %s;
            """,
            (ip_address,),
        )
        row = cursor.fetchone()

        if not row:
            return f"No WHOIS/DNS data found for {ip_address}."

        return (
            f"IP Address: {row[0]}\n"
            f"ASN: {row[1]}\n"
            f"Organization: {row[2]}\n"
            f"Country: {row[3]}\n"
            f"Reverse DNS: {row[4]}\n"
            f"Notes: {row[5]}"
        )

    except Exception as e:
        return f"PostgreSQL T2 error: {e}"

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@tool("siem_event_lookup")
def t3(ip_address: str) -> str:
    """Returns internal SIEM events where the given IP was the source: assets,
    event types, actions, descriptions, severity and timestamps. Input: the
    IP address."""

    record_tool_call("T3")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT event_id, timestamp, source_ip, asset, event_type,
                   action, description, severity
            FROM siem_events
            WHERE source_ip = %s
            ORDER BY timestamp;
            """,
            (ip_address,),
        )
        rows = cursor.fetchall()

        if not rows:
            return f"No SIEM events found for {ip_address}."

        results = []
        for row in rows:
            results.append(
                f"Event ID: {row[0]}\n"
                f"Timestamp: {row[1]}\n"
                f"Source IP: {row[2]}\n"
                f"Asset: {row[3]}\n"
                f"Event Type: {row[4]}\n"
                f"Action: {row[5]}\n"
                f"Description: {row[6]}\n"
                f"Severity: {row[7]}"
            )

        return "\n\n".join(results)

    except Exception as e:
        return f"PostgreSQL T3 error: {e}"

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


@tool("threat_knowledge_search")
def t4(query: str) -> str:
    """Searches general threat intelligence knowledge (not IP-specific).
    Input: a topic, term, tactic or category to look up, not an IP address."""

    record_tool_call("T4")

    try:
        return search_rag(query)

    except Exception as e:
        return f"CrewAI RAG T4 error: {e}"