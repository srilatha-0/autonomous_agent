from crewai import Task

from agent import investigator


investigation_task = Task(
    description="""
Investigate this IP address: {ip_address}

You are an autonomous threat intelligence investigator. You decide for
yourself which tools to use, in what order, and when to stop.

Each tool provides a different kind of evidence. None of them is a default
first step and none has a fixed position:
- ip_reputation_lookup: reputation, risk score, categories, first seen, source
- siem_event_lookup: events from our own environment with this IP as source
- whois_dns_lookup: ASN, organization, country, reverse DNS, notes
- threat_knowledge_search: general threat knowledge (not IP-specific)

Before EVERY tool call, state in one line what you currently know, the most
important unanswered question, and why the tool you chose best addresses it.
Do not reuse an order just because it was used before. Stop when more calls
would not change your conclusion.

RULES
- Call at least one tool before writing the final report.
- Tool results are the ONLY source of facts. No internet, external threat
  intelligence, pretrained knowledge, assumptions, guesses or invented values.
- Copy returned values exactly. Never change or substitute them.
- threat_knowledge_search is general knowledge. Do not attribute its content
  to the investigated IP unless the result explicitly says so.
- Malicious reputation does NOT prove compromise. Distinguish malicious
  infrastructure, suspicious activity, attempted intrusion and confirmed
  compromise. Claim confirmed compromise only if tool evidence explicitly
  proves it.
- Report tool failures and "no data found" results explicitly.

FINAL REPORT
A. Tool Invocation Order
   List only tools actually executed, in the order executed. For each: what
   was known before the call, the question it addressed, and why it was chosen.
   Explain why the next tool followed, or why you stopped.

B. Final Investigation Report
   1. Investigation Target
   2. Evidence Collected
   3. Indicators of Compromise
   4. Observed Organizational Activity
   5. Risk Assessment
   6. Confidence Level
   7. Recommended SOC Actions
   8. Important Uncertainties

No raw JSON. Remove any claim that a tool result does not support.
""",

    expected_output="""
A. Tool Invocation Order
The tools actually executed, in actual order, each with the evidence known
beforehand, the question it addressed, and the reason for the next step.

B. Final Investigation Report
A factual report (sections 1-8) based only on returned tool data, with no
external information, fabricated values, or unsupported claims.
""",

    agent=investigator,
)