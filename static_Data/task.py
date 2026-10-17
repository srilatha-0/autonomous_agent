from crewai import Task

from agent import investigator


investigation_task = Task(
    description="""
Investigate this IP address:

IP ADDRESS: {ip_address}

You are an autonomous threat intelligence investigator.

Your first responsibility is to obtain evidence using the provided
CrewAI investigation tools.

AVAILABLE TOOLS:

T1 = IP Reputation
T2 = DNS/WHOIS
T3 = SIEM
T4 = Threat Intelligence Knowledge

==================================================
MANDATORY INVESTIGATION REQUIREMENT
==================================================

You MUST call at least one investigation tool before producing
your final answer.

Do NOT produce the final investigation report before obtaining
tool evidence.

You must autonomously decide:

- which tools are necessary
- the order of the tools
- whether additional tools are necessary
- when sufficient evidence has been collected

There is NO predefined sequence.

Do NOT automatically assume:

T1 -> T2 -> T3 -> T4

The investigation order must be your decision.

==================================================
ABSOLUTE DATA RESTRICTION
==================================================

The tool results are the ONLY source of factual information.

The tools read exclusively from:

initial_data.py

You MUST NOT use:

- internet information
- external databases
- external threat intelligence
- pretrained knowledge as evidence
- assumptions
- guesses
- fabricated values

Every factual statement in your final report MUST be directly
supported by a value returned by an investigation tool.

==================================================
NO HALLUCINATION
==================================================

If a value is not present in the tool result, DO NOT provide it.

For example, if the tool returns:

Country: Germany

you may write:

Country: Germany

You MUST NOT write:

Country: Russia

If the tool returns:

Risk Score: 95

you may write:

Risk Score: 95

You MUST NOT write:

Risk Score: 0.7

If the tool returns:

Organization: M247 Europe SRL

you may write:

Organization: M247 Europe SRL

You MUST NOT replace it with another organization.

Do not create facts.

Do not transform facts into different facts.

Do not use outside knowledge to fill missing information.

==================================================
T4 RESTRICTION
==================================================

T4 contains general threat knowledge.

T4 does NOT automatically contain IP-specific information.

Do not attribute information to the investigated IP unless
that information is explicitly present in the T4 result.

==================================================
COMPROMISE RULE
==================================================

A malicious IP reputation does NOT automatically prove
successful compromise.

Do not claim confirmed compromise unless the collected
tool evidence explicitly proves it.

Clearly distinguish between:

- malicious infrastructure
- suspicious activity
- attempted intrusion
- confirmed compromise

==================================================
FINAL REPORT
==================================================

After actually using the tools, produce:

A. Tool Invocation Order

List the tools actually used.

B. Final Investigation Report

1. Investigation Target
2. Evidence Collected
3. Indicators of Compromise
4. Observed Organizational Activity
5. Risk Assessment
6. Confidence Level
7. Recommended SOC Actions
8. Important Uncertainties

The report MUST contain only information supported by actual
tool results.

Do not output raw JSON.

Do not invent missing information.

Do not mention facts that were not returned by a tool.

==================================================
FINAL CHECK
==================================================

Before producing the final answer, verify:

1. Did I actually call a tool?
2. Does every factual claim come from a tool result?
3. Did I accidentally use outside knowledge?
4. Did I change any returned value?
5. Did I invent any information?

If any factual information cannot be supported by a tool result,
remove it from the report.
""",

    expected_output="""
A. Tool Invocation Order

The actual tools used during the investigation.

B. Final Investigation Report

A factual report based exclusively on the returned tool data.

Every factual statement must be directly supported by tool output.

No external information.
No hallucinations.
No fabricated values.
No unsupported claims.
""",

    agent=investigator,
)