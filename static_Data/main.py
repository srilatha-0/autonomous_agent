import csv

from crew import crew
from postgres.tools import tool_invocation_order


IP_ADDRESS = "185.220.101.45"


print("=" * 70)
print("AUTONOMOUS THREAT INTELLIGENCE INVESTIGATION")
print("=" * 70)

print(f"\nIP Address: {IP_ADDRESS}")
print("\nStarting investigation...\n")


tool_invocation_order.clear()


result = crew.kickoff(
    inputs={
        "ip_address": IP_ADDRESS
    }
)


actual_order = "\n".join(tool_invocation_order)


print("\n" + "=" * 70)
print("ACTUAL TOOL INVOCATION ORDER")
print("=" * 70)

if actual_order:
    print(actual_order)
else:
    print("NONE")


print("\n" + "=" * 70)
print("FINAL INVESTIGATION RESULT")
print("=" * 70)


if not tool_invocation_order:

    final_result = (
        "INVESTIGATION INVALID.\n\n"
        "No investigation tools were actually invoked. "
        "Therefore no factual investigation report is accepted."
    )

    print(final_result)

else:

    final_result = str(result)

    print(final_result)


with open(
    "output.csv",
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.writer(file)

    writer.writerow([
        "Scenario",
        "IP Address",
        "Actual Tool Invocation Order",
        "Final Report"
    ])

    writer.writerow([
        "Initial Data",
        IP_ADDRESS,
        actual_order if actual_order else "NONE",
        final_result
    ])


print("\nSaved to output.csv")