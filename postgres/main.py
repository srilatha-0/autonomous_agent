import crewai.llms.cache as cache

def no_cache_breakpoint(message):
    message.pop("cache_breakpoint", None)
    return message

cache.mark_cache_breakpoint = no_cache_breakpoint

import crewai.agents.crew_agent_executor as executor
executor.mark_cache_breakpoint = no_cache_breakpoint

import crewai.experimental.agent_executor as experimental_executor
experimental_executor.mark_cache_breakpoint = no_cache_breakpoint

import os
import csv
import random
from datetime import datetime

from crew import crew
from agent import investigator
from tools import (
    t1, t2, t3, t4,
    reset_tool_invocation_order,
    get_tool_invocation_order,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_PATH = os.path.join(BASE_DIR, "output.csv")


def save_output(ip_address, tool_order, report, status):
    try:
        file_exists = os.path.exists(OUTPUT_PATH)

        with open(OUTPUT_PATH, "a", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames=[
                    "Timestamp",
                    "IP Address",
                    "Actual Tool Invocation Order",
                    "Verification Status",
                    "Final Report"
                ]
            )

            if not file_exists or os.path.getsize(OUTPUT_PATH) == 0:
                writer.writeheader()

            writer.writerow({
                "Timestamp": datetime.now().isoformat(timespec="seconds"),
                "IP Address": ip_address,
                "Actual Tool Invocation Order": (
                    " -> ".join(tool_order) if tool_order else "None"
                ),
                "Verification Status": status,
                "Final Report": str(report)
            })

            file.flush()

        print(f"\nOutput saved to:\n{OUTPUT_PATH}")

    except Exception as e:
        print(f"\nError saving output.csv: {e}")


def investigate_ip(ip_address: str):
    reset_tool_invocation_order()

    # Present the tools in a different order each run so list position
    # cannot bias the agent's choice. The agent still decides what to call.
    shuffled_tools = [t1, t2, t3, t4]
    random.shuffle(shuffled_tools)
    investigator.tools = shuffled_tools

    print(f"\nInvestigating IP: {ip_address}\n")

    result = None
    error_message = None

    try:
        result = crew.kickoff(inputs={"ip_address": ip_address})

    except Exception as e:
        error_message = str(e)
        print(f"\nInvestigation failed: {error_message}")

    actual_order = get_tool_invocation_order()

    print("\nActual Tool Invocation Order:")
    print(" -> ".join(actual_order) if actual_order else "No tools executed")

    if not actual_order:
        status = "UNVERIFIED - NO TOOLS EXECUTED"
        report = (
            "Investigation rejected: no tool invocations were recorded. "
            "The generated report, if any, has not been verified against "
            "actual tool results."
        )

        if error_message:
            report += f"\nExecution error: {error_message}"

        print("\nERROR: No tool executions were recorded.")
        print("The generated report will not be accepted as a verified investigation.")

        save_output(ip_address, actual_order, report, status)
        return None

    if error_message:
        status = "FAILED - EXECUTION ERROR"
        report = f"Investigation failed: {error_message}"

    elif result is None:
        status = "FAILED - NO REPORT"
        report = "Tools were recorded, but no report was returned."

    else:
        status = "TOOLS RECORDED - REPORT REQUIRES VALIDATION"
        report = str(result)

        print("\nFinal Investigation Report:\n")
        print(report)

    save_output(ip_address, actual_order, report, status)

    return result


if __name__ == "__main__":
    while True:
        ip_address = input(
            "\nEnter IP address (or type 'exit' to stop): "
        ).strip()

        if ip_address.lower() == "exit":
            break

        if not ip_address:
            print("IP address cannot be empty.")
            continue

        investigate_ip(ip_address)