
from crewai import Agent, Task, Crew, Process
from agent import ollama_llm
from tools import t1, reset_tool_invocation_order, get_tool_invocation_order

reset_tool_invocation_order()

test_agent = Agent(
    role="Tool Execution Tester",
    goal="Retrieve the IP reputation using the provided tool.",
    backstory="You test CrewAI tool execution.",
    llm=ollama_llm,
    tools=[t1],
    verbose=True,
    allow_delegation=False,
    max_iter=5
)

test_task = Task(
    description=(
        "Call the available IP reputation tool for "
        "185.220.101.45. Use the actual tool result "
        "to report its reputation and risk score. "
        "Do not answer without executing the tool."
    ),
    expected_output="The IP reputation and risk score from the tool.",
    agent=test_agent
)

test_crew = Crew(
    agents=[test_agent],
    tasks=[test_task],
    process=Process.sequential,
    verbose=True
)

try:
    result = test_crew.kickoff()
    print("\nRESULT:", result)
except Exception as e:
    import traceback
    traceback.print_exc()

print("\nRECORDED TOOL ORDER:")
print(get_tool_invocation_order())
