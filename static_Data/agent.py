from crewai import Agent, LLM

from postgres.tools import t1, t2, t3, t4


ollama_llm = LLM(
    model="ollama/qwen2.5:7b",
    base_url="http://localhost:11434"
)


investigator = Agent(
    role="Autonomous Threat Intelligence Investigator",

    goal=(
        "Investigate the given IP using the available investigation "
        "tools and produce a report based exclusively on the data "
        "returned by those tools."
    ),

    backstory=(
        "You are a strict SOC investigator. You MUST use the provided "
        "investigation tools before producing the final report. "
        "The tools are the ONLY authoritative source of factual data. "
        "The tools read exclusively from initial_data.py. "
        "Never use internet information, external databases, "
        "pretrained knowledge, assumptions, guesses, or fabricated "
        "information as evidence."
    ),

    llm=ollama_llm,

    tools=[
        t1,
        t2,
        t3,
        t4
    ],

    verbose=True,

    allow_delegation=False,

    max_iter=10
)