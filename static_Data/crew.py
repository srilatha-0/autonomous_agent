from crewai import Crew, Process

from agent import investigator
from task import investigation_task


crew = Crew(
    agents=[investigator],
    tasks=[investigation_task],
    process=Process.sequential,
    verbose=False,
)