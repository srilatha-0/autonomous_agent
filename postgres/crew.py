
import crewai.llms.cache as crew_cache

crew_cache.mark_cache_breakpoint = lambda msg: msg

from crewai import Crew, Process

from agent import investigator
from task import investigation_task

crew = Crew(
    agents=[investigator],
    tasks=[investigation_task],
    process=Process.sequential,
    verbose=True,
)
