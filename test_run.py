import json
from job_sources_registry import get_jobs
from matcher import rank_jobs

with open("profiles.json", "r", encoding="utf-8") as f:
    profile = json.load(f)

jobs = get_jobs()
ranked = rank_jobs(profile, jobs, min_score=0)

for j in ranked:
    print("----")
    print(j["title"], "|", j.get("company"), "| score:", j["_score"])
    print("WHY:", j["_why"])
