# jobs_source.py
from typing import List, Dict
import json
from job_engine import JobBoardEngine
from job_sources_registry import SOURCES


def get_jobs(selected_sources: List[Dict]) -> List[Dict]:
    engine = JobBoardEngine()
    adapters = []
    configs = []

    for row in selected_sources or []:
        key = row.get("source_key")
        if key not in SOURCES:
            continue
        adapters.append(SOURCES[key]["fn"])
        try:
            configs.append(json.loads(row.get("config_json") or "{}"))
        except Exception:
            configs.append({})

    return engine.run(adapters=adapters, configs=configs, per_request_delay_sec=1.0, max_jobs=400)
