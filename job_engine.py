# job_engine.py
import time
import hashlib
from typing import Callable, Dict, List
import requests


def _hash(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()


class JobBoardEngine:
    def __init__(self, user_agent: str = "Scout/1.0 (+job-matching)", timeout: int = 25):
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        self.timeout = timeout

    def fetch(self, url: str) -> str:
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.text

    def fetch_json(self, url: str):
        r = self.session.get(url, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def run(
        self,
        adapters: List[Callable[[Dict, "JobBoardEngine"], List[Dict]]],
        configs: List[Dict],
        per_request_delay_sec: float = 1.0,
        max_jobs: int = 400,
    ) -> List[Dict]:
        out: List[Dict] = []
        seen = set()

        for adapter, cfg in zip(adapters, configs):
            jobs = adapter(cfg, self) or []
            for j in jobs:
                url = (j.get("url") or "").strip()
                if not url:
                    continue
                key = _hash(url)
                if key in seen:
                    continue
                seen.add(key)
                out.append(j)
                if len(out) >= max_jobs:
                    return out
            time.sleep(per_request_delay_sec)

        return out
