# boards/rss_board.py
from typing import Dict, List
import feedparser


def run_rss_board(cfg: Dict, engine) -> List[Dict]:
    feed_url = (cfg.get("feed_url") or "").strip()
    if not feed_url:
        return []

    d = feedparser.parse(feed_url)
    default_location = (cfg.get("default_location") or "").strip()
    default_company = (cfg.get("default_company") or "").strip()

    jobs: List[Dict] = []
    for e in (d.entries or []):
        title = (getattr(e, "title", "") or "").strip()
        url = (getattr(e, "link", "") or "").strip()
        summary = (getattr(e, "summary", "") or "").strip()

        jobs.append(
            {
                "title": title,
                "company": default_company,
                "location": default_location,
                "description": summary,
                "url": url,
            }
        )
    return jobs
