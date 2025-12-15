# boards/greenhouse_board.py
from typing import Dict, List
from urllib.parse import quote


def run_greenhouse_board(cfg: Dict, engine) -> List[Dict]:
    """
    Greenhouse API:
      https://boards-api.greenhouse.io/v1/boards/{board_token}/jobs
    cfg:
      board_token: required
      company_name: optional
      location_contains: optional
      title_contains: optional
      max_results: optional
    """
    token = (cfg.get("board_token") or "").strip()
    if not token:
        return []

    max_results = int(cfg.get("max_results") or 200)
    max_results = max(1, min(max_results, 500))

    url = f"https://boards-api.greenhouse.io/v1/boards/{quote(token)}/jobs"
    data = engine.fetch_json(url) or {}
    jobs = data.get("jobs") or []

    loc_contains = (cfg.get("location_contains") or "").strip().lower()
    title_contains = (cfg.get("title_contains") or "").strip().lower()
    company_name = (cfg.get("company_name") or token).strip()

    out: List[Dict] = []
    for j in jobs:
        title = (j.get("title") or "").strip()
        gh_url = (j.get("absolute_url") or "").strip()
        location = ((j.get("location") or {}).get("name") or "").strip()

        if loc_contains and loc_contains not in location.lower():
            continue
        if title_contains and title_contains not in title.lower():
            continue

        out.append(
            {
                "title": title,
                "company": company_name,
                "location": location,
                "description": "",
                "url": gh_url,
            }
        )
        if len(out) >= max_results:
            break

    return out
