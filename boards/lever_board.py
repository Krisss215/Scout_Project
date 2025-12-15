from typing import Dict, List
from urllib.parse import quote


def run_lever_board(cfg: Dict, engine) -> List[Dict]:
    company = (cfg.get("company") or "").strip()
    if not company:
        return []

    max_results = int(cfg.get("max_results") or 200)
    max_results = max(1, min(max_results, 500))

    url = f"https://api.lever.co/v0/postings/{quote(company)}?mode=json"
    data = engine.fetch_json(url) or []

    q = (cfg.get("query") or "").strip().lower()
    loc_contains = (cfg.get("location_contains") or "").strip().lower()
    team_contains = (cfg.get("team_contains") or "").strip().lower()

    out: List[Dict] = []
    for p in data:
        title = (p.get("text") or "").strip()
        apply_url = (p.get("hostedUrl") or p.get("applyUrl") or "").strip()

        categories = p.get("categories") or {}
        location = (categories.get("location") or "").strip()
        team = (categories.get("team") or "").strip()
        commitment = (categories.get("commitment") or "").strip()

        desc = (p.get("descriptionPlain") or p.get("description") or "").strip()
        company_name = (cfg.get("company_name") or company).strip()

        if q:
            blob = f"{title} {desc} {team} {location}".lower()
            if q not in blob:
                continue
        if loc_contains and loc_contains not in location.lower():
            continue
        if team_contains and team_contains not in team.lower():
            continue

        out.append({
            "title": title,
            "company": company_name,
            "location": location,
            "description": f"{team} {commitment}\n{desc}".strip(),
            "url": apply_url,
        })

        if len(out) >= max_results:
            break

    return out
