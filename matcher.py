# matcher.py
import re
from typing import List, Dict


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def rank_jobs(profile: Dict, jobs: List[Dict], min_score: int = 35) -> List[Dict]:
    titles = [_norm(x) for x in (profile.get("target_titles") or []) if _norm(x)]
    keywords = [_norm(x) for x in (profile.get("keywords") or []) if _norm(x)]
    excludes = [_norm(x) for x in (profile.get("exclude_keywords") or []) if _norm(x)]

    ranked = []
    for j in jobs or []:
        title = _norm(j.get("title", ""))
        company = _norm(j.get("company", ""))
        location = _norm(j.get("location", ""))
        desc = _norm(j.get("description", ""))

        blob = f"{title} {company} {location} {desc}"

        matched_titles = [t for t in titles if t and t in blob]
        matched_keywords = [k for k in keywords if k and k in blob]
        excluded_hits = [x for x in excludes if x and x in blob]

        score = 0
        score += 30 * min(len(matched_titles), 2)
        score += 10 * min(len(matched_keywords), 5)
        score -= 40 * min(len(excluded_hits), 2)

        score = max(0, min(100, score))

        out = dict(j)
        out["_score"] = int(score)
        out["_why"] = {
            "matched_titles": matched_titles,
            "matched_keywords": matched_keywords,
            "excluded_hits": excluded_hits,
        }

        if out["_score"] >= min_score:
            ranked.append(out)

    ranked.sort(key=lambda x: x.get("_score", 0), reverse=True)
    return ranked
