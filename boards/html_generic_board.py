# boards/html_generic_board.py
from typing import Dict, List
from urllib.parse import urljoin
from bs4 import BeautifulSoup


def _pick(el, sel: str):
    if not sel:
        return None
    return el.select_one(sel)


def _text(el):
    return (el.get_text(" ", strip=True) if el else "").strip()


def run_html_generic_board(cfg: Dict, engine) -> List[Dict]:
    list_url = (cfg.get("list_url") or "").strip()
    if not list_url:
        return []

    job_item_sel = (cfg.get("job_item_sel") or "").strip()
    title_sel = (cfg.get("title_sel") or "").strip()
    url_sel = (cfg.get("url_sel") or "").strip()

    company_sel = (cfg.get("company_sel") or "").strip()
    location_sel = (cfg.get("location_sel") or "").strip()
    desc_sel = (cfg.get("desc_sel") or "").strip()

    base_url = (cfg.get("base_url") or "").strip()

    max_pages = int(cfg.get("max_pages") or 1)
    max_pages = max(1, min(max_pages, 10))

    next_page_sel = (cfg.get("next_page_sel") or "").strip()
    next_page_attr = (cfg.get("next_page_attr") or "href").strip() or "href"

    jobs: List[Dict] = []
    current_url = list_url

    for _ in range(max_pages):
        html = engine.fetch(current_url)
        soup = BeautifulSoup(html, "html.parser")

        items = soup.select(job_item_sel) if job_item_sel else []
        for it in items[:400]:
            t_el = _pick(it, title_sel)
            a_el = _pick(it, url_sel)

            title = _text(t_el)
            href = ((a_el.get("href") if a_el else "") or "").strip()
            url = href

            if url:
                if base_url and url.startswith("/"):
                    url = base_url.rstrip("/") + url
                elif url.startswith("/"):
                    url = urljoin(current_url, url)
                elif base_url and not url.startswith("http"):
                    url = urljoin(base_url.rstrip("/") + "/", url)

            company = _text(_pick(it, company_sel))
            location = _text(_pick(it, location_sel))
            description = _text(_pick(it, desc_sel))

            if title and url:
                jobs.append(
                    {
                        "title": title,
                        "company": company,
                        "location": location,
                        "description": description,
                        "url": url,
                    }
                )

        if not next_page_sel:
            break

        nxt = soup.select_one(next_page_sel)
        nxt_href = ((nxt.get(next_page_attr) if nxt else "") or "").strip()
        if not nxt_href:
            break

        if nxt_href.startswith("http"):
            current_url = nxt_href
        elif nxt_href.startswith("/"):
            current_url = (base_url.rstrip("/") + nxt_href) if base_url else urljoin(current_url, nxt_href)
        else:
            current_url = urljoin(current_url, nxt_href)

    return jobs
