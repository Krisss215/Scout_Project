# job_sources_registry.py
from boards.rss_board import run_rss_board
from boards.html_generic_board import run_html_generic_board
from boards.lever_board import run_lever_board
from boards.greenhouse_board import run_greenhouse_board

SOURCES = {
    "lever_api": {
        "label": "Lever (API preset)",
        "fn": run_lever_board,
        "config_fields": [
            {"key": "company", "label": "Lever company slug (required)", "placeholder": "e.g., netflix"},
            {"key": "company_name", "label": "Company display name (optional)", "placeholder": "Netflix"},
            {"key": "query", "label": "Filter contains (optional)", "placeholder": "e.g., support / marketing"},
            {"key": "location_contains", "label": "Location contains (optional)", "placeholder": "e.g., Israel / Tel Aviv"},
            {"key": "team_contains", "label": "Team contains (optional)", "placeholder": "e.g., Sales"},
            {"key": "max_results", "label": "Max results (optional)", "placeholder": "200"},
        ],
    },
    "greenhouse_api": {
        "label": "Greenhouse (API preset)",
        "fn": run_greenhouse_board,
        "config_fields": [
            {"key": "board_token", "label": "Greenhouse board token (required)", "placeholder": "e.g., stripe"},
            {"key": "company_name", "label": "Company display name (optional)", "placeholder": "Stripe"},
            {"key": "title_contains", "label": "Title contains (optional)", "placeholder": "e.g., customer / operations"},
            {"key": "location_contains", "label": "Location contains (optional)", "placeholder": "e.g., Israel / Tel Aviv"},
            {"key": "max_results", "label": "Max results (optional)", "placeholder": "200"},
        ],
    },
    "rss": {
        "label": "RSS Job Feed (recommended)",
        "fn": run_rss_board,
        "config_fields": [
            {"key": "feed_url", "label": "Feed URL (required)", "placeholder": "https://.../jobs.rss"},
            {"key": "default_company", "label": "Default company (optional)", "placeholder": "Company"},
            {"key": "default_location", "label": "Default location (optional)", "placeholder": "e.g., Tel Aviv"},
        ],
    },
    "html_generic": {
        "label": "HTML Board (CSS selectors + pagination)",
        "fn": run_html_generic_board,
        "config_fields": [
            {"key": "list_url", "label": "List URL (required)", "placeholder": "https://board.com/search?q=..."},
            {"key": "base_url", "label": "Base URL (optional)", "placeholder": "https://board.com"},
            {"key": "job_item_sel", "label": "Job item selector (required)", "placeholder": ".job-card"},
            {"key": "title_sel", "label": "Title selector (required)", "placeholder": ".job-title"},
            {"key": "url_sel", "label": "URL selector (required)", "placeholder": "a.job-link"},
            {"key": "company_sel", "label": "Company selector (optional)", "placeholder": ".company"},
            {"key": "location_sel", "label": "Location selector (optional)", "placeholder": ".location"},
            {"key": "desc_sel", "label": "Description selector (optional)", "placeholder": ".summary"},
            {"key": "max_pages", "label": "Max pages (optional, 1-10)", "placeholder": "3"},
            {"key": "next_page_sel", "label": "Next-page selector (optional)", "placeholder": "a.next"},
            {"key": "next_page_attr", "label": "Next-page attribute (optional)", "placeholder": "href"},
        ],
    },
}
