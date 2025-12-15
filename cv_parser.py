# cv_parser.py
import re
from typing import List


def extract_text_from_pdf(file_path: str) -> str:
    text = ""
    try:
        import pdfplumber  # type: ignore
        with pdfplumber.open(file_path) as pdf:
            for page in pdf.pages:
                text += (page.extract_text() or "") + "\n"
    except Exception:
        return ""
    return text


def extract_keywords_from_cv(file_path: str, max_keywords: int = 30) -> List[str]:
    text = extract_text_from_pdf(file_path).lower()
    if not text:
        return []

    dictionary = [
        "excel", "word", "powerpoint", "google sheets", "google docs",
        "customer service", "communication", "sales", "marketing",
        "project management", "analysis", "data analysis", "python", "sql",
        "jira", "sap", "crm", "call center", "administration", "operations",
        "english", "hebrew", "russian", "presentation", "teamwork",
        "problem solving", "time management",
    ]

    hits = [term for term in dictionary if term in text]

    tokens = re.findall(r"[a-zA-Z][a-zA-Z\+\#\.\-]{2,}", text)
    stop = set(["the", "and", "for", "with", "from", "this", "that", "are", "was", "were", "you", "your"])
    freq = {}
    for t in tokens:
        if t in stop:
            continue
        freq[t] = freq.get(t, 0) + 1

    extra = [k for k, v in sorted(freq.items(), key=lambda kv: kv[1], reverse=True) if v >= 2]
    merged = list(dict.fromkeys(hits + extra))
    return merged[:max_keywords]
