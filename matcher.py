# matcher.py
from dataclasses import dataclass
from typing import List, Dict

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class JobMatchResult:
    job_id: str
    title: str
    company: str
    location: str
    url: str
    score: float
    explanation: str


def compute_matches(profile_text: str, jobs: List[Dict]) -> List[JobMatchResult]:
    """
    profile_text: combined CV + 'what you are looking for'
    jobs: list of dicts with keys: id, title, company, location, url, description
    """
    if not jobs:
        return []

    # CV+preferences text + all job descriptions → TF-IDF
    corpus = [profile_text] + [job["description"] for job in jobs]

    vectorizer = TfidfVectorizer(stop_words="english")
    tfidf_matrix = vectorizer.fit_transform(corpus)

    profile_vec = tfidf_matrix[0:1]
    job_vecs = tfidf_matrix[1:]

    similarities = cosine_similarity(profile_vec, job_vecs).flatten()

    results: List[JobMatchResult] = []
    for sim, job in zip(similarities, jobs):
        score = float(sim * 100)  # 0–100
        explanation = (
            "Score is based on text similarity between your CV + preferences and the job description. "
            "Higher = more overlapping skills, tools, and keywords. "
            "Later we can add a deeper LLM-based explanation."
        )

        results.append(
            JobMatchResult(
                job_id=str(job["id"]),
                title=job["title"],
                company=job.get("company", ""),
                location=job.get("location", ""),
                url=job.get("url", ""),
                score=round(score, 2),
                explanation=explanation,
            )
        )

    results.sort(key=lambda r: r.score, reverse=True)
    return results
