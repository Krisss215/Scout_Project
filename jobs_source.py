# jobs_source.py
from typing import List, Dict


def get_sample_jobs() -> List[Dict]:
    """
    Temporary job source: in the future this will be replaced
    with real job boards (LinkedIn, local sites, etc).
    """
    return [
        {
            "id": "job1",
            "title": "Junior Security Analyst",
            "company": "CyberSecure Ltd",
            "location": "Tel Aviv, Israel (Hybrid)",
            "url": "https://example.com/job1",
            "description": (
                "We are looking for a junior security analyst with experience in "
                "SOC environments, SIEM tools, incident response, Linux, and basic "
                "Python scripting. Advantage for networking knowledge and previous "
                "military / defense background."
            ),
        },
        {
            "id": "job2",
            "title": "Junior Python Developer (Cyber Tools)",
            "company": "RedShield Labs",
            "location": "Hybrid – Tel Aviv",
            "url": "https://example.com/job2",
            "description": (
                "Develop internal cyber security tools in Python. Work with APIs, "
                "automation scripts, log parsing, and simple dashboards. Team uses "
                "Git, Linux, Docker, and basic cloud (AWS)."
            ),
        },
        {
            "id": "job3",
            "title": "SOC Analyst Tier 1",
            "company": "BlueTeam 24/7",
            "location": "Rishon LeZion, Israel – On-site",
            "url": "https://example.com/job3",
            "description": (
                "Entry-level SOC position. Monitor security alerts, escalate incidents, "
                "work with SIEM, EDR, and ticketing systems. Shifts, including nights "
                "and weekends. Advantage for cyber courses and hands-on labs."
            ),
        },
        {
            "id": "job4",
            "title": "Information Security Engineer (Student Position)",
            "company": "FinTech Guard",
            "location": "Remote in Israel",
            "url": "https://example.com/job4",
            "description": (
                "Part-time role for CS / Cyber students. Assist with security controls, "
                "hardening, vulnerability scanning, and documentation. Familiarity with "
                "NIST, ISO 27001, and scripting (Python/Bash) is a big plus."
            ),
        },
        {
            "id": "job5",
            "title": "Junior Data & Security Analyst",
            "company": "InsightDefense",
            "location": "Hybrid – Herzliya",
            "url": "https://example.com/job5",
            "description": (
                "Analyze security and product data, build basic dashboards, and support "
                "threat research. Requires strong Excel/Sheets, SQL basics, and Python. "
                "Experience with BI tools is an advantage."
            ),
        },
    ]
