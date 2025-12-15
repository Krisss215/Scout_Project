# scheduler.py
import json
import random
import hashlib
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler

from db import get_conn
from jobs_source import get_jobs
from matcher import rank_jobs
from notifier import send_email, send_telegram

scheduler = BackgroundScheduler()


def _now() -> datetime:
    return datetime.utcnow()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _url_hash(url: str) -> str:
    return hashlib.sha256((url or "").encode("utf-8")).hexdigest()


def _get_user_profile(user_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM profiles WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return None
    p = dict(row)
    for k in ["target_titles", "industries", "employment_types", "languages", "keywords", "exclude_keywords"]:
        try:
            p[k] = json.loads(p.get(k) or "[]")
        except Exception:
            p[k] = []
    return p


def _get_user_sources(user_id: int) -> list[dict]:
    conn = get_conn()
    rows = conn.execute(
        "SELECT source_key, config_json FROM user_sources WHERE user_id=? AND is_enabled=1",
        (user_id,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _get_user_notifications(user_id: int) -> dict | None:
    conn = get_conn()
    row = conn.execute("SELECT * FROM notifications WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _get_user_scan_settings(user_id: int) -> dict:
    conn = get_conn()
    row = conn.execute("SELECT * FROM scans WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    if not row:
        return {"is_enabled": 1, "min_interval_minutes": 40, "max_interval_minutes": 60, "next_run_at": None}
    return dict(row)


def _set_scan_state(user_id: int, status: str, next_minutes: int):
    conn = get_conn()
    next_run = _now() + timedelta(minutes=next_minutes)
    conn.execute(
        """
        INSERT INTO scans (user_id, last_run_at, next_run_at, last_status, is_enabled, min_interval_minutes, max_interval_minutes)
        VALUES (?, ?, ?, ?, 1, 40, 60)
        ON CONFLICT(user_id) DO UPDATE SET
          last_run_at=excluded.last_run_at,
          next_run_at=excluded.next_run_at,
          last_status=excluded.last_status
        """,
        (user_id, _now().isoformat(), next_run.isoformat(), status),
    )
    conn.commit()
    conn.close()


def _should_run_now(scan_row: dict) -> bool:
    if not scan_row.get("is_enabled", 1):
        return False
    nra = scan_row.get("next_run_at")
    if not nra:
        return True
    try:
        due = datetime.fromisoformat(nra)
        return _now() >= due
    except Exception:
        return True


def _job_seen_exists(user_id: int, url_hash: str) -> bool:
    conn = get_conn()
    row = conn.execute(
        "SELECT 1 FROM job_seen WHERE user_id=? AND url_hash=?",
        (user_id, url_hash),
    ).fetchone()
    conn.close()
    return bool(row)


def _job_seen_upsert(user_id: int, job: dict):
    url = (job.get("url") or "").strip()
    uh = _url_hash(url)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO job_seen (user_id, url_hash, url, title, company, location, first_seen_at, last_seen_at, last_score)
        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?)
        ON CONFLICT(user_id, url_hash) DO UPDATE SET
          last_seen_at=CURRENT_TIMESTAMP,
          title=excluded.title,
          company=excluded.company,
          location=excluded.location,
          last_score=excluded.last_score
        """,
        (
            user_id,
            uh,
            url,
            (job.get("title") or ""),
            (job.get("company") or ""),
            (job.get("location") or ""),
            job.get("_score"),
        ),
    )
    conn.commit()
    conn.close()


def scan_user(user_id: int):
    scan_settings = _get_user_scan_settings(user_id)
    if not _should_run_now(scan_settings):
        return

    min_m = int(scan_settings.get("min_interval_minutes") or 40)
    max_m = int(scan_settings.get("max_interval_minutes") or 60)
    next_minutes = random.randint(min_m, max_m)

    try:
        profile = _get_user_profile(user_id)
        if not profile:
            _set_scan_state(user_id, "no_profile", next_minutes)
            return

        sources = _get_user_sources(user_id)
        if not sources:
            _set_scan_state(user_id, "no_sources", next_minutes)
            return

        jobs = get_jobs(sources)
        ranked = rank_jobs(profile, jobs, min_score=35)

        new_jobs = []
        for j in ranked:
            url = (j.get("url") or "").strip()
            if not url:
                continue
            uh = _url_hash(url)
            if not _job_seen_exists(user_id, uh):
                new_jobs.append(j)
            _job_seen_upsert(user_id, j)

        top_new = new_jobs[:10]
        lines = [
            f"- {j.get('title')} | {j.get('company','')} | score {j.get('_score')} | {j.get('url','')}"
            for j in top_new
        ]
        digest = "\n".join(lines) if lines else "No new matches in this scan."
        digest_hash = _sha(digest)

        notif = _get_user_notifications(user_id)
        if notif:
            last_hash = notif.get("last_digest_hash")
            if digest_hash != last_hash and top_new:
                if notif.get("notify_email") and notif.get("email_to"):
                    send_email(to_email=notif["email_to"], subject="Scout: NEW job matches", body=digest)
                if notif.get("notify_telegram") and notif.get("telegram_chat_id"):
                    send_telegram(chat_id=notif["telegram_chat_id"], text="Scout: NEW job matches\n\n" + digest)

                conn = get_conn()
                conn.execute(
                    "UPDATE notifications SET last_digest_hash=?, updated_at=CURRENT_TIMESTAMP WHERE user_id=?",
                    (digest_hash, user_id),
                )
                conn.commit()
                conn.close()

        _set_scan_state(user_id, "ok", next_minutes)

    except Exception as e:
        _set_scan_state(user_id, f"error:{type(e).__name__}", next_minutes)


def scan_all_users():
    conn = get_conn()
    user_ids = [r["id"] for r in conn.execute("SELECT id FROM users").fetchall()]
    conn.close()
    for uid in user_ids:
        scan_user(uid)


def start_scheduler():
    scheduler.add_job(scan_all_users, "interval", minutes=5, id="scan_all_users", replace_existing=True)
    scheduler.start()
