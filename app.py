# app.py
import os
import json
import secrets
import hashlib
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import init_db, get_conn
from matcher import rank_jobs
from jobs_source import get_jobs
from job_sources_registry import SOURCES
from cv_parser import extract_keywords_from_cv
from scheduler import start_scheduler, scan_user
from notifier import send_email, send_telegram, send_sms

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_A_RANDOM_SECRET"

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

init_db()
start_scheduler()


# ----------------- auth helpers -----------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def get_current_user():
    if "user_id" not in session:
        return None
    conn = get_conn()
    user = conn.execute("SELECT id, email FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return user


def get_user_by_email(email: str):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return row


def get_user_row(user_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    return row


# ----------------- profile helpers -----------------
def parse_csv_field(value: str):
    items = [x.strip() for x in (value or "").split(",")]
    return [x for x in items if x]


def get_profile(user_id: int):
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


def upsert_profile(user_id: int, data: dict):
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO profiles (
            user_id, full_name, location, phone,
            target_titles, industries, employment_types,
            languages, keywords, exclude_keywords,
            salary_expectation
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            full_name=excluded.full_name,
            location=excluded.location,
            phone=excluded.phone,
            target_titles=excluded.target_titles,
            industries=excluded.industries,
            employment_types=excluded.employment_types,
            languages=excluded.languages,
            keywords=excluded.keywords,
            exclude_keywords=excluded.exclude_keywords,
            salary_expectation=excluded.salary_expectation,
            updated_at=CURRENT_TIMESTAMP
        """,
        (
            user_id,
            data.get("full_name", ""),
            data.get("location", ""),
            data.get("phone"),
            json.dumps(data.get("target_titles", [])),
            json.dumps(data.get("industries", [])),
            json.dumps(data.get("employment_types", [])),
            json.dumps(data.get("languages", [])),
            json.dumps(data.get("keywords", [])),
            json.dumps(data.get("exclude_keywords", [])),
            data.get("salary_expectation"),
        ),
    )
    conn.commit()
    conn.close()


# ----------------- settings bootstrap -----------------
def ensure_default_settings(user_id: int):
    conn = get_conn()

    row = conn.execute("SELECT user_id FROM notifications WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        conn.execute(
            """
            INSERT INTO notifications (user_id, notify_email, email_to, notify_telegram, telegram_chat_id)
            VALUES (?, 0, NULL, 0, NULL)
            """,
            (user_id,),
        )

    row = conn.execute("SELECT user_id FROM scans WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO scans (user_id, is_enabled, min_interval_minutes, max_interval_minutes) VALUES (?, 1, 40, 60)",
            (user_id,),
        )

    existing = conn.execute("SELECT source_key FROM user_sources WHERE user_id=?", (user_id,)).fetchall()
    existing_keys = {r["source_key"] for r in existing}
    for key in SOURCES.keys():
        if key not in existing_keys:
            conn.execute(
                "INSERT INTO user_sources (user_id, source_key, is_enabled, config_json) VALUES (?, ?, 0, '{}')",
                (user_id, key),
            )

    conn.commit()
    conn.close()


# ----------------- 2FA (Email/SMS OTP) -----------------
def _utcnow():
    return datetime.utcnow()


def _hash_code(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def otp_create(user_id: int, code: str, minutes_valid: int = 10):
    expires = (_utcnow() + timedelta(minutes=minutes_valid)).isoformat()
    code_hash = _hash_code(code)
    conn = get_conn()
    conn.execute(
        """
        INSERT INTO otp_codes (user_id, code_hash, expires_at, attempts_left)
        VALUES (?, ?, ?, 5)
        ON CONFLICT(user_id) DO UPDATE SET
          code_hash=excluded.code_hash,
          expires_at=excluded.expires_at,
          attempts_left=5,
          created_at=CURRENT_TIMESTAMP
        """,
        (user_id, code_hash, expires),
    )
    conn.commit()
    conn.close()


def otp_get(user_id: int):
    conn = get_conn()
    row = conn.execute("SELECT * FROM otp_codes WHERE user_id=?", (user_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def otp_decrement_attempts(user_id: int):
    conn = get_conn()
    conn.execute("UPDATE otp_codes SET attempts_left = attempts_left - 1 WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()


def otp_delete(user_id: int):
    conn = get_conn()
    conn.execute("DELETE FROM otp_codes WHERE user_id=?", (user_id,))
    conn.commit()
    conn.close()


def otp_verify(user_id: int, code: str) -> tuple[bool, str]:
    row = otp_get(user_id)
    if not row:
        return False, "No OTP session."
    if row["attempts_left"] <= 0:
        return False, "Too many attempts. Please request a new code."

    try:
        expires = datetime.fromisoformat(row["expires_at"])
        if _utcnow() > expires:
            otp_delete(user_id)
            return False, "Code expired. Please request a new code."
    except Exception:
        otp_delete(user_id)
        return False, "Code expired. Please request a new code."

    if _hash_code(code) == row["code_hash"]:
        otp_delete(user_id)
        return True, "OK"

    otp_decrement_attempts(user_id)
    return False, "Invalid code."


def set_twofa_settings(user_id: int, enabled: int, method: str):
    conn = get_conn()
    conn.execute(
        "UPDATE users SET twofa_enabled=?, twofa_method=? WHERE id=?",
        (enabled, method, user_id),
    )
    conn.commit()
    conn.close()


def send_otp_to_user(user_id: int) -> str:
    u = get_user_row(user_id)
    if not u:
        raise RuntimeError("User not found.")

    method = (u["twofa_method"] or "email").strip().lower()
    code = f"{secrets.randbelow(10**6):06d}"
    otp_create(user_id, code, minutes_valid=10)

    message = f"Your Scout verification code is: {code}\nThis code expires in 10 minutes."

    if method == "email":
        send_email(to_email=u["email"], subject="Scout login code", body=message)
        return "email"
    elif method == "sms":
        prof = get_profile(user_id) or {}
        phone = (prof.get("phone") or "").strip()
        if not phone:
            raise RuntimeError("No phone number on profile.")
        send_sms(phone=phone, text=message)
        return "sms"
    else:
        raise RuntimeError("Invalid 2FA method.")


# ----------------- routes -----------------
@app.route("/")
def index():
    return render_template("index.html", user=get_current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            flash("Email and password are required.", "error")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)

        try:
            conn = get_conn()
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, pw_hash))
            conn.commit()
            user_id = cur.lastrowid

            conn.execute("UPDATE users SET twofa_enabled=0, twofa_method='email' WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
        except Exception:
            flash("This email is already registered.", "error")
            return redirect(url_for("register"))

        ensure_default_settings(user_id)
        session["user_id"] = user_id
        return redirect(url_for("onboarding"))

    return render_template("register.html", user=get_current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        user = get_user_by_email(email)
        if not user or not check_password_hash(user["password_hash"], password):
            flash("Invalid email or password.", "error")
            return redirect(url_for("login"))

        ensure_default_settings(user["id"])

        if int(user.get("twofa_enabled", 0)) == 1:
            session["pending_2fa_user_id"] = user["id"]
            try:
                channel = send_otp_to_user(user["id"])
                flash(f"Verification code sent via {channel}.", "ok")
            except Exception as e:
                flash(str(e), "error")
                return redirect(url_for("login"))
            return redirect(url_for("login_2fa"))

        session["user_id"] = user["id"]
        if not get_profile(user["id"]):
            return redirect(url_for("onboarding"))
        return redirect(url_for("dashboard"))

    return render_template("login.html", user=get_current_user())


@app.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        ok, msg = otp_verify(pending_id, code)
        if ok:
            session["user_id"] = pending_id
            session.pop("pending_2fa_user_id", None)

            if not get_profile(pending_id):
                return redirect(url_for("onboarding"))
            return redirect(url_for("dashboard"))
        flash(msg, "error")

    return render_template("otp_login.html", user=None)


@app.route("/login/2fa/resend", methods=["POST"])
def login_2fa_resend():
    pending_id = session.get("pending_2fa_user_id")
    if not pending_id:
        return redirect(url_for("login"))
    try:
        channel = send_otp_to_user(pending_id)
        flash(f"Code resent via {channel}.", "ok")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("login_2fa"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/onboarding", methods=["GET", "POST"])
@login_required
def onboarding():
    user = get_current_user()
    existing = get_profile(user["id"]) or {}

    if request.method == "POST":
        data = {
            "full_name": request.form.get("full_name") or "",
            "location": request.form.get("location") or "",
            "phone": (request.form.get("phone") or "").strip() or None,
            "target_titles": parse_csv_field(request.form.get("target_titles")),
            "industries": parse_csv_field(request.form.get("industries")),
            "employment_types": parse_csv_field(request.form.get("employment_types")),
            "languages": parse_csv_field(request.form.get("languages")),
            "keywords": parse_csv_field(request.form.get("keywords")),
            "exclude_keywords": parse_csv_field(request.form.get("exclude_keywords")),
            "salary_expectation": (request.form.get("salary_expectation") or "").strip() or None,
        }
        upsert_profile(user["id"], data)
        return redirect(url_for("dashboard"))

    return render_template("onboarding.html", user=user, profile=existing)


@app.route("/upload_cv", methods=["POST"])
@login_required
def upload_cv():
    user = get_current_user()
    f = request.files.get("cv")
    if not f or f.filename == "":
        flash("No file uploaded.", "error")
        return redirect(url_for("onboarding"))

    filename = secure_filename(f.filename)
    path = os.path.join(UPLOAD_DIR, f"{user['id']}_{filename}")
    f.save(path)

    new_keywords = extract_keywords_from_cv(path)
    profile = get_profile(user["id"]) or {}

    existing_kw = set(profile.get("keywords") or [])
    for kw in new_keywords:
        existing_kw.add(kw)

    profile_update = {
        "full_name": profile.get("full_name", ""),
        "location": profile.get("location", ""),
        "phone": profile.get("phone"),
        "target_titles": profile.get("target_titles", []),
        "industries": profile.get("industries", []),
        "employment_types": profile.get("employment_types", []),
        "languages": profile.get("languages", []),
        "keywords": sorted(existing_kw),
        "exclude_keywords": profile.get("exclude_keywords", []),
        "salary_expectation": profile.get("salary_expectation"),
    }
    upsert_profile(user["id"], profile_update)

    flash("CV uploaded. Keywords updated.", "ok")
    return redirect(url_for("onboarding"))


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    user = get_current_user()
    ensure_default_settings(user["id"])

    conn = get_conn()

    if request.method == "POST":
        enabled_sources = set(request.form.getlist("sources"))

        for key in SOURCES.keys():
            is_enabled = 1 if key in enabled_sources else 0
            cfg = {}
            for f in SOURCES[key].get("config_fields", []):
                form_key = f"cfg_{key}_{f['key']}"
                val = (request.form.get(form_key) or "").strip()
                if val:
                    cfg[f["key"]] = val

            conn.execute(
                """
                INSERT INTO user_sources (user_id, source_key, is_enabled, config_json)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, source_key) DO UPDATE SET
                  is_enabled=excluded.is_enabled,
                  config_json=excluded.config_json
                """,
                (user["id"], key, is_enabled, json.dumps(cfg)),
            )

        notify_email = 1 if request.form.get("notify_email") == "on" else 0
        email_to = (request.form.get("email_to") or "").strip() or None
        notify_telegram = 1 if request.form.get("notify_telegram") == "on" else 0
        telegram_chat_id = (request.form.get("telegram_chat_id") or "").strip() or None

        conn.execute(
            """
            INSERT INTO notifications (user_id, notify_email, email_to, notify_telegram, telegram_chat_id)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              notify_email=excluded.notify_email,
              email_to=excluded.email_to,
              notify_telegram=excluded.notify_telegram,
              telegram_chat_id=excluded.telegram_chat_id,
              updated_at=CURRENT_TIMESTAMP
            """,
            (user["id"], notify_email, email_to, notify_telegram, telegram_chat_id),
        )

        scans_enabled = 1 if request.form.get("scans_enabled") == "on" else 0
        min_i = int((request.form.get("min_interval") or "40").strip())
        max_i = int((request.form.get("max_interval") or "60").strip())
        if min_i < 5:
            min_i = 5
        if max_i < min_i:
            max_i = min_i

        conn.execute(
            """
            INSERT INTO scans (user_id, is_enabled, min_interval_minutes, max_interval_minutes)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
              is_enabled=excluded.is_enabled,
              min_interval_minutes=excluded.min_interval_minutes,
              max_interval_minutes=excluded.max_interval_minutes
            """,
            (user["id"], scans_enabled, min_i, max_i),
        )

        # 2FA
        twofa_enabled = 1 if request.form.get("twofa_enabled") == "on" else 0
        twofa_method = (request.form.get("twofa_method") or "email").strip().lower()
        if twofa_method not in ("email", "sms"):
            twofa_method = "email"
        conn.execute(
            "UPDATE users SET twofa_enabled=?, twofa_method=? WHERE id=?",
            (twofa_enabled, twofa_method, user["id"]),
        )

        conn.commit()
        flash("Settings saved.", "ok")

    src_rows = conn.execute(
        "SELECT source_key, is_enabled, config_json FROM user_sources WHERE user_id=?",
        (user["id"],),
    ).fetchall()
    src_map = {r["source_key"]: dict(r) for r in src_rows}

    notif = conn.execute("SELECT * FROM notifications WHERE user_id=?", (user["id"],)).fetchone()
    notif = dict(notif) if notif else {}

    scans = conn.execute("SELECT * FROM scans WHERE user_id=?", (user["id"],)).fetchone()
    scans = dict(scans) if scans else {}

    u = conn.execute("SELECT twofa_enabled, twofa_method FROM users WHERE id=?", (user["id"],)).fetchone()
    twofa = dict(u) if u else {"twofa_enabled": 0, "twofa_method": "email"}

    conn.close()

    return render_template(
        "settings.html",
        user=user,
        sources=SOURCES,
        src_map=src_map,
        notif=notif,
        scans=scans,
        twofa=twofa,
        phone=(get_profile(user["id"]) or {}).get("phone"),
    )


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    ensure_default_settings(user["id"])

    profile = get_profile(user["id"])
    if not profile:
        return redirect(url_for("onboarding"))

    conn = get_conn()
    src_rows = conn.execute(
        "SELECT source_key, config_json FROM user_sources WHERE user_id=? AND is_enabled=1",
        (user["id"],),
    ).fetchall()
    conn.close()

    sources = [dict(r) for r in src_rows]
    jobs = get_jobs(sources)
    ranked = rank_jobs(profile, jobs, min_score=35)

    return render_template("dashboard.html", user=user, profile=profile, jobs=ranked, total=len(jobs))


@app.route("/scan_now", methods=["POST"])
@login_required
def scan_now():
    user = get_current_user()
    scan_user(user["id"])
    flash("Scan triggered.", "ok")
    return redirect(url_for("dashboard"))


@app.route("/tools/selectors", methods=["GET", "POST"])
@login_required
def tools_selectors():
    user = get_current_user()
    result = {"error": None, "items": [], "html_title": "", "final_url": ""}

    if request.method == "POST":
        url = (request.form.get("url") or "").strip()
        selector = (request.form.get("selector") or "").strip()
        attr = (request.form.get("attr") or "").strip() or None

        if not url or not selector:
            result["error"] = "URL and selector are required."
            return render_template("tools_selectors.html", user=user, result=result)

        try:
            r = requests.get(url, timeout=25, headers={"User-Agent": "Scout/1.0 (+selector-helper)"})
            r.raise_for_status()
            html = r.text
            soup = BeautifulSoup(html, "html.parser")
            result["html_title"] = (soup.title.get_text(strip=True) if soup.title else "")
            result["final_url"] = r.url

            els = soup.select(selector)[:20]
            items = []
            for el in els:
                text = el.get_text(" ", strip=True)[:200]
                link = None
                if attr:
                    v = el.get(attr)
                    if v:
                        link = v
                else:
                    if el.name == "a" and el.get("href"):
                        link = el.get("href")
                    else:
                        a = el.select_one("a[href]")
                        if a and a.get("href"):
                            link = a.get("href")

                if link and not link.startswith("http"):
                    link = urljoin(r.url, link)

                items.append({"text": text, "link": link, "tag": el.name})
            result["items"] = items

        except Exception as e:
            result["error"] = str(e)

    return render_template("tools_selectors.html", user=user, result=result)


@app.route("/profile")
@login_required
def profile_redirect():
    return redirect(url_for("onboarding"))


if __name__ == "__main__":
    app.run(debug=True)
