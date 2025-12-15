# db.py
import sqlite3
from pathlib import Path

DB_PATH = Path("scout.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT DEFAULT '',
            location TEXT DEFAULT '',
            target_titles TEXT DEFAULT '[]',
            industries TEXT DEFAULT '[]',
            employment_types TEXT DEFAULT '[]',
            languages TEXT DEFAULT '[]',
            keywords TEXT DEFAULT '[]',
            exclude_keywords TEXT DEFAULT '[]',
            salary_expectation TEXT DEFAULT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user_sources (
            user_id INTEGER NOT NULL,
            source_key TEXT NOT NULL,
            is_enabled INTEGER NOT NULL DEFAULT 0,
            config_json TEXT DEFAULT '{}',
            PRIMARY KEY (user_id, source_key),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS notifications (
            user_id INTEGER PRIMARY KEY,
            notify_email INTEGER NOT NULL DEFAULT 0,
            email_to TEXT DEFAULT NULL,
            notify_telegram INTEGER NOT NULL DEFAULT 0,
            telegram_chat_id TEXT DEFAULT NULL,
            last_digest_hash TEXT DEFAULT NULL,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            user_id INTEGER PRIMARY KEY,
            is_enabled INTEGER NOT NULL DEFAULT 1,
            min_interval_minutes INTEGER NOT NULL DEFAULT 40,
            max_interval_minutes INTEGER NOT NULL DEFAULT 60,
            last_run_at TEXT DEFAULT NULL,
            next_run_at TEXT DEFAULT NULL,
            last_status TEXT DEFAULT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    # --- migrations / 2FA email-or-sms OTP (email works; sms needs provider) ---
    try:
        cur.execute("ALTER TABLE users ADD COLUMN twofa_method TEXT DEFAULT 'email'")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE users ADD COLUMN twofa_enabled INTEGER NOT NULL DEFAULT 0")
    except Exception:
        pass
    try:
        cur.execute("ALTER TABLE profiles ADD COLUMN phone TEXT DEFAULT NULL")
    except Exception:
        pass

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS otp_codes (
            user_id INTEGER PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            attempts_left INTEGER NOT NULL DEFAULT 5,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    # History of seen jobs per user (for "new only" notifications)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS job_seen (
            user_id INTEGER NOT NULL,
            url_hash TEXT NOT NULL,
            url TEXT NOT NULL,
            title TEXT DEFAULT '',
            company TEXT DEFAULT '',
            location TEXT DEFAULT '',
            first_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_score INTEGER DEFAULT NULL,
            PRIMARY KEY (user_id, url_hash),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )

    conn.commit()
    conn.close()
