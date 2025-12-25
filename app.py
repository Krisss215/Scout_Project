# =========================
# DROP-IN FIX (FULL CODE)
# Paste this over your existing /login route (and helpers) in app.py
# =========================

import os
import sqlite3
from flask import Flask, render_template, redirect, url_for, flash, request, session

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

# --- DB helpers (SQLite) ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "scout.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # returns sqlite3.Row
    return conn

def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None

def get_user_by_email(email: str) -> dict | None:
    email = (email or "").strip().lower()
    if not email:
        return None
    conn = get_db()
    try:
        cur = conn.execute("SELECT * FROM users WHERE lower(email)=?", (email,))
        row = cur.fetchone()
        return row_to_dict(row)  # ✅ dict so .get works
    finally:
        conn.close()

# --- Password verify placeholder (replace with your real one) ---
def verify_password(plain: str, stored_hash: str) -> bool:
    # If you already use werkzeug.security.check_password_hash, replace this function with it.
    from werkzeug.security import check_password_hash
    return check_password_hash(stored_hash, plain)

# --- Flask-WTF form placeholders (replace imports if you already have forms) ---
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=128)])
    submit = SubmitField("Login")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = (form.email.data or "").strip().lower()
        password = form.password.data or ""

        user = get_user_by_email(email)  # ✅ dict or None

        if not user:
            flash("Invalid email or password", "error")
            return render_template("login.html", form=form)

        # Adjust the column name to your DB schema:
        # common: password_hash / password / hash
        stored_hash = user.get("password_hash") or user.get("password") or user.get("hash")
        if not stored_hash:
            flash("Account misconfigured (missing password hash).", "error")
            return render_template("login.html", form=form)

        if not verify_password(password, stored_hash):
            flash("Invalid email or password", "error")
            return render_template("login.html", form=form)

        # ✅ FIX: now .get exists safely because user is dict
        twofa_enabled = int(user.get("twofa_enabled", 0) or 0)
        session["user_id"] = user.get("id")

        if twofa_enabled == 1:
            # If you have a 2FA flow, redirect there
            return redirect(url_for("twofa_verify"))  # make sure this route exists

        flash("Logged in!", "success")
        return redirect(url_for("home"))

    # If POST but failed validation
    if request.method == "POST":
        flash("Please check the form fields.", "error")

    return render_template("login.html", form=form)
