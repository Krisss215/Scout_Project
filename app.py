import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_wtf.csrf import CSRFProtect

# If you already have your own forms, keep them.
# But make sure your templates include {{ form.hidden_tag() }}.

from forms import LoginForm, RegisterForm  # <-- create forms.py from below

app = Flask(__name__)

# ✅ MUST: stable secret key (Render ENV) for sessions + CSRF to work
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")

# Optional but recommended behind proxies (Render)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True  # Render is HTTPS

# ✅ Enable CSRF protection globally
csrf = CSRFProtect(app)


@app.get("/")
def home():
    return render_template("index.html")


@app.get("/login")
@app.post("/login")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # TODO: replace with your real auth logic
        flash("Logged in (demo).", "success")
        return redirect(url_for("home"))

    # If POST failed validation, show errors
    if request.method == "POST":
        flash("Login failed. Please check the form.", "error")

    return render_template("login.html", form=form)


@app.get("/register")
@app.post("/register")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        # TODO: replace with your real user creation logic
        flash("Registered (demo). You can now login.", "success")
        return redirect(url_for("login"))

    if request.method == "POST":
        flash("Register failed. Please check the form.", "error")

    return render_template("register.html", form=form)


# (Optional) friendlier CSRF error message instead of plain "Bad Request"
from flask_wtf.csrf import CSRFError

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # Show a proper page instead of raw 400
    return (
        render_template("csrf_error.html", reason=e.description),
        400
    )


if __name__ == "__main__":
    # Local dev only
    app.run(host="0.0.0.0", port=5000)
