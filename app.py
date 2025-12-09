from flask import Flask, render_template, request
from cv_parser import extract_cv_text
from matcher import compute_matches
from jobs_source import get_sample_jobs
import uuid
import json
from pathlib import Path
from datetime import datetime

app = Flask(__name__)

PROFILES_DB = Path("profiles.json")


def load_profiles():
    if PROFILES_DB.exists():
        with PROFILES_DB.open("r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_profiles(profiles: dict):
    with PROFILES_DB.open("w", encoding="utf-8") as f:
        json.dump(profiles, f, ensure_ascii=False, indent=2)


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


@app.route("/setup", methods=["POST"])
def setup_agent():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    desired_roles = request.form.get("desired_roles", "").strip()
    location = request.form.get("location", "").strip()
    work_mode = request.form.get("work_mode", "any")
    frequency = request.form.get("frequency", "60")

    cv_file = request.files.get("cv_file")

    if not cv_file:
        return render_template("index.html", error="Please upload your CV file.")

    if not desired_roles:
        return render_template(
            "index.html",
            error="Please describe what you are looking for (roles / tech)."
        )

    cv_filename = f"uploaded_cv_{cv_file.filename}"
    cv_path = Path(cv_filename)
    cv_file.save(cv_path)

    try:
        cv_text = extract_cv_text(cv_path)
    except Exception as e:
        return render_template("index.html", error=f"Error reading CV: {e}")

    # Combine CV text + desired roles to represent "who you are + what you want"
    profile_text = cv_text + "\n\nDesired roles & preferences:\n" + desired_roles

    # "Connect job boards": currently sample jobs; later → real APIs
    all_jobs = get_sample_jobs()

    # Rank matches for this profile
    matches = compute_matches(profile_text, all_jobs)
    top_matches = matches[:5]  # show top 5

    profile_id = str(uuid.uuid4())
    profiles = load_profiles()

    profiles[profile_id] = {
        "id": profile_id,
        "name": name,
        "email": email,
        "desired_roles": desired_roles,
        "location": location,
        "work_mode": work_mode,
        "frequency_minutes": int(frequency),
        "cv_path": str(cv_path),
        "cv_text_sample": cv_text[:1500],
        "created_at": datetime.utcnow().isoformat() + "Z",
    }

    save_profiles(profiles)

    profile = profiles[profile_id]

    # "Send alerts" will later mean: email / Telegram. For now we show them on the dashboard.
    return render_template(
        "dashboard.html",
        profile=profile,
        matches=top_matches,
    )


if __name__ == "__main__":
    app.run(debug=True)
