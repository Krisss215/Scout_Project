# notifier.py
import os
import smtplib
from email.mime.text import MIMEText
import requests


def send_email(to_email: str, subject: str, body: str):
    smtp_host = os.environ.get("SMTP_HOST")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER")
    smtp_pass = os.environ.get("SMTP_PASS")
    from_email = os.environ.get("SMTP_FROM", smtp_user)

    if not all([smtp_host, smtp_user, smtp_pass, from_email]):
        raise RuntimeError("Email not configured. Set SMTP_HOST/SMTP_USER/SMTP_PASS/SMTP_FROM.")

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, [to_email], msg.as_string())


def send_telegram(chat_id: str, text: str):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("Telegram not configured. Set TELEGRAM_BOT_TOKEN.")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    r = requests.post(url, json={"chat_id": chat_id, "text": text})
    if r.status_code != 200:
        raise RuntimeError(f"Telegram send failed: {r.status_code} {r.text}")


def send_sms(phone: str, text: str):
    """
    SMS requires an external provider (Twilio/Vonage/AWS SNS).
    Implement this function with your provider.
    """
    raise RuntimeError("SMS not configured. Implement send_sms() with an SMS provider.")
