import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

load_dotenv()

email = os.getenv("EMAIL_USERNAME")
password = os.getenv("EMAIL_PASSWORD")

msg = MIMEText("Test email")
msg["Subject"] = "OTP Test"
msg["From"] = email
msg["To"] = email

try:
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(email, password)
        server.sendmail(email, email, msg.as_string())
    print("Email sent successfully.")
except Exception as e:
    print("Failed to send:", e)
