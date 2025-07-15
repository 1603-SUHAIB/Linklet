import smtplib
from email.message import EmailMessage
import os

EMAIL_ADDRESS = os.getenv("MAIL_USER")
EMAIL_PASSWORD = os.getenv("MAIL_PASS")

def send_magic_link(email, link):
    msg = EmailMessage()
    msg['Subject'] = 'Your Linklet Magic Login Link'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    msg.set_content(f"Click to login: {link}")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)

def send_otp(email, otp_code):
    msg = EmailMessage()
    msg['Subject'] = 'Your OTP Code – Linklet'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    msg.set_content(f"Your OTP is: {otp_code}")

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)
