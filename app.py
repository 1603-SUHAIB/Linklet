from flask import Flask, render_template, request, redirect, session, url_for
from modules.mailer import send_magic_link, send_otp
from modules.otp_handler import generate_otp, verify_otp
from modules.token_utils import create_magic_token, verify_magic_token, create_session_token
from dotenv import load_dotenv
import os

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", "temp_key")

@app.route('/')
def home():
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        token = create_magic_token(email)
        link = f"http://localhost:5000/verify?token={token}"
        send_magic_link(email, link)
        return render_template("magic_sent.html", email=email)
    return render_template("login.html")

@app.route('/verify')
def verify_link():
    token = request.args.get("token")
    data = verify_magic_token(token)
    if not data:
        return "Invalid or expired token.", 403

    # Simulated risk scoring
    email = data["email"]
    risk_score = 0.7  # hardcoded high-risk for demo
    if risk_score < 0.3:
        session['email'] = email
        return redirect('/dashboard')
    else:
        otp = generate_otp(email)
        send_otp(email, otp)
        return redirect(f"/otp?email={email}")

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    email = request.args.get("email")
    if request.method == 'POST':
        otp_input = request.form['otp']
        email = request.form['email']
        if verify_otp(email, otp_input):
            session['email'] = email
            return redirect('/dashboard')
        else:
            return "Invalid OTP", 401
    return render_template("otp.html", email=email)

@app.route('/dashboard')
def dashboard():
    if 'email' not in session:
        return redirect('/login')
    return render_template("dashboard.html", email=session['email'])

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)