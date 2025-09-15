from flask import Flask, request, render_template, redirect, session, jsonify, url_for, flash, g
import jwt
import smtplib
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
import os
import pyotp
import random
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from functools import wraps
from flask_pymongo import PyMongo
from pymongo import TEXT
from bson.objectid import ObjectId
import qrcode
import io
import base64
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# --- Boilerplate setup ---
load_dotenv()
app = Flask(__name__)
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
if not app.config["MONGO_URI"]:
    raise ValueError("No MONGO_URI set for Flask application")
app.secret_key = os.getenv("FLASK_SECRET", "a_very_strong_and_random_secret_key")
app.config["WTF_CSRF_TIME_LIMIT"] = 1800
EMAIL_ADDRESS = os.getenv("MAIL_USER")
EMAIL_PASSWORD = os.getenv("MAIL_PASS")
JWT_SECRET = os.getenv("JWT_SECRET", "a_secure_jwt_secret_key")

# --- Security Extensions Setup ---
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=os.getenv("MONGO_URI"),
    strategy="fixed-window"
)

# --- Database & OAuth Setup ---
mongo = PyMongo(app)
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# --- Database Indexing ---
with app.app_context():
    mongo.db.magic_tokens.create_index("created_at", expireAfterSeconds=300)
    mongo.db.users.create_index([("email", TEXT)], default_language='english')

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login_page'))
        if not g.user or not g.user.get('is_admin'):
            return render_template('error.html', error_title="Access Denied", error_message="You do not have permission to view this page."), 403
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' not in session:
            flash("Please log in to view this page.", "warning")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def send_email(to_email, subject, body):
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        print(f"🔥🔥🔥 WARNING: Email not sent to {to_email}.")
        return False
    msg = EmailMessage()
    msg['Subject'], msg['From'], msg['To'] = subject, EMAIL_ADDRESS, to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"✅ Email with subject '{subject}' sent to {to_email}")
            return True
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        return False

def get_redirect_url_for_user(email):
    user = mongo.db.users.find_one({"email": email})
    return url_for('admin_panel') if user and user.get('is_admin') else url_for('dashboard')

def create_magic_link_token(email):
    payload = {"email": email, "exp": datetime.now(timezone.utc) + timedelta(minutes=5), "iat": datetime.now(timezone.utc), "jti": os.urandom(16).hex()}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_magic_link_token(token):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        jti = decoded.get("jti")
        if not jti or mongo.db.magic_tokens.find_one({"jti": jti}): return None
        return decoded
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError): return None

def update_user_on_login(email, user_agent, ip_address):
    user = mongo.db.users.find_one({"email": email})
    if not user: return
    update_operation = {"$set": {"last_login": datetime.now(timezone.utc), "last_ip": ip_address, "failed_attempts": 0, "is_locked": False,}}
    known_user_agents = user.get("known_user_agents", [])
    if user_agent not in known_user_agents:
        subject = "Security Alert: New Login to Your Linklet Account"
        body = f"Hello,\n\nWe detected a new login to your account from a device we don't recognize.\n\nDevice: {user_agent}\nTime: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n\nIf this was you, you can safely ignore this email. If you don't recognize this activity, please secure your account immediately.\n\nThanks,\nThe Linklet Team"
        send_email(email, subject, body)
        update_operation["$push"] = {"known_user_agents": user_agent}
    mongo.db.users.update_one({"email": email}, update_operation)

# --- Global App Hooks ---
@app.before_request
def load_logged_in_user():
    user_email = session.get('email')
    g.user = mongo.db.users.find_one({"email": user_email}) if user_email else None

@app.after_request
def inject_csrf_token(response):
    if hasattr(response, 'get_data') and 'text/html' in response.content_type:
        response.set_data(response.get_data().replace(b'__CSRF_TOKEN_PLACEHOLDER__', generate_csrf().encode('utf-8')))
    return response

# ========================================
#  Captcha Route
# ========================================
@app.route('/api/rotation-captcha', methods=['GET'])
@limiter.limit("30 per minute")
def get_rotation_captcha_challenge():
    ROTATION_DEGREES = [0, 45, 90, 135, 180, 225, 270, 315]
    
    target_rotation = random.choice(ROTATION_DEGREES)
    # Ensure initial rotation is different from the target
    initial_rotation = random.choice([r for r in ROTATION_DEGREES if r != target_rotation])
    
    session['captcha_answer'] = target_rotation
    
    return jsonify({
        "prompt": "Use the arrows to rotate the image to match the direction of the hand.",
        "initial_rotation": initial_rotation,
        "target_rotation": target_rotation
    })

# ========================================
#  Flask Routes
# ========================================
@app.route('/')
def home():
    return render_template("landing.html")

@app.route('/login', methods=['GET'])
def login_page():
    if 'email' in session:
        return redirect(get_redirect_url_for_user(session['email']))
    return render_template("login.html")

@app.route('/api/login/email', methods=['POST'])
@limiter.limit("10 per minute")
def handle_email_submission():
    # --- Captcha Verification ---
    correct_rotation = session.pop('captcha_answer', None)
    user_rotation_str = request.json.get('captcha_rotation')

    try:
        user_rotation = int(user_rotation_str)
    except (ValueError, TypeError):
        user_rotation = -1 # Invalid format

    if correct_rotation is None or user_rotation != correct_rotation:
        return jsonify({"success": False, "reason": "captcha_failed", "error": "Incorrect captcha. Please try again."}), 400

    email = request.json.get('email')
    if not email:
        return jsonify({"success": False, "error": "Email is required."}), 400
    user = mongo.db.users.find_one({"email": email})
    if not user:
        return jsonify({"success": False, "reason": "not_found", "message": "Account not found. Please request access first."})
    if not user.get("is_approved"):
        return jsonify({"success": False, "reason": "not_approved", "message": "Your account is pending administrator approval."})
    if user.get("is_locked"):
        locked_until = user.get("locked_until")
        if locked_until and datetime.now(timezone.utc) < locked_until:
            return jsonify({"success": False, "error": f"Your account is temporarily locked. Please try again later."}), 429
        else:
            mongo.db.users.update_one({"email": email}, {"$set": {"is_locked": False, "failed_attempts": 0}})
    session['login_email'] = email
    action = "setup_2fa" if not user.get('totp_secret') else "enter_totp"
    return jsonify({"success": True, "action": action})

@app.route('/setup-2fa', methods=['GET', 'POST'])
@csrf.exempt
def setup_2fa():
    if 'login_email' not in session: return redirect(url_for('login_page'))
    email = session['login_email']
    if request.method == 'POST':
        csrf.protect()
        otp_code = request.form.get('otp')
        temp_secret = session.get('temp_totp_secret')
        if not temp_secret or not otp_code:
            flash("Session expired or invalid code. Please try again.", "error")
            return redirect(url_for('setup_2fa'))
        if pyotp.TOTP(temp_secret).verify(otp_code):
            mongo.db.users.update_one({'email': email}, {'$set': {'totp_secret': temp_secret}})
            session.pop('temp_totp_secret', None)
            flash("Two-factor authentication set up successfully! Please log in.", "success")
            return redirect(url_for('login_page'))
        else:
            flash("The code was incorrect. Please try again.", "error")
            return redirect(url_for('setup_2fa'))
    temp_secret = pyotp.random_base32()
    session['temp_totp_secret'] = temp_secret
    provisioning_uri = pyotp.TOTP(temp_secret).provisioning_uri(name=email, issuer_name='LinkletApp')
    img = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return render_template('setup_2fa.html', qr_code_image=img_str, secret_key=temp_secret)

@app.route('/api/login/totp', methods=['POST'])
@limiter.limit("5 per 5 minutes", key_func=lambda: session.get('login_email') or get_remote_address())
def handle_totp_verification():
    email = session.get('login_email')
    otp_code = request.json.get('otp')
    if not email: return jsonify({"success": False, "error": "Session expired. Please start over."}), 400
    user = mongo.db.users.find_one({"email": email})
    if not user or not user.get('totp_secret'): return jsonify({"success": False, "error": "2FA is not set up for this account."}), 400
    if pyotp.TOTP(user['totp_secret']).verify(otp_code):
        session['2fa_passed_email'] = email
        session.pop('login_email', None)
        return jsonify({"success": True, "message": "Verification successful."})
    else:
        failed_attempts = user.get("failed_attempts", 0) + 1
        if failed_attempts >= 5:
            locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
            mongo.db.users.update_one({"email": email}, {"$set": {"is_locked": True, "locked_until": locked_until, "failed_attempts": failed_attempts}})
            return jsonify({"success": False, "error": "Too many failed attempts. Your account has been locked for 15 minutes."}), 429
        else:
            mongo.db.users.update_one({"email": email}, {"$set": {"failed_attempts": failed_attempts}})
            return jsonify({"success": False, "error": "The code is incorrect or has expired."})

@app.route('/api/send-magic-link', methods=['POST'])
@limiter.limit("3 per 10 minutes", key_func=lambda: session.get('2fa_passed_email') or get_remote_address())
def issue_magic_link():
    email = session.get('2fa_passed_email')
    if not email: return jsonify({"success": False, "error": "Authentication failed. Please start over."}), 403
    token = create_magic_link_token(email)
    magic_link = url_for('verify_link', token=token, _external=True)
    subject = "Your Login Link – Linklet"
    body = f"Hello,\n\nClick the login link below to sign in:\n\n{magic_link}\n\nThis link is for one-time use and will expire in 5 minutes."
    send_email(email, subject, body)
    return jsonify({"success": True, "message": f"A link has been sent to {email}."})

@app.route('/verify-link')
def verify_link():
    token = request.args.get('token')
    payload = verify_magic_link_token(token)
    if not payload: return render_template("error.html", error_title="Link Invalid", error_message="This link is invalid, expired, or has already been used."), 403
    email = payload["email"]
    mongo.db.magic_tokens.insert_one({"jti": payload["jti"], "created_at": datetime.now(timezone.utc)})
    session.clear()
    session['email'] = email
    update_user_on_login(email, request.user_agent.string, request.remote_addr)
    flash("You have been logged in successfully!", "success")
    return redirect(get_redirect_url_for_user(email))

@app.route('/login/google')
def login_google():
    if '2fa_passed_email' not in session:
        flash("Please complete the first step of authentication.", "warning")
        return redirect(url_for('login_page'))
    redirect_uri = url_for('auth_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/auth/google/callback')
def auth_callback():
    if '2fa_passed_email' not in session: return render_template("error.html", error_title="Authentication Error", error_message="Your session is invalid. Please start over."), 400
    expected_email = session['2fa_passed_email']
    try:
        token = oauth.google.authorize_access_token()
        google_email = token.get('userinfo').get('email')
        if not google_email or google_email.lower() != expected_email.lower():
            return render_template("error.html", error_title="Account Mismatch", error_message="You authenticated with a different Google account."), 400
        session.clear()
        session['email'] = expected_email
        update_user_on_login(expected_email, request.user_agent.string, request.remote_addr)
        flash("You have been logged in successfully!", "success")
        return redirect(get_redirect_url_for_user(expected_email))
    except Exception as e:
        print(f"OAuth callback error: {e}")
        return render_template("error.html", error_title="Authentication Error", error_message="An error occurred during Google authentication."), 500

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", user=g.user)

# --- Admin Panel Routes ---
@app.route('/admin')
@admin_required
def admin_panel():
    all_users = list(mongo.db.users.find().sort("created_at", -1))
    return render_template('admin.html', all_users=all_users)

@app.route('/admin/approve/<user_id>', methods=['POST'])
@admin_required
def approve_user(user_id):
    mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_approved": True}})
    flash("User has been approved.", "success")
    return redirect(url_for('admin_panel'))

@app.route('/admin/create_user', methods=['POST'])
@admin_required
def create_user():
    email = request.form.get('email')
    is_admin = request.form.get('is_admin') == 'on'
    if not email:
        flash("Email is required.", 'error')
        return redirect(url_for('admin_panel'))
    if mongo.db.users.find_one({"email": email}):
        flash(f"User with email {email} already exists.", 'error')
        return redirect(url_for('admin_panel'))
    mongo.db.users.insert_one({
        "email": email, "is_admin": is_admin, "is_approved": True, "totp_secret": None,
        "user_agent": "Created by admin", "created_at": datetime.now(timezone.utc), "last_login": None,
        "is_locked": False, "failed_attempts": 0, "known_user_agents": []
    })
    flash(f"User {email} has been created and approved.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user_to_edit = mongo.db.users.find_one_or_404({"_id": ObjectId(user_id)})
    if request.method == 'POST':
        new_is_admin = request.form.get('is_admin') == 'on'
        if user_to_edit['email'] == g.user['email'] and not new_is_admin:
            admin_count = mongo.db.users.count_documents({'is_admin': True})
            if admin_count <= 1:
                flash("You cannot remove your own admin status as you are the only admin.", 'error')
                return redirect(url_for('edit_user', user_id=user_id))
        mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_admin": new_is_admin}})
        flash(f"User {user_to_edit['email']} has been updated.", 'success')
        return redirect(url_for('admin_panel'))
    return render_template('edit_user.html', user_to_edit=user_to_edit)

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user_to_delete = mongo.db.users.find_one_or_404({"_id": ObjectId(user_id)})
    if user_to_delete['email'] == g.user['email']:
        flash("You cannot delete your own account from the admin panel.", 'error')
        return redirect(url_for('admin_panel'))
    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    flash(f"User {user_to_delete['email']} has been deleted.", 'success')
    return redirect(url_for('admin_panel'))

# --- Other Routes ---
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"success": True, "redirect_url": url_for('home')})

@app.route('/request-access', methods=['GET', 'POST'])
def request_access_page():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("Email is required to request access.", "error")
            return redirect(url_for('request_access_page'))
        existing_user = mongo.db.users.find_one({"email": email})
        if existing_user:
            if existing_user.get('is_approved'):
                flash("This account already exists and is approved. Please try logging in.", "info")
                return redirect(url_for('login_page'))
            else:
                flash("An access request for this email already exists and is pending approval.", "info")
                return redirect(url_for('request_access_page'))
        mongo.db.users.insert_one({
            "email": email, "is_admin": False, "is_approved": False, "totp_secret": None,
            "user_agent": "Access Request", "created_at": datetime.now(timezone.utc), "last_login": None,
            "is_locked": False, "failed_attempts": 0, "known_user_agents": []
        })
        flash("Your access request has been submitted. An administrator will review it shortly.", "success")
        return redirect(url_for('home'))
    return render_template('request_access.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
