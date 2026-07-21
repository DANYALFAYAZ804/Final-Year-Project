"""
Trust-Flow Backend — Flask REST API
ML prediction with whitelist fast-pass and heuristic fallback.
"""

import re
import math
import os
import time
import pymysql
from datetime import datetime
import joblib
import numpy as np
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from urllib.parse import urlparse

app = Flask(__name__)

# Restrict credentialed cross-origin requests to an explicit allowlist.
# supports_credentials=True combined with an unrestricted origin lets ANY
# website's JS make session-cookie-bearing requests against this public
# API. The Electron client's fetch() calls run in the Node main process
# (not a browser page), so they never send an Origin header and are
# unaffected by this — tightening it only closes the gap for third-party
# browser pages hitting the public backend directly.
CORS_ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
CORS(app, supports_credentials=True, origins=CORS_ALLOWED_ORIGINS)

# Session-signing key. A hardcoded secret means anyone who reads this file
# (or the public repo) can forge session cookies. Overridable via env var.
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'dev-only-insecure-secret-key-change-me'
if not os.environ.get('FLASK_SECRET_KEY'):
    print("[Auth] WARNING: FLASK_SECRET_KEY not set — using an insecure default. Set it in production.")

# Database URI — defaults to the local XAMPP MySQL install for dev, but is
# overridable via DATABASE_URL for any deployed environment (e.g. Railway),
# where 'localhost:3306' never resolves to a real MySQL server.
_db_url = os.environ.get('DATABASE_URL', 'mysql+pymysql://root:@localhost:3306/trust_flow_db')
if _db_url.startswith('mysql://'):
    _db_url = _db_url.replace('mysql://', 'mysql+pymysql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

EMAIL_REGEX = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')

# "Stay logged in" session tokens — signed + timestamped via itsdangerous,
# using the same app.secret_key already required above. No separate
# sessions table is needed: the token itself carries the user id and an
# embedded issue time, and itsdangerous's max_age check on .loads()
# enforces expiry cryptographically (a tampered/forged expiry can't pass
# signature verification). 30 days chosen per the "Stay logged in" spec.
SESSION_TOKEN_MAX_AGE_SECONDS = 30 * 24 * 60 * 60  # 30 days
_session_serializer = URLSafeTimedSerializer(app.secret_key, salt='trustflow-session')


def issue_session_token(user_id):
    """Returns (token, expires_at_ms) — expires_at is in epoch milliseconds
    so the Electron client can compare it directly against Date.now()."""
    token = _session_serializer.dumps({'user_id': user_id})
    expires_at_ms = int((time.time() + SESSION_TOKEN_MAX_AGE_SECONDS) * 1000)
    return token, expires_at_ms


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "Trust Flow Backend is Running"
    })


# ─────────────────────────────────────────────
# DATABASE MODELS — XAMPP MySQL
# ─────────────────────────────────────────────
class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    last_login_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)


class LoginHistory(db.Model):
    """Audit trail of login attempts — one row per attempt, success or
    failure, for the security-review/'who logged in when from where'
    use case. Only written for attempts against a real, existing account
    (an unknown-email attempt has no user_id to attach it to)."""
    __tablename__ = 'login_history'
    login_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    ip_address = db.Column(db.String(45))  # 45 chars fits a full IPv6 address
    login_status = db.Column(db.String(10), nullable=False)  # 'success' | 'failed'
    logged_in_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


class UserScan(db.Model):
    __tablename__ = 'user_scans'
    scan_id = db.Column(db.BigInteger, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    scanned_url = db.Column(db.Text, nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    verdict = db.Column(db.String(50), nullable=False)
    threat_score = db.Column(db.Numeric(5, 2), default=0.00)
    scanned_at = db.Column(db.DateTime, default=datetime.now, nullable=False)


def ensure_database_exists():
    """A fresh XAMPP MySQL install won't already have 'trust_flow_db', and
    SQLAlchemy's create_all() only creates tables — not the database itself.
    Without this, connecting fails with an 'Unknown database' error."""
    parsed  = urlparse(app.config['SQLALCHEMY_DATABASE_URI'])
    db_name = parsed.path.lstrip('/')
    conn = pymysql.connect(
        host=parsed.hostname or 'localhost',
        port=parsed.port or 3306,
        user=parsed.username or 'root',
        password=parsed.password or '',
    )
    try:
        with conn.cursor() as cur:
            cur.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}`")
        conn.commit()
    finally:
        conn.close()


# Runs at import time (module level) so both `python app.py` and a
# production WSGI server (gunicorn) get the database/tables ready before
# the first request arrives — wrapped so a MySQL/XAMPP outage doesn't take
# down the ML endpoints, which don't depend on the database.
try:
    # ensure_database_exists() speaks raw pymysql — only relevant when the
    # configured URI is actually MySQL (the local XAMPP default or a real
    # deployment). Calling it against a non-MySQL DATABASE_URL would just
    # fail and skip table creation entirely.
    if _db_url.startswith('mysql'):
        ensure_database_exists()
    with app.app_context():
        db.create_all()
    print(f"[DB] Connected — tables ready ({_db_url.split('://')[0]}).")
except Exception as e:
    print(f"[DB] WARNING: could not initialize the database — {e}")


# ─────────────────────────────────────────────
# AUTHENTICATION ROUTES
# ─────────────────────────────────────────────
@app.route('/auth/check-email', methods=['POST'])
def check_email():
    """
    Step 1: Search database for user email.
    If found -> Allow Login.
    If not found -> Redirect to Sign Up.
    """
    data = request.get_json(force=True) or {}
    email = data.get('email', '').strip().lower()

    if not email or not EMAIL_REGEX.match(email):
        return jsonify({"status": "error", "message": "A valid email address is required"}), 400

    # Search database for existing user
    try:
        existing_user = User.query.filter_by(email=email).first()
    except SQLAlchemyError:
        return jsonify({"status": "error", "message": "Database is temporarily unavailable. Please try again shortly."}), 503

    if existing_user:
        return jsonify({
            "status": "user_exists",
            "action": "login",
            "message": "Account found! Please enter your password to log in.",
            "email": email
        }), 200
    else:
        return jsonify({
            "status": "user_not_found",
            "action": "signup",
            "message": "No account found with this email. Please sign up first.",
            "email": email
        }), 404


@app.route('/auth/login', methods=['POST'])
def login():
    """ Step 2A: Direct Login if account exists """
    data = request.get_json(force=True) or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    # Without this, a missing/empty password reaches check_password_hash()
    # below, which raises a TypeError on a non-string argument — an
    # unhandled exception (HTML 500) instead of a clean error message.
    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required"}), 400

    try:
        user = User.query.filter_by(email=email).first()
    except SQLAlchemyError:
        return jsonify({"status": "error", "message": "Database is temporarily unavailable. Please try again shortly."}), 503

    if not user:
        return jsonify({"status": "error", "message": "No account found. Please sign up."}), 404

    if not user.is_active:
        return jsonify({"status": "error", "message": "This account has been deactivated."}), 403

    if check_password_hash(user.password_hash, password):
        # Update last login timestamp and record the successful attempt.
        try:
            user.last_login_at = datetime.now()
            db.session.add(LoginHistory(user_id=user.user_id, ip_address=request.remote_addr, login_status='success'))
            db.session.commit()
        except SQLAlchemyError:
            db.session.rollback()
            # Non-critical — still let the user in even if the timestamp/audit-log update failed.

        # Save active session
        session['user_id'] = user.user_id
        session['user_name'] = user.full_name

        # Always issue a session token — whether the client persists it
        # locally (for "Stay logged in") is entirely the client's choice;
        # issuing it unconditionally keeps this endpoint's behavior uniform.
        session_token, expires_at = issue_session_token(user.user_id)

        return jsonify({
            "status": "success",
            "message": f"Welcome back, {user.full_name}!",
            "user_id": user.user_id,
            "session_token": session_token,
            "expires_at": expires_at
        }), 200

    # Record the failed attempt too, but never let a logging failure mask
    # the actual "incorrect password" response the user needs to see.
    try:
        db.session.add(LoginHistory(user_id=user.user_id, ip_address=request.remote_addr, login_status='failed'))
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()

    return jsonify({"status": "error", "message": "Incorrect password. Please try again."}), 401


@app.route('/auth/signup', methods=['POST'])
def signup():
    """ Step 2B: Register new account if not found """
    data = request.get_json(force=True) or {}
    email = data.get('email', '').strip().lower()
    full_name = data.get('full_name')
    password = data.get('password')

    if not email or not EMAIL_REGEX.match(email) or not password or not full_name:
        return jsonify({"status": "error", "message": "A valid email, full name and password are required"}), 400

    # Double check if user registered in the meantime
    try:
        if User.query.filter_by(email=email).first():
            return jsonify({"status": "error", "message": "Account already exists! Please log in."}), 400
    except SQLAlchemyError:
        return jsonify({"status": "error", "message": "Database is temporarily unavailable. Please try again shortly."}), 503

    hashed_pwd = generate_password_hash(password)
    new_user = User(full_name=full_name, email=email, password_hash=hashed_pwd)

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        # Another request registered the same email in the gap between the
        # check above and this commit — the DB's unique constraint on email
        # is what actually prevents the duplicate; without this handler the
        # request would fail with an unhandled 500 instead of a clean error.
        db.session.rollback()
        return jsonify({"status": "error", "message": "Account already exists! Please log in."}), 400
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Could not create account. Please try again."}), 500

    # Automatically log them in after signup
    session['user_id'] = new_user.user_id
    session['user_name'] = new_user.full_name

    session_token, expires_at = issue_session_token(new_user.user_id)

    return jsonify({
        "status": "success",
        "message": f"Account created successfully! Welcome, {new_user.full_name}.",
        "user_id": new_user.user_id,
        "session_token": session_token,
        "expires_at": expires_at
    }), 201


@app.route('/auth/validate-session', methods=['POST'])
def validate_session():
    """
    Validates a locally-persisted "Stay logged in" token on app launch.
    The client is expected to also check the expiry timestamp itself
    before even calling this, but the token's expiry is re-checked here
    server-side too (via max_age) so a stale/forged local flag can never
    bypass login on its own.
    """
    data = request.get_json(force=True) or {}
    token = data.get('session_token')

    if not token:
        return jsonify({"status": "error", "message": "No session token provided"}), 400

    try:
        payload = _session_serializer.loads(token, max_age=SESSION_TOKEN_MAX_AGE_SECONDS)
    except SignatureExpired:
        return jsonify({"status": "error", "message": "Session expired. Please log in again."}), 401
    except BadSignature:
        return jsonify({"status": "error", "message": "Invalid session token."}), 401

    try:
        user = User.query.get(payload.get('user_id'))
    except SQLAlchemyError:
        return jsonify({"status": "error", "message": "Database is temporarily unavailable. Please try again shortly."}), 503

    if not user:
        return jsonify({"status": "error", "message": "Account no longer exists."}), 401

    return jsonify({
        "status": "success",
        "user_id": user.user_id,
        "email": user.email,
        "full_name": user.full_name
    }), 200


@app.route('/scan-url', methods=['POST'])
def scan_url():
    """
    Persists a completed scan under the account identified by
    session_token. This deliberately does NOT use Flask's cookie-based
    `session` (unlike login()/signup() above, which set it for
    completeness) — the Electron client's main-process fetch() calls
    never send/receive cookies, so a cookie-session check here would
    silently reject every real caller. The token is the same one already
    issued by /auth/login and /auth/signup, decoded the same way
    /auth/validate-session does.

    The verdict/threat_score are supplied by the caller rather than
    recomputed here: the Electron app's own ML/WHOIS/VirusTotal trust
    score engine has already produced them, so this endpoint's job is
    only to store that result under the right user, not to re-derive it.
    """
    data = request.get_json(force=True) or {}
    token = data.get('session_token')
    if not token:
        return jsonify({"status": "error", "message": "Not logged in."}), 401

    try:
        payload = _session_serializer.loads(token, max_age=SESSION_TOKEN_MAX_AGE_SECONDS)
    except (SignatureExpired, BadSignature):
        return jsonify({"status": "error", "message": "Session expired or invalid. Please log in again."}), 401

    current_user_id = payload.get('user_id')

    url_to_scan = (data.get('url') or '').strip()
    if not url_to_scan:
        return jsonify({"status": "error", "message": "URL is required"}), 400

    verdict = data.get('verdict') or 'suspicious'
    if verdict not in ('safe', 'suspicious', 'malicious', 'phishing'):
        verdict = 'suspicious'

    try:
        threat_score = float(data.get('threat_score', 0))
    except (TypeError, ValueError):
        threat_score = 0.0
    threat_score = max(0.0, min(100.0, threat_score))

    domain = urlparse(url_to_scan).netloc or url_to_scan

    scan_record = UserScan(
        user_id=current_user_id,
        scanned_url=url_to_scan,
        domain=domain,
        verdict=verdict,
        threat_score=threat_score
    )
    try:
        db.session.add(scan_record)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Failed to save scan record"}), 500

    return jsonify({"status": "success"}), 200


@app.route('/my-stats', methods=['GET'])
def my_stats():
    """ Returns the logged-in user's scan summary — requires session_token
    as a query param since this is a GET request with no body. """
    token = request.args.get('session_token')
    if not token:
        return jsonify({"error": "Not logged in."}), 401

    try:
        payload = _session_serializer.loads(token, max_age=SESSION_TOKEN_MAX_AGE_SECONDS)
    except (SignatureExpired, BadSignature):
        return jsonify({"error": "Session expired or invalid. Please log in again."}), 401

    current_user_id = payload.get('user_id')

    try:
        scans = UserScan.query.filter_by(user_id=current_user_id).all()
    except SQLAlchemyError:
        return jsonify({"error": "Database is temporarily unavailable. Please try again shortly."}), 503

    return jsonify({
        "total_searched": len(scans),
        "total_safe": sum(1 for s in scans if s.verdict == 'safe'),
        "total_phishing": sum(1 for s in scans if s.verdict in ('phishing', 'malicious')),
        "total_suspicious": sum(1 for s in scans if s.verdict == 'suspicious'),
    })


# ─────────────────────────────────────────────
# Feature extraction — 45 features (v4.0, matches train.py)
# ─────────────────────────────────────────────
TLD_REPUTATION = {

    'gov': 1.0, 'mil': 1.0, 'edu': 0.95,
    'com': 0.80, 'org': 0.78, 'net': 0.75,
    'int': 0.90, 'uk':  0.80, 'de':  0.80,
    'fr':  0.78, 'jp':  0.78, 'ca':  0.80,
    'au':  0.80, 'us':  0.78, 'eu':  0.80,
    'io':  0.72, 'co':  0.70, 'me':  0.65,
    'info': 0.55, 'mobi': 0.55, 'biz': 0.50,
    'xyz': 0.20, 'top': 0.20, 'ru':  0.18,
    'tk':  0.05, 'ml':  0.05, 'ga':  0.05,
    'cf':  0.05, 'gq':  0.05, 'pw':  0.10,
    'cc':  0.15, 'click': 0.10, 'link': 0.15,
    'work': 0.15, 'date': 0.10, 'bid': 0.10,
    'trade': 0.10, 'stream': 0.12, 'loan': 0.08,
    'download': 0.08, 'racing': 0.08, 'icu': 0.10,
    'cam': 0.10, 'men': 0.10, 'review': 0.15,
    'accountant': 0.08, 'monster': 0.15, 'buzz': 0.15,
    'party': 0.08, 'win': 0.10, 'zone': 0.20,
    'club': 0.20, 'online': 0.25, 'site': 0.25,
}

BRAND_SLDS = [
    'google','paypal','microsoft','apple','amazon','facebook',
    'netflix','instagram','twitter','linkedin','dropbox','icloud',
    'ebay','chase','wellsfargo','bankofamerica','citibank','hsbc',
    'steam','spotify','coinbase','binance','tiktok','snapchat',
    'whatsapp','youtube','reddit','discord','slack','zoom',
    'adobe','oracle','salesforce','shopify','wordpress','squarespace',
    'cloudflare','github','gitlab','bitbucket','atlassian','jira',
    'stripe','twilio','sendgrid','mailchimp','hubspot','zendesk',
    'okta','docusign',
]

BRAND_KEYWORDS = [
    'paypal','google','microsoft','apple','amazon','facebook',
    'netflix','instagram','twitter','linkedin','bank','secure',
    'signin','login','verify','update','account','webscr',
    'ebay','chase','wellsfargo','bankofamerica','citibank',
    'steam','dropbox','icloud','outlook','office365',
]
PHISHING_WORDS = [
    'verify','login','signin','secure','update','confirm',
    'account','banking','payment','password','credential',
    'alert','suspended','locked','unusual','activity',
    'click','urgent','immediately','action','required',
]

WHITELIST_DOMAINS = {
    'google.com','youtube.com','facebook.com','wikipedia.org','twitter.com',
    'instagram.com','linkedin.com','reddit.com','amazon.com','yahoo.com',
    'microsoft.com','apple.com','netflix.com','github.com','stackoverflow.com',
    'twitch.tv','pinterest.com','tumblr.com','wordpress.com','blogspot.com',
    'bbc.com','bbc.co.uk','cnn.com','nytimes.com','theguardian.com',
    'reuters.com','forbes.com','bloomberg.com','wsj.com','techcrunch.com',
    'wired.com','medium.com','quora.com','discord.com','slack.com',
    'zoom.us','dropbox.com','notion.so','trello.com','asana.com',
    'spotify.com','soundcloud.com','hulu.com','disneyplus.com',
    'paypal.com','stripe.com','ebay.com','etsy.com','shopify.com',
    'adobe.com','salesforce.com','oracle.com','ibm.com','cisco.com',
    'aws.amazon.com','cloud.google.com','azure.microsoft.com',
    'cloudflare.com','godaddy.com','namecheap.com','digitalocean.com',
    'heroku.com','vercel.com','netlify.com','firebase.google.com',
    'npmjs.com','pypi.org','huggingface.co','kaggle.com',
    'arxiv.org','scholar.google.com','python.org','nodejs.org',
    'reactjs.org','vuejs.org','angular.io','tailwindcss.com',
    'docker.com','kubernetes.io','w3schools.com','developer.mozilla.org',
    'fonts.google.com','unsplash.com','imdb.com','steampowered.com',
    'epicgames.com','xbox.com','nintendo.com','playstation.com',
    'wolframalpha.com','mathworks.com','tableau.com',
}

SUSPICIOUS_PATH_WORDS = ['login','signin','verify','account','password','banking','payment']


def levenshtein(s1: str, s2: str) -> int:
    if s1 == s2:
        return 0
    if len(s1) < len(s2):
        s1, s2 = s2, s1
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1, 1):
        curr = [i]
        for j, c2 in enumerate(s2, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (c1 != c2)))
        prev = curr
    return prev[-1]


def homograph_min_distance(sld: str) -> int:
    if not sld:
        return 99
    return min(levenshtein(sld, brand) for brand in BRAND_SLDS)


def ca_tier_from_url(url_lower: str) -> float:
    parsed = urlparse(url_lower if url_lower.startswith('http') else 'https://' + url_lower)
    domain = parsed.netloc.split(':')[0].lstrip('www.')
    parts  = domain.split('.')
    tld    = parts[-1] if len(parts) > 1 else ''
    sld    = parts[-2] if len(parts) > 1 else ''
    if tld in ('gov', 'mil', 'edu'):
        return 1.0
    rep = TLD_REPUTATION.get(tld, 0.3)
    if rep >= 0.75 and sld in BRAND_SLDS:
        return 1.0
    if rep < 0.25:
        return 0.0
    return round(rep * 0.6, 2)


def shannon_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')


def is_whitelisted(url: str) -> bool:
    url_lower = url.lower()
    try:
        parsed = urlparse(url_lower if url_lower.startswith('http') else 'https://' + url_lower)
        domain = parsed.netloc.split(':')[0].lstrip('www.')
        path   = parsed.path.lower()
    except Exception:
        return False
    parts   = domain.split('.')
    base    = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
    in_list = domain in WHITELIST_DOMAINS or base in WHITELIST_DOMAINS
    if not in_list:
        return False
    if any(w in path for w in SUSPICIOUS_PATH_WORDS):
        return False
    return True


def extract_features(
    url: str,
    has_password_field: int = 0,
    external_resource_ratio: float = 0.0,
) -> list:
    url       = str(url).strip()
    url_lower = url.lower()
    try:
        parsed   = urlparse(url_lower if url_lower.startswith('http') else 'http://' + url_lower)
        domain   = parsed.netloc or url_lower
        path     = parsed.path or ''
        query    = parsed.query or ''
        fragment = parsed.fragment or ''
    except Exception:
        domain, path, query, fragment = url_lower, '', '', ''

    domain_clean  = domain.split(':')[0].lstrip('www.')
    parts         = domain_clean.split('.')
    tld           = parts[-1] if len(parts) > 1 else ''
    sld           = parts[-2] if len(parts) > 1 else ''
    subdomains    = parts[:-2] if len(parts) > 2 else []
    subdomain_str = '.'.join(subdomains)
    is_ip         = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0

    hom_dist = homograph_min_distance(sld)
    hom_flag = 1 if 1 <= hom_dist <= 2 else 0
    is_puny  = 1 if domain_clean.startswith('xn--') or any(p.startswith('xn--') for p in parts) else 0
    tld_rep  = TLD_REPUTATION.get(tld, 0.3)
    ca_tier  = ca_tier_from_url(url_lower)

    return [
        len(url),
        len(domain_clean),
        len(path),
        len(query),
        url_lower.count('.'),
        url_lower.count('-'),
        url_lower.count('_'),
        url_lower.count('@'),
        url_lower.count('/'),
        url_lower.count('?'),
        url_lower.count('='),
        url_lower.count('&'),
        url_lower.count('%'),
        url_lower.count('#'),
        sum(c.isdigit() for c in url_lower),
        sum(not c.isalnum() and c not in '/:.-_?=&%#@' for c in url_lower),
        ca_tier,
        1 if ':' in domain else 0,
        is_ip,
        len(subdomains),
        len(subdomain_str),
        shannon_entropy(domain_clean),
        shannon_entropy(sld),
        sum(c.isdigit() for c in domain_clean),
        domain_clean.count('-'),
        len(tld),
        tld_rep,
        count_vowels(sld) / max(len(sld), 1),
        hom_dist,
        hom_flag,
        is_puny,
        int(any(k in subdomain_str for k in BRAND_KEYWORDS)),
        int(any(k in path         for k in BRAND_KEYWORDS)),
        int(any(k in query        for k in BRAND_KEYWORDS)),
        int(any(k in sld          for k in BRAND_KEYWORDS)),
        sum(1 for k in PHISHING_WORDS if k in url_lower),
        1 if '//' in path else 0,
        1 if '%' in url_lower else 0,
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url_lower) else 0,
        len(parts),
        int(bool(fragment)),
        int(len(url) > 75),
        has_password_field,
        float(external_resource_ratio),
    ]

# ─────────────────────────────────────────────
# Model
# ─────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
model_data = None

def load_model():
    global model_data
    if os.path.exists(MODEL_PATH):
        model_data = joblib.load(MODEL_PATH)
        ver = model_data.get('version', '1.0') if isinstance(model_data, dict) else '1.0'
        print(f"[ML] Model v{ver} loaded from {MODEL_PATH}")
    else:
        print("[ML] WARNING: model.pkl not found — run train.py first. Heuristic fallback active.")

# Called at import time (module level), not just inside __main__ — this is
# required for production WSGI servers like gunicorn, which import this
# file as a module rather than executing it as a script. The __main__
# block only runs for `python app.py` (local dev); gunicorn never triggers
# it, so the model would silently never load in production without this.
load_model()

# ─────────────────────────────────────────────
# Heuristic fallback
# ─────────────────────────────────────────────
def heuristic_score(url):
    url = url.lower()
    risk = 0.0
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url):    risk += 0.40
    if url.count('-') > 3:                            risk += 0.10
    if url.count('.') > 4:                            risk += 0.10
    if '@' in url:                                    risk += 0.30
    tld = url.split('.')[-1].split('/')[0]
    if TLD_REPUTATION.get(tld, 0.3) < 0.25:          risk += 0.20
    if any(k in url for k in BRAND_KEYWORDS):
        if not re.match(r'https://(?:www\.)?(\w+)\.com', url):
            risk += 0.25
    risk += min(sum(1 for k in PHISHING_WORDS if k in url) * 0.05, 0.25)
    return min(1.0, risk)

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'model_loaded': model_data is not None,
        'model_version': model_data.get('version', 'unknown') if isinstance(model_data, dict) else 'legacy',
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url required'}), 400

    # DOM signals forwarded by Electron (optional)
    has_password_field      = int(data.get('has_password_field', 0))
    external_resource_ratio = float(data.get('external_resource_ratio', 0.0))

    # Behavioral gate: skip heavy ML scan if no form/password field
    # (only applies when the Electron layer explicitly sets the flag to False/0)
    behavioral_scan = has_password_field or data.get('force_scan', False)

    # ── Whitelist fast-pass ──
    if is_whitelisted(url) and not behavioral_scan:
        return jsonify({
            'score':               1.0,
            'label':               'safe',
            'confidence':          1.0,
            'phishing_probability': 0.0,
            'whitelist':           True,
        })

    try:
        if model_data is not None:
            clf      = model_data['model'] if isinstance(model_data, dict) else model_data
            features = np.array([extract_features(
                url,
                has_password_field=has_password_field,
                external_resource_ratio=external_resource_ratio,
            )])
            proba         = clf.predict_proba(features)[0]
            phishing_prob = float(proba[1])
            result = {
                'score':               round(1.0 - phishing_prob, 4),
                'label':               'phishing' if phishing_prob > 0.5 else 'safe',
                'confidence':          round(float(max(proba)), 4),
                'phishing_probability': round(phishing_prob, 4),
                'whitelist':           False,
            }
        else:
            risk = heuristic_score(url)
            result = {
                'score':               round(1.0 - risk, 4),
                'label':               'phishing' if risk > 0.5 else 'safe',
                'confidence':          round(max(risk, 1 - risk), 4),
                'phishing_probability': round(risk, 4),
                'fallback':            True,
                'whitelist':           False,
            }

        return jsonify(result)

    except Exception as e:
        return jsonify({'score': 0.5, 'label': 'unknown', 'error': str(e)}), 200

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"[Trust-Flow Backend] Starting on port {port}")
    app.run(
        host="0.0.0.0",
        port=port
    )