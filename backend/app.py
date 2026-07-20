"""
Trust-Flow Backend — Flask REST API
ML prediction with whitelist fast-pass and heuristic fallback.
"""

import re
import math
import os
import joblib
import numpy as np
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return jsonify({
        "status": "online",
        "message": "Trust Flow Backend is Running"
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