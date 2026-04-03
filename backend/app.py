"""
Trust-Flow Backend — Flask REST API with Redis Caching
Full backend: ML prediction, WHOIS intelligence, health, cache management.
"""

import re
import math
import os
import json
import hashlib
import joblib
import numpy as np
import redis
from flask import Flask, request, jsonify
from flask_cors import CORS
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)

# ─────────────────────────────────────────────
# Redis
# ─────────────────────────────────────────────
REDIS_HOST     = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT     = int(os.environ.get('REDIS_PORT', 6379))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
CACHE_TTL      = int(os.environ.get('CACHE_TTL_SECONDS', 3600))

_redis = None

def get_redis():
    global _redis
    if _redis is None:
        try:
            client = redis.Redis(
                host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD,
                decode_responses=True, socket_connect_timeout=2, socket_timeout=2,
            )
            client.ping()
            _redis = client
            print(f"[Redis] Connected at {REDIS_HOST}:{REDIS_PORT}")
        except Exception as e:
            print(f"[Redis] Unavailable ({e}) — running without cache")
    return _redis

def cache_key(url):
    return "tf:pred:" + hashlib.sha256(url.encode()).hexdigest()

def cache_get(url):
    r = get_redis()
    if not r:
        return None
    try:
        raw = r.get(cache_key(url))
        return json.loads(raw) if raw else None
    except Exception:
        return None

def cache_set(url, result):
    r = get_redis()
    if not r:
        return
    try:
        r.setex(cache_key(url), CACHE_TTL, json.dumps(result))
    except Exception:
        pass

# ─────────────────────────────────────────────
# Feature extraction (40 features — matches train.py)
# ─────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','ru','pw','cc','top',
    'click','link','work','date','bid','trade','stream','loan',
    'download','racing','icu','cam','men','review','accountant',
}
LEGITIMATE_TLDS = {'com','org','net','edu','gov','co','io','uk','de','fr'}
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

def shannon_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)

def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')

def extract_features(url):
    url = str(url).strip()
    url_lower = url.lower()
    try:
        parsed = urlparse(url_lower if url_lower.startswith('http') else 'http://' + url_lower)
        domain = parsed.netloc or url_lower
        path   = parsed.path or ''
        query  = parsed.query or ''
        scheme = parsed.scheme or 'http'
        fragment = parsed.fragment or ''
    except Exception:
        domain, path, query, scheme, fragment = url_lower, '', '', 'http', ''

    domain_clean = domain.split(':')[0].lstrip('www.')
    parts     = domain_clean.split('.')
    tld       = parts[-1] if len(parts) > 1 else ''
    sld       = parts[-2] if len(parts) > 1 else ''
    subdomains = parts[:-2] if len(parts) > 2 else []
    subdomain_str = '.'.join(subdomains)
    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0

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
        1 if scheme == 'https' else 0,
        1 if ':' in domain else 0,
        is_ip,
        len(subdomains),
        len(subdomain_str),
        shannon_entropy(domain_clean),
        shannon_entropy(sld),
        sum(c.isdigit() for c in domain_clean),
        domain_clean.count('-'),
        len(tld),
        1 if tld in SUSPICIOUS_TLDS else 0,
        1 if tld in LEGITIMATE_TLDS else 0,
        count_vowels(sld) / max(len(sld), 1),
        int(any(k in subdomain_str for k in BRAND_KEYWORDS)),
        int(any(k in path for k in BRAND_KEYWORDS)),
        int(any(k in query for k in BRAND_KEYWORDS)),
        int(any(k in sld for k in BRAND_KEYWORDS)),
        sum(1 for k in PHISHING_WORDS if k in url_lower),
        1 if '//' in path else 0,
        1 if '%' in url_lower else 0,
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url_lower) else 0,
        len(parts),
        int(bool(fragment)),
        int(len(url) > 75),
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

# ─────────────────────────────────────────────
# Heuristic fallback
# ─────────────────────────────────────────────
def heuristic_score(url):
    url = url.lower()
    risk = 0.0
    if not url.startswith('https'):                     risk += 0.20
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url):      risk += 0.40
    if url.count('-') > 3:                              risk += 0.10
    if url.count('.') > 4:                              risk += 0.10
    if '@' in url:                                      risk += 0.30
    if any(t in url for t in SUSPICIOUS_TLDS):         risk += 0.15
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
    r = get_redis()
    redis_ok = False
    if r:
        try: r.ping(); redis_ok = True
        except Exception: pass
    return jsonify({
        'status': 'ok',
        'model_loaded': model_data is not None,
        'model_version': model_data.get('version', 'unknown') if isinstance(model_data, dict) else 'legacy',
        'redis_connected': redis_ok,
        'cache_ttl_seconds': CACHE_TTL,
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url  = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url required'}), 400

    cached = cache_get(url)
    if cached:
        cached['cached'] = True
        return jsonify(cached)

    try:
        if model_data is not None:
            clf      = model_data['model'] if isinstance(model_data, dict) else model_data
            features = np.array([extract_features(url)])
            proba    = clf.predict_proba(features)[0]
            phishing_prob = float(proba[1])
            result = {
                'score':               round(1.0 - phishing_prob, 4),
                'label':               'phishing' if phishing_prob > 0.5 else 'safe',
                'confidence':          round(float(max(proba)), 4),
                'phishing_probability': round(phishing_prob, 4),
                'cached':              False,
            }
        else:
            risk = heuristic_score(url)
            result = {
                'score':               round(1.0 - risk, 4),
                'label':               'phishing' if risk > 0.5 else 'safe',
                'confidence':          round(max(risk, 1 - risk), 4),
                'phishing_probability': round(risk, 4),
                'fallback':            True,
                'cached':              False,
            }

        cache_set(url, result)
        return jsonify(result)

    except Exception as e:
        return jsonify({'score': 0.5, 'label': 'unknown', 'error': str(e), 'cached': False}), 200

@app.route('/cache/flush', methods=['POST'])
def flush_cache():
    r = get_redis()
    if not r:
        return jsonify({'error': 'Redis not connected'}), 503
    try:
        keys = r.keys('tf:pred:*')
        if keys:
            r.delete(*keys)
        return jsonify({'flushed': len(keys)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cache/stats', methods=['GET'])
def cache_stats():
    r = get_redis()
    if not r:
        return jsonify({'error': 'Redis not connected'}), 503
    try:
        info = r.info('memory')
        keys = r.keys('tf:pred:*')
        return jsonify({
            'prediction_keys':   len(keys),
            'used_memory_human': info.get('used_memory_human'),
            'maxmemory_human':   info.get('maxmemory_human', 'unlimited'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    load_model()
    get_redis()
    port = int(os.environ.get('PORT', 5000))
    print(f"[Trust-Flow Backend] Starting on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
