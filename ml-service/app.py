"""
Trust-Flow ML Service — Flask REST API with Redis Caching
POST /predict  { "url": "..." }  →  { "score": 0.0–1.0, "label": "safe|phishing", "confidence": 0.0–1.0 }
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
from urllib.parse import urlparse

app = Flask(__name__)

# ─────────────────────────────────────────────
# Redis connection
# ─────────────────────────────────────────────
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD', None)
CACHE_TTL = int(os.environ.get('CACHE_TTL_SECONDS', 3600))  # 1 hour default

redis_client = None

def get_redis():
    global redis_client
    if redis_client is None:
        try:
            redis_client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                password=REDIS_PASSWORD,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
            )
            redis_client.ping()
            print(f"[Trust-Flow ML] Redis connected at {REDIS_HOST}:{REDIS_PORT}")
        except Exception as e:
            print(f"[Trust-Flow ML] Redis unavailable ({e}). Running without cache.")
            redis_client = None
    return redis_client

def cache_key(url: str) -> str:
    """Stable SHA-256 cache key for a URL."""
    return "tf:predict:" + hashlib.sha256(url.encode()).hexdigest()

def cache_get(url: str):
    r = get_redis()
    if not r:
        return None
    try:
        raw = r.get(cache_key(url))
        return json.loads(raw) if raw else None
    except Exception:
        return None

def cache_set(url: str, result: dict):
    r = get_redis()
    if not r:
        return
    try:
        r.setex(cache_key(url), CACHE_TTL, json.dumps(result))
    except Exception:
        pass

# ─────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────
BRAND_KEYWORDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'bank', 'secure',
    'signin', 'login', 'verify', 'update', 'account', 'webscr',
]

def shannon_entropy(s):
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):
    url = url.strip().lower()
    try:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc or url
        path = parsed.path or ''
        scheme = parsed.scheme
    except Exception:
        domain = url
        path = ''
        scheme = 'http'

    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0
    domain_clean = domain.split(':')[0]
    parts = domain_clean.split('.')
    subdomain_depth = max(0, len(parts) - 2)

    return [
        len(url),
        url.count('.'),
        url.count('-'),
        url.count('@'),
        url.count('/'),
        sum(c.isdigit() for c in url),
        sum(1 for c in url if c in '?=&%#~'),
        1 if scheme == 'https' else 0,
        is_ip,
        subdomain_depth,
        len(domain_clean),
        len(path),
        shannon_entropy(domain_clean),
        1 if ':' in domain else 0,
        int(any(k in '.'.join(parts[:-2]) for k in BRAND_KEYWORDS)),
        int(any(k in path for k in BRAND_KEYWORDS)),
        1 if '//' in path else 0,
        1 if '%' in url else 0,
        len(parts[-1]) if parts else 0,
        subdomain_depth,
    ]

# ─────────────────────────────────────────────
# Load model
# ─────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model.pkl')
model_data = None

def load_model():
    global model_data
    if os.path.exists(MODEL_PATH):
        model_data = joblib.load(MODEL_PATH)
        print(f"[Trust-Flow ML] Model loaded from {MODEL_PATH}")
    else:
        print("[Trust-Flow ML] WARNING: model.pkl not found. Using heuristic fallback.")

# ─────────────────────────────────────────────
# Heuristic fallback (no model)
# ─────────────────────────────────────────────
def heuristic_score(url):
    url = url.lower()
    risk = 0
    if not url.startswith('https'):       risk += 0.20
    if re.search(r'\d{1,3}(\.\d{1,3}){3}', url): risk += 0.40
    if url.count('-') > 3:               risk += 0.10
    if url.count('.') > 4:               risk += 0.10
    if '@' in url:                        risk += 0.30
    if any(k in url for k in BRAND_KEYWORDS) and not any(
        url.startswith(f'https://www.{k}.com') for k in BRAND_KEYWORDS
    ):
        risk += 0.25
    return min(1.0, risk)

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    r = get_redis()
    redis_ok = False
    if r:
        try:
            r.ping()
            redis_ok = True
        except Exception:
            pass
    return jsonify({
        'status': 'ok',
        'model_loaded': model_data is not None,
        'redis_connected': redis_ok,
        'cache_ttl_seconds': CACHE_TTL,
    })

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json(force=True)
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'url required'}), 400

    # ── Cache hit ──
    cached = cache_get(url)
    if cached:
        cached['cached'] = True
        return jsonify(cached)

    # ── Inference ──
    try:
        if model_data is not None:
            clf = model_data['model']
            features = np.array([extract_features(url)])
            proba = clf.predict_proba(features)[0]
            phishing_prob = float(proba[1])
            safe_score = 1.0 - phishing_prob
            result = {
                'score': round(safe_score, 4),
                'label': 'phishing' if phishing_prob > 0.5 else 'safe',
                'confidence': round(float(max(proba)), 4),
                'phishing_probability': round(phishing_prob, 4),
                'cached': False,
            }
        else:
            risk = heuristic_score(url)
            safe_score = 1.0 - risk
            result = {
                'score': round(safe_score, 4),
                'label': 'phishing' if risk > 0.5 else 'safe',
                'confidence': round(max(risk, 1 - risk), 4),
                'phishing_probability': round(risk, 4),
                'fallback': True,
                'cached': False,
            }

        # ── Cache store ──
        cache_set(url, result)
        return jsonify(result)

    except Exception as e:
        return jsonify({'score': 0.5, 'label': 'unknown', 'error': str(e), 'cached': False}), 200

@app.route('/cache/flush', methods=['POST'])
def flush_cache():
    """Flush all Trust-Flow prediction cache keys from Redis."""
    r = get_redis()
    if not r:
        return jsonify({'error': 'Redis not connected'}), 503
    try:
        keys = r.keys('tf:predict:*')
        if keys:
            r.delete(*keys)
        return jsonify({'flushed': len(keys)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cache/stats', methods=['GET'])
def cache_stats():
    """Return Redis memory and key-count stats."""
    r = get_redis()
    if not r:
        return jsonify({'error': 'Redis not connected'}), 503
    try:
        info = r.info('memory')
        keys = r.keys('tf:predict:*')
        return jsonify({
            'prediction_keys': len(keys),
            'used_memory_human': info.get('used_memory_human'),
            'maxmemory_human': info.get('maxmemory_human', 'unlimited'),
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    load_model()
    get_redis()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
