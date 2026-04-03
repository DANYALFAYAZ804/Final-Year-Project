"""
Trust-Flow ML URL Classifier — Training Script
Trains a Random Forest on synthetic + heuristic features derived from URL structure.
Run once: python train.py
Outputs: model.pkl
"""

import re
import math
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# ─────────────────────────────────────────────
# Feature extraction (mirrors app.py)
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
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        domain = parsed.netloc or url
        path = parsed.path or ''
        scheme = parsed.scheme
    except Exception:
        domain = url
        path = ''
        scheme = 'http'

    # IP address used as domain
    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0

    # Strip port for analysis
    domain_clean = domain.split(':')[0]
    parts = domain_clean.split('.')
    subdomain_depth = max(0, len(parts) - 2)

    features = {
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_at': url.count('@'),
        'num_slashes': url.count('/'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special': sum(1 for c in url if c in '?=&%#~'),
        'is_https': 1 if scheme == 'https' else 0,
        'is_ip': is_ip,
        'subdomain_depth': subdomain_depth,
        'domain_length': len(domain_clean),
        'path_length': len(path),
        'domain_entropy': shannon_entropy(domain_clean),
        'has_port': 1 if ':' in domain else 0,
        'brand_in_subdomain': int(any(k in '.'.join(parts[:-2]) for k in BRAND_KEYWORDS)),
        'brand_in_path': int(any(k in path for k in BRAND_KEYWORDS)),
        'has_double_slash': 1 if '//' in path else 0,
        'has_hex_encoding': 1 if '%' in url else 0,
        'tld_length': len(parts[-1]) if parts else 0,
        'num_subdomains': subdomain_depth,
    }
    return list(features.values())

FEATURE_NAMES = [
    'url_length', 'num_dots', 'num_hyphens', 'num_at', 'num_slashes',
    'num_digits', 'num_special', 'is_https', 'is_ip', 'subdomain_depth',
    'domain_length', 'path_length', 'domain_entropy', 'has_port',
    'brand_in_subdomain', 'brand_in_path', 'has_double_slash',
    'has_hex_encoding', 'tld_length', 'num_subdomains',
]

# ─────────────────────────────────────────────
# Synthetic dataset generation
# ─────────────────────────────────────────────
safe_urls = [
    'https://www.google.com',
    'https://www.github.com/user/repo',
    'https://www.wikipedia.org/wiki/Machine_learning',
    'https://stackoverflow.com/questions/12345',
    'https://www.amazon.com/dp/B08N5KWB9H',
    'https://www.microsoft.com/en-us/windows',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.bbc.com/news/technology',
    'https://www.nytimes.com/section/technology',
    'https://www.reddit.com/r/programming',
    'https://www.linkedin.com/in/username',
    'https://www.apple.com/iphone',
    'https://www.twitter.com/home',
    'https://www.instagram.com/explore',
    'https://www.netflix.com/browse',
    'https://news.ycombinator.com',
    'https://www.cloudflare.com',
    'https://www.python.org/downloads',
    'https://docs.python.org/3/',
    'https://www.w3schools.com/html/',
    'https://developer.mozilla.org/en-US/',
    'https://www.coursera.org/learn/machine-learning',
    'https://www.udemy.com/course/python',
    'https://www.facebook.com/pages',
    'https://www.dropbox.com/home',
    'https://drive.google.com/drive/my-drive',
    'https://mail.google.com/mail/u/0/#inbox',
    'https://www.paypal.com/myaccount/summary',
    'https://www.ebay.com/sch/i.html?_nkw=laptop',
    'https://www.walmart.com/browse/electronics',
    'https://www.bestbuy.com/site/computers',
    'https://www.target.com/c/electronics/-/N-5xtg6',
    'https://www.spotify.com/us/account/overview',
    'https://www.twitch.tv/directory',
    'https://discord.com/channels/@me',
    'https://www.slack.com/intl/en-us/',
    'https://zoom.us/join',
    'https://www.adobe.com/products/photoshop.html',
    'https://www.oracle.com/java/',
    'https://www.ibm.com/cloud',
] * 3  # 120 safe

phishing_urls = [
    'http://paypal-secure-login.suspicious-domain.xyz/webscr?cmd=login',
    'http://192.168.1.1/signin/account/verify',
    'http://google-login.tk/accounts/signin',
    'http://microsoft-update.ru/windows/activate',
    'http://apple-id-verify.ml/account/locked',
    'http://facebook-login-secure.gq/login.php',
    'http://amazon-order-confirm.cf/signin',
    'http://netflix-billing-update.tk/account',
    'http://instagram-verify-account.ml/login',
    'http://twitter-secure-login.ga/auth',
    'http://bankofamerica-online-secure.xyz/login',
    'http://wellsfargo-verify.tk/signin',
    'http://chase-secure-login.ml/auth',
    'http://paypa1.com/login@evil.ru',
    'http://login-microsoft.suspicious.tk',
    'http://secure-apple-icloud.verify-now.tk/signin',
    'http://verify-paypal-account.tk/webscr',
    'http://update-bank-account.secure-login.ml',
    'http://facebook.login-secure.xyz/user/auth',
    'http://accounts.google.com.phish.ru/signin',
    'http://82.45.210.33/login',
    'http://1.2.3.4/paypal/secure/login.php',
    'http://login-update-verify.secure-account.tk',
    'http://ebay-secure-verification.ml/signin',
    'http://support.apple.com.verify-id.tk',
    'http://amazon.co.uk.verify-order.xyz',
    'http://login.microsoftonline-secure.tk',
    'http://steam-trade-offer.xyz/login',
    'http://linkedin-security-alert.ml/verify',
    'http://dropbox-share-file.phish.tk/login',
    'http://your-account-suspended-verify.tk',
    'http://confirm-payment-update.ml/amazon',
    'http://tax-refund-claim.verify-gov.tk',
    'http://covid-relief-fund.phish.xyz/login',
    'http://fedex-package-delivery.secure-track.tk',
    'http://ups-shipping-update.phish.ml',
    'http://dhl-parcel-update.secure.gq/login',
    'http://irs-refund-2024.verify-now.tk',
    'http://account-breach-alert.secure-login.xyz',
    'http://microsoft.com.update-windows.tk/activate',
] * 3  # 120 phishing

all_urls = safe_urls + phishing_urls
labels = [0] * len(safe_urls) + [1] * len(phishing_urls)

X = np.array([extract_features(u) for u in all_urls])
y = np.array(labels)

# ─────────────────────────────────────────────
# Train
# ─────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, class_weight='balanced')
clf.fit(X_train, y_train)

y_pred = clf.predict(X_test)
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")

joblib.dump({'model': clf, 'features': FEATURE_NAMES}, 'model.pkl')
print("Model saved to model.pkl")
