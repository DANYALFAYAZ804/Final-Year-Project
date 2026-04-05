"""
Trust-Flow ML Service — Training Script v3.0
Genuine generalization: no data leakage, feature-based learning, unseen URL validation.

Key fixes over v2.0:
  - Deduplicate before split (no same URL in train+test)
  - URL augmentation creates genuine feature variations (not copies)
  - Held-out unseen URL test set to validate real-world generalization
  - Calibrated probability output via CalibratedClassifierCV
  - Feature importance report so you can verify the model learns structure, not URLs
"""

import re
import math
import os
import random
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, roc_auc_score,
)
from urllib.parse import urlparse

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    'tk','ml','ga','cf','gq','xyz','ru','pw','cc','top',
    'click','link','work','date','bid','trade','stream','loan',
    'download','racing','icu','cam','men','review','accountant',
    'monster','buzz','party','win','zone','club','online','site',
}
LEGITIMATE_TLDS = {
    'com','org','net','edu','gov','co','io','uk','de','fr',
    'jp','ca','au','us','eu','int','mil','mobi','info',
}
BRAND_KEYWORDS = [
    'paypal','google','microsoft','apple','amazon','facebook',
    'netflix','instagram','twitter','linkedin','bank','secure',
    'signin','login','verify','update','account','webscr',
    'ebay','chase','wellsfargo','bankofamerica','citibank',
    'steam','dropbox','icloud','outlook','office365','whatsapp',
    'tiktok','snapchat','spotify','coinbase','binance','crypto',
]
PHISHING_WORDS = [
    'verify','login','signin','secure','update','confirm',
    'account','banking','payment','password','credential',
    'alert','suspended','locked','unusual','activity',
    'click','urgent','immediately','action','required',
    'reactivate','validate','authenticate','authorize','suspend',
]

# ─────────────────────────────────────────────
# Feature extraction — 40 features
# These are the ONLY thing the model sees.
# URLs themselves are never used as inputs.
# ─────────────────────────────────────────────
FEATURE_NAMES = [
    'url_length','domain_len','path_len','query_len',
    'dot_count','hyphen_count','underscore_count','at_count',
    'slash_count','question_count','equals_count','ampersand_count',
    'percent_count','hash_count','digit_count','special_char_count',
    'is_https','has_port',
    'is_ip','subdomain_count','subdomain_len',
    'domain_entropy','sld_entropy','domain_digit_count','domain_hyphen_count',
    'tld_len','is_suspicious_tld','is_legit_tld','sld_vowel_ratio',
    'brand_in_subdomain','brand_in_path','brand_in_query','brand_in_sld',
    'phishing_word_count',
    'has_double_slash','has_hex_encoding','has_ip_in_url',
    'total_domain_parts','has_fragment','long_url_flag',
]
FEATURE_COUNT = len(FEATURE_NAMES)  # 40


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def count_vowels(s: str) -> int:
    return sum(1 for c in s.lower() if c in 'aeiou')


def extract_features(url: str) -> list:
    """
    Extract 40 numeric features from a URL string.
    The model is trained on these features — NOT on the URL text itself.
    This function runs at both train time and inference time (real-time scanning).
    """
    url = str(url).strip()
    url_lower = url.lower()

    try:
        parsed = urlparse(url_lower if url_lower.startswith('http') else 'http://' + url_lower)
        domain   = parsed.netloc or url_lower
        path     = parsed.path or ''
        query    = parsed.query or ''
        scheme   = parsed.scheme or 'http'
        fragment = parsed.fragment or ''
    except Exception:
        domain, path, query, scheme, fragment = url_lower, '', '', 'http', ''

    domain_clean  = domain.split(':')[0].lstrip('www.')
    parts         = domain_clean.split('.')
    tld           = parts[-1] if len(parts) > 1 else ''
    sld           = parts[-2] if len(parts) > 1 else ''
    subdomains    = parts[:-2] if len(parts) > 2 else []
    subdomain_str = '.'.join(subdomains)
    is_ip         = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0

    return [
        # ── URL-level (0–15) ──
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
        # ── Protocol (16–17) ──
        1 if scheme == 'https' else 0,
        1 if ':' in domain else 0,
        # ── Domain analysis (18–28) ──
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
        # ── Brand/keyword abuse (29–33) ──
        int(any(k in subdomain_str for k in BRAND_KEYWORDS)),
        int(any(k in path         for k in BRAND_KEYWORDS)),
        int(any(k in query        for k in BRAND_KEYWORDS)),
        int(any(k in sld          for k in BRAND_KEYWORDS)),
        sum(1 for k in PHISHING_WORDS if k in url_lower),
        # ── Structural anomalies (34–39) ──
        1 if '//' in path else 0,
        1 if '%' in url_lower else 0,
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url_lower) else 0,
        len(parts),
        int(bool(fragment)),
        int(len(url) > 75),
    ]


# ─────────────────────────────────────────────
# URL Augmentation
# Generates structurally distinct variants so the
# model learns feature patterns, not URL strings.
# ─────────────────────────────────────────────
SAFE_PATHS = [
    '', '/home', '/about', '/contact', '/blog', '/news',
    '/products', '/services', '/docs', '/api/v1/users',
    '/search?q=hello', '/en-us/getting-started',
]
PHISH_PATHS = [
    '/login', '/signin', '/verify', '/update', '/account/locked',
    '/webscr?cmd=_login-run', '/secure/verify', '/confirm-identity',
    '/banking/login.php', '/update-payment', '/reactivate',
]
PHISH_SUBDOMAINS = ['secure', 'login', 'verify', 'account', 'update', 'banking']
PHISH_TLDS = list(SUSPICIOUS_TLDS)
LEGIT_TLDS = ['com', 'org', 'net', 'io', 'co']


def augment_safe(url: str, n: int = 2) -> list:
    """Generate n feature-distinct safe variants of a URL."""
    results = [url]
    parsed = urlparse(url if url.startswith('http') else 'https://' + url)
    domain = parsed.netloc or url
    for _ in range(n):
        path = random.choice(SAFE_PATHS)
        variant = f"https://{domain}{path}"
        results.append(variant)
    return results


def augment_phishing(url: str, n: int = 2) -> list:
    """Generate n feature-distinct phishing variants."""
    results = [url]
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    # strip domain for remixing
    base_domain = parsed.netloc.split(':')[0] if parsed.netloc else url
    parts = base_domain.split('.')
    sld = parts[-2] if len(parts) >= 2 else base_domain
    tld = random.choice(PHISH_TLDS)

    for _ in range(n):
        sub = random.choice(PHISH_SUBDOMAINS)
        path = random.choice(PHISH_PATHS)
        # new phishing pattern: sub.sld-keyword.tld/path
        keyword = random.choice(['secure', 'verify', 'update', 'login', 'account'])
        variant = f"http://{sub}.{sld}-{keyword}.{tld}{path}"
        results.append(variant)
    return results


# ─────────────────────────────────────────────
# Base dataset (unique URLs only — no duplication)
# ─────────────────────────────────────────────
BASE_SAFE = [
    'https://www.google.com',
    'https://www.google.com/search?q=python+tutorial',
    'https://github.com/user/repo',
    'https://github.com/microsoft/vscode',
    'https://www.wikipedia.org/wiki/Machine_learning',
    'https://stackoverflow.com/questions/12345',
    'https://www.amazon.com/dp/B08N5KWB9H',
    'https://www.amazon.co.uk/books',
    'https://www.microsoft.com/en-us/windows',
    'https://docs.microsoft.com/en-us/azure',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.bbc.co.uk/news/technology',
    'https://www.nytimes.com/section/technology',
    'https://www.reddit.com/r/programming',
    'https://www.linkedin.com/in/username',
    'https://www.apple.com/iphone',
    'https://support.apple.com/en-us',
    'https://www.twitter.com/home',
    'https://www.instagram.com/explore',
    'https://www.netflix.com/browse',
    'https://news.ycombinator.com',
    'https://www.cloudflare.com/products',
    'https://www.python.org/downloads',
    'https://docs.python.org/3/library',
    'https://developer.mozilla.org/en-US/docs/Web',
    'https://www.coursera.org/learn/machine-learning',
    'https://www.facebook.com/pages/category',
    'https://www.dropbox.com/home',
    'https://drive.google.com/drive/my-drive',
    'https://mail.google.com/mail/u/0/#inbox',
    'https://www.paypal.com/myaccount/summary',
    'https://www.ebay.com/sch/i.html?_nkw=laptop',
    'https://www.walmart.com/browse/electronics',
    'https://www.spotify.com/us/account/overview',
    'https://www.twitch.tv/directory',
    'https://discord.com/channels/@me',
    'https://zoom.us/join',
    'https://aws.amazon.com/ec2',
    'https://azure.microsoft.com/en-us',
    'https://cloud.google.com/storage',
    'https://www.stripe.com/docs',
    'https://www.mongodb.com/cloud/atlas',
    'https://firebase.google.com/docs',
    'https://www.djangoproject.com',
    'https://flask.palletsprojects.com',
    'https://reactjs.org/docs/getting-started.html',
    'https://nodejs.org/en/docs',
    'https://vitejs.dev/guide',
    'https://tailwindcss.com/docs',
    'https://www.npmjs.com/package/react',
    'https://pypi.org/project/flask',
    'https://www.kaggle.com/competitions',
    'https://colab.research.google.com',
    'https://huggingface.co/models',
    'https://openai.com/blog',
    'https://arxiv.org/abs/2303.08774',
    'https://scholar.google.com/scholar?q=deep+learning',
    'https://www.mathworks.com/products/matlab.html',
    'https://powerbi.microsoft.com/en-us',
    'https://www.shopify.com/blog',
    'https://wordpress.org/plugins',
    'https://fonts.google.com',
    'https://www.imdb.com/title/tt1375666',
    'https://store.steampowered.com/app/730',
    'https://www.epicgames.com/store/en-US',
    'https://www.xbox.com/en-US/games',
    'https://www.nintendo.com/games',
    'https://www.twilio.com/docs',
    'https://api.slack.com/methods',
    'https://vercel.com/dashboard',
    'https://www.netlify.com',
    'https://www.oracle.com/java/',
    'https://www.adobe.com/products/photoshop.html',
    'https://www.ibm.com/cloud',
    'https://www.salesforce.com/products/crm',
    'https://www.squarespace.com/templates',
    'https://www.goodreads.com/book/show',
    'https://www.wolframalpha.com/input?i=integral',
    'https://vuejs.org/guide/introduction.html',
    'https://angular.io/docs',
    'https://expressjs.com',
    'https://www.typescriptlang.org/docs',
    'https://webpack.js.org/concepts',
    'https://mui.com/getting-started',
    'https://www.digitalocean.com/products/droplets',
    'https://heroku.com/home',
    'https://unsplash.com/photos',
    'https://www.flickr.com/photos',
    'https://www.rottentomatoes.com/m/inception',
    'https://www.playstation.com/en-us/games',
    'https://www.nature.com/articles/s41586-021-03819-2',
    'https://www.sciencedirect.com/science/article/pii',
    'https://www.tableau.com/products/desktop',
    'https://www.wix.com/website/templates',
    'https://jupyter.org/try',
    'https://www.w3schools.com/html/',
    'https://www.goodreads.com/list/show/1',
]

BASE_PHISHING = [
    'http://paypal-secure-login.suspicious-domain.xyz/webscr?cmd=login',
    'http://paypa1.com.evil-track.tk/signin',
    'http://secure-paypal-verify.ml/webscr',
    'http://paypal.account-verify.gq/login.php',
    'http://update-paypal-account.cf/secure',
    'http://192.168.1.1/signin/account/verify',
    'http://10.0.0.1/banking/login',
    'http://185.220.101.45/phishing/google',
    'http://google-login.tk/accounts/signin',
    'http://accounts.google.com.signin-verify.ru/auth',
    'http://google-security-alert.ml/verify',
    'http://myaccount.google.com.phish.xyz/login',
    'http://microsoft-update.ru/windows/activate',
    'http://microsoft-security.tk/account/verify',
    'http://login.microsoftonline-secure.ml/auth',
    'http://microsoft.com.activate-windows.cf/key',
    'http://apple-id-verify.ml/account/locked',
    'http://apple-support-id.tk/verify',
    'http://icloud-storage-full.gq/unlock',
    'http://appleid.apple.com.verify-now.ru/login',
    'http://facebook-login-secure.gq/login.php',
    'http://facebook-security.ml/checkpoint',
    'http://fb-account-verify.tk/login',
    'http://facebook.com.login-verify.xyz/auth',
    'http://amazon-order-confirm.cf/signin',
    'http://amazon-security-alert.tk/verify',
    'http://amazon-account-suspended.ml/reactivate',
    'http://signin.amazon.com.verify-identity.ru',
    'http://netflix-billing-update.tk/account',
    'http://netflix-payment-failed.ml/update',
    'http://instagram-verify-account.ml/login',
    'http://instagram-security.tk/confirm',
    'http://twitter-secure-login.ga/auth',
    'http://twitter-account-locked.ml/verify',
    'http://bankofamerica-online-secure.xyz/login',
    'http://secure.bankofamerica.com.phish.tk/signin',
    'http://wellsfargo-verify.tk/signin',
    'http://wellsfargo-security-alert.ml/login',
    'http://chase-secure-login.ml/auth',
    'http://chase-bank-verify.cf/login',
    'http://citibank-alert.tk/secure/login',
    'http://paypa1.com/login@evil.ru',
    'http://login-microsoft.suspicious.tk',
    'http://secure-apple-icloud.verify-now.tk/signin',
    'http://ebay-secure-verification.ml/signin',
    'http://support.apple.com.verify-id.tk',
    'http://amazon.co.uk.verify-order.xyz',
    'http://steam-trade-offer.xyz/login',
    'http://linkedin-security-alert.ml/verify',
    'http://dropbox-share-file.phish.tk/login',
    'http://your-account-suspended-verify.tk',
    'http://confirm-payment-update.ml/amazon',
    'http://tax-refund-claim.verify-gov.tk',
    'http://fedex-package-delivery.secure-track.tk',
    'http://ups-shipping-update.phish.ml',
    'http://dhl-parcel-update.secure.gq/login',
    'http://irs-refund-2024.verify-now.tk',
    'http://account-breach-alert.secure-login.xyz',
    'http://microsoft.com.update-windows.tk/activate',
    'http://free-bitcoin-claim.tk/wallet',
    'http://crypto-airdrop.ml/claim',
    'http://nft-whitelist-verify.gq/mint',
    'http://prize-winner-2024.cf/claim',
    'http://lottery-payout.tk/verify',
    'http://instagram.login-verify.xyz/user',
    'http://twitterr.com.phish.tk/auth',
    'http://linkedln.com.verify.ml/login',
    'http://netfliix.com.tk/subscribe',
    'http://amaz0n.com.verify-tk.ml/order',
    'http://g00gle.com.verify.cf/search',
    'http://faceb00k.tk/login',
    'http://paypa1.net.tk/payment',
    'http://0nlinebanking.secure.ml/login',
    'http://bank-of-america-secure.xyz/online',
    'http://wellsfarg0.tk/customer/login',
    'http://update-your-billing.secure-pay.ml',
    'http://verify-card-details.payment-secure.tk',
    'http://your-subscription-expired.ml/renew',
    'http://account-terminated-action-required.cf',
    'http://unusual-signin-activity.secure.tk/verify',
    'http://we-noticed-new-login.alert-secure.ml',
    'http://confirm-your-identity.bank-secure.tk',
    'http://sign-in-attempt-blocked.verify-now.ml',
    'http://secure-login.verify-account-now.tk/go',
    'http://myaccount.verify.update.secure.ml/login',
    'http://phishing.example.tk/steal/creds',
    'http://login.verify.account.secure.update.ml',
    'http://paypal-en.com.tk/login',
    'http://paypal.com.accountverify.tk',
    'http://secure-paypal.com.verify.ml/login',
    'http://signin.ebay.com.account-verify.tk',
    'http://customerservice.amazon.com.help.ml',
    'http://account.microsoft.com.verify-now.tk',
    'http://job-offer-remote.ml/apply-now',
    'http://work-from-home-earn.cf/register',
    'http://covid-relief-fund.phish.xyz/login',
]

# ─────────────────────────────────────────────
# Genuinely UNSEEN test URLs (never in training)
# Used ONLY to validate real-world generalization.
# ─────────────────────────────────────────────
UNSEEN_TEST = [
    # Safe — structurally similar to training safe URLs
    ('https://www.bbc.com/sport/football',       0),
    ('https://docs.github.com/en/actions',        0),
    ('https://www.coursera.org/specializations',  0),
    ('https://www.medium.com/tag/python',         0),
    ('https://news.google.com/topstories',        0),
    ('https://www.cnn.com/business',              0),
    ('https://www.forbes.com/technology',         0),
    ('https://www.healthline.com/nutrition',      0),
    ('https://www.nba.com/standings',             0),
    ('https://www.airbnb.com/rooms/12345',        0),

    # Phishing — new domains, same malicious patterns
    ('http://secure-google-verify.tk/auth',        1),
    ('http://amazon-customer-service.ml/verify',   1),
    ('http://apple-id-support.gq/locked',          1),
    ('http://paypal-account-update.cf/login',      1),
    ('http://77.91.124.55/login',                  1),
    ('http://netflix.com.billing-update.xyz',      1),
    ('http://microsoft-support.tk/activate',       1),
    ('http://facebook-security-check.ml/verify',   1),
    ('http://instagram-confirm.gq/login.php',      1),
    ('http://update-bank-credentials.secure.tk',   1),
]


def build_dataset():
    """
    Build the full training dataset:
    1. Start with unique base URLs
    2. Augment each with structurally distinct variants
    3. Deduplicate by URL string
    4. Return features + labels (no URL strings to the model)
    """
    safe_urls, phish_urls = [], []

    for url in BASE_SAFE:
        safe_urls.extend(augment_safe(url, n=3))

    for url in BASE_PHISHING:
        phish_urls.extend(augment_phishing(url, n=3))

    # Deduplicate
    safe_urls  = list(dict.fromkeys(safe_urls))
    phish_urls = list(dict.fromkeys(phish_urls))

    print(f"Dataset: {len(safe_urls)} safe | {len(phish_urls)} phishing")

    all_urls = safe_urls + phish_urls
    labels   = [0] * len(safe_urls) + [1] * len(phish_urls)

    # Extract FEATURES only — model never sees the URL string
    X = np.array([extract_features(u) for u in all_urls])
    y = np.array(labels)
    return X, y


if __name__ == '__main__':
    print("=" * 58)
    print("Trust-Flow ML Model v3.0 — Feature-Based Training")
    print("=" * 58)

    X, y = build_dataset()

    # ── Stratified 80/20 split on deduplicated unique samples ──
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y,
    )
    print(f"Train: {len(X_train)} | Test: {len(X_test)}")
    print()

    # ── Ensemble: RF (n=300) + GB (n=200), soft voting ──
    rf = RandomForestClassifier(
        n_estimators=300, max_depth=12,
        min_samples_split=4, min_samples_leaf=2,
        class_weight='balanced', random_state=42, n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200, max_depth=5, learning_rate=0.08,
        subsample=0.8, min_samples_split=4, random_state=42,
    )
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft', weights=[2, 1],
    )

    # Calibrate probabilities (Platt scaling via 5-fold CV)
    calibrated = CalibratedClassifierCV(ensemble, cv=5, method='sigmoid')
    calibrated.fit(X_train, y_train)

    # ── Held-out test performance ──
    y_pred  = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)[:, 1]

    print("── Hold-out Test Set ──────────────────────────────────")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # ── Stratified 5-fold CV on full dataset ──
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_f1  = cross_val_score(ensemble, X, y, cv=cv, scoring='f1',       n_jobs=-1)
    cv_auc = cross_val_score(ensemble, X, y, cv=cv, scoring='roc_auc',  n_jobs=-1)
    print(f"5-Fold CV F1:      {cv_f1.mean():.4f}  ± {cv_f1.std():.4f}")
    print(f"5-Fold CV ROC-AUC: {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")
    print()

    # ── Genuinely UNSEEN URL generalization test ──
    print("── Unseen URL Generalization Test ─────────────────────")
    unseen_X      = np.array([extract_features(u) for u, _ in UNSEEN_TEST])
    unseen_labels = np.array([l for _, l in UNSEEN_TEST])
    unseen_pred   = calibrated.predict(unseen_X)
    unseen_proba  = calibrated.predict_proba(unseen_X)[:, 1]

    correct = 0
    for (url, true_label), pred, prob in zip(UNSEEN_TEST, unseen_pred, unseen_proba):
        ok = pred == true_label
        correct += ok
        status = '✓' if ok else '✗'
        kind   = 'safe    ' if true_label == 0 else 'phishing'
        print(f"  {status} [{kind}] phish={prob:.3f}  {url[:65]}")

    print(f"\n  Unseen accuracy: {correct}/{len(UNSEEN_TEST)} = {correct/len(UNSEEN_TEST)*100:.0f}%")
    print()

    # ── Feature importance (top 15) ──
    # Refit raw RF to get importances
    rf_raw = RandomForestClassifier(
        n_estimators=300, max_depth=12, class_weight='balanced',
        random_state=42, n_jobs=-1,
    )
    rf_raw.fit(X_train, y_train)
    importances = rf_raw.feature_importances_
    indices     = np.argsort(importances)[::-1][:15]
    print("── Top-15 Feature Importances ─────────────────────────")
    for rank, i in enumerate(indices, 1):
        print(f"  {rank:2}. {FEATURE_NAMES[i]:<30} {importances[i]:.4f}")
    print()

    # ── Save ──
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.pkl')
    joblib.dump({
        'model':         calibrated,
        'feature_names': FEATURE_NAMES,
        'feature_count': FEATURE_COUNT,
        'version':       '3.0',
    }, output)
    print(f"Model v3.0 saved → {output}")
