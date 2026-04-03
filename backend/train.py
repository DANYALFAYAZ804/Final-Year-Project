"""
Trust-Flow ML Service — Training Script (Improved)
Uses a larger, more realistic synthetic dataset with 40 features.
Run: python train.py
Output: model.pkl
"""

import re
import math
import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report
from urllib.parse import urlparse

# ─────────────────────────────────────────────
# Feature extraction (40 features)
# ─────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'ru', 'pw', 'cc', 'top',
    'click', 'link', 'work', 'date', 'bid', 'trade', 'stream', 'loan',
    'download', 'racing', 'icu', 'cam', 'men', 'review', 'accountant',
}

LEGITIMATE_TLDS = {'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'uk', 'de', 'fr'}

BRAND_KEYWORDS = [
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook',
    'netflix', 'instagram', 'twitter', 'linkedin', 'bank', 'secure',
    'signin', 'login', 'verify', 'update', 'account', 'webscr',
    'ebay', 'chase', 'wellsfargo', 'bankofamerica', 'citibank',
    'steam', 'dropbox', 'icloud', 'outlook', 'office365',
]

PHISHING_WORDS = [
    'verify', 'login', 'signin', 'secure', 'update', 'confirm',
    'account', 'banking', 'payment', 'password', 'credential',
    'alert', 'suspended', 'locked', 'unusual', 'activity',
    'click', 'urgent', 'immediately', 'action', 'required',
]


def shannon_entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')


def extract_features(url):
    """Extract 40 features from a URL."""
    url = str(url).strip()
    url_lower = url.lower()

    try:
        parsed = urlparse(url_lower if url_lower.startswith('http') else 'http://' + url_lower)
        domain = parsed.netloc or url_lower
        path = parsed.path or ''
        query = parsed.query or ''
        scheme = parsed.scheme or 'http'
        fragment = parsed.fragment or ''
    except Exception:
        domain, path, query, scheme, fragment = url_lower, '', '', 'http', ''

    domain_clean = domain.split(':')[0].lstrip('www.')
    parts = domain_clean.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    sld = parts[-2] if len(parts) > 1 else ''
    subdomains = parts[:-2] if len(parts) > 2 else []
    subdomain_str = '.'.join(subdomains)

    is_ip = 1 if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain.split(':')[0]) else 0

    features = [
        # URL-level
        len(url),                                                           # 0
        len(domain_clean),                                                  # 1
        len(path),                                                          # 2
        len(query),                                                         # 3
        url_lower.count('.'),                                               # 4
        url_lower.count('-'),                                               # 5
        url_lower.count('_'),                                               # 6
        url_lower.count('@'),                                               # 7
        url_lower.count('/'),                                               # 8
        url_lower.count('?'),                                               # 9
        url_lower.count('='),                                               # 10
        url_lower.count('&'),                                               # 11
        url_lower.count('%'),                                               # 12
        url_lower.count('#'),                                               # 13
        sum(c.isdigit() for c in url_lower),                               # 14
        sum(not c.isalnum() and c not in '/:.-_?=&%#@' for c in url_lower), # 15

        # Protocol/Security
        1 if scheme == 'https' else 0,                                     # 16
        1 if ':' in domain else 0,                                         # 17 has port

        # Domain
        is_ip,                                                              # 18
        len(subdomains),                                                    # 19 subdomain count
        len(subdomain_str),                                                 # 20
        shannon_entropy(domain_clean),                                      # 21
        shannon_entropy(sld),                                               # 22
        sum(c.isdigit() for c in domain_clean),                            # 23 digits in domain
        domain_clean.count('-'),                                            # 24 hyphens in domain
        len(tld),                                                           # 25
        1 if tld in SUSPICIOUS_TLDS else 0,                                # 26
        1 if tld in LEGITIMATE_TLDS else 0,                                # 27
        count_vowels(sld) / max(len(sld), 1),                              # 28 vowel ratio (legitimacy signal)

        # Brand/keyword abuse
        int(any(k in subdomain_str for k in BRAND_KEYWORDS)),              # 29
        int(any(k in path for k in BRAND_KEYWORDS)),                       # 30
        int(any(k in query for k in BRAND_KEYWORDS)),                      # 31
        int(any(k in sld for k in BRAND_KEYWORDS)),                        # 32 brand in SLD
        sum(1 for k in PHISHING_WORDS if k in url_lower),                  # 33 phishing word count

        # Structural anomalies
        1 if '//' in path else 0,                                          # 34
        1 if '%' in url_lower else 0,                                      # 35
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url_lower) else 0,      # 36 IP in URL
        len(parts),                                                         # 37 total domain parts
        int(bool(fragment)),                                                # 38
        int(len(url) > 75),                                                # 39 long URL flag
    ]
    return features


FEATURE_COUNT = 40

# ─────────────────────────────────────────────
# Dataset
# ─────────────────────────────────────────────
SAFE_URLS = [
    'https://www.google.com',
    'https://www.google.com/search?q=python+tutorial',
    'https://www.github.com/user/repo',
    'https://github.com/microsoft/vscode',
    'https://www.wikipedia.org/wiki/Machine_learning',
    'https://stackoverflow.com/questions/12345',
    'https://www.amazon.com/dp/B08N5KWB9H',
    'https://www.amazon.co.uk/books',
    'https://www.microsoft.com/en-us/windows',
    'https://docs.microsoft.com/en-us/azure',
    'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
    'https://www.bbc.com/news/technology',
    'https://www.nytimes.com/section/technology',
    'https://www.reddit.com/r/programming',
    'https://www.linkedin.com/in/username',
    'https://www.apple.com/iphone',
    'https://support.apple.com/en-us',
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
    'https://www.facebook.com/pages',
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
    'https://www.adobe.com/products/photoshop.html',
    'https://www.oracle.com/java/',
    'https://www.ibm.com/cloud',
    'https://aws.amazon.com/ec2',
    'https://azure.microsoft.com/en-us',
    'https://cloud.google.com/storage',
    'https://www.digitalocean.com/products/droplets',
    'https://heroku.com/home',
    'https://www.netlify.com',
    'https://vercel.com/dashboard',
    'https://www.stripe.com/docs',
    'https://www.twilio.com/docs',
    'https://api.slack.com/methods',
    'https://www.mongodb.com/cloud/atlas',
    'https://firebase.google.com/docs',
    'https://www.djangoproject.com',
    'https://flask.palletsprojects.com',
    'https://reactjs.org/docs/getting-started.html',
    'https://vuejs.org/guide/introduction.html',
    'https://angular.io/docs',
    'https://nodejs.org/en/docs',
    'https://expressjs.com',
    'https://www.typescriptlang.org/docs',
    'https://webpack.js.org/concepts',
    'https://vitejs.dev/guide',
    'https://tailwindcss.com/docs',
    'https://mui.com/getting-started',
    'https://www.npmjs.com/package/react',
    'https://pypi.org/project/flask',
    'https://www.kaggle.com/competitions',
    'https://colab.research.google.com',
    'https://jupyter.org/try',
    'https://huggingface.co/models',
    'https://openai.com/blog',
    'https://arxiv.org/abs/2303.08774',
    'https://www.nature.com/articles/s41586-021-03819-2',
    'https://www.sciencedirect.com/science/article/pii',
    'https://scholar.google.com/scholar?q=deep+learning',
    'https://www.wolframalpha.com/input?i=integral',
    'https://www.mathworks.com/products/matlab.html',
    'https://www.tableau.com/products/desktop',
    'https://powerbi.microsoft.com/en-us',
    'https://www.salesforce.com/products/crm',
    'https://www.shopify.com/blog',
    'https://www.squarespace.com/templates',
    'https://wordpress.org/plugins',
    'https://www.wix.com/website/templates',
    'https://fonts.google.com',
    'https://unsplash.com/photos',
    'https://www.flickr.com/photos',
    'https://www.imdb.com/title/tt1375666',
    'https://www.rottentomatoes.com/m/inception',
    'https://www.goodreads.com/book/show',
    'https://www.goodreads.com/list/show/1.Best_Books_Ever',
    'https://store.steampowered.com/app/730/CSGO',
    'https://www.epicgames.com/store/en-US',
    'https://www.xbox.com/en-US/games',
    'https://www.playstation.com/en-us/games',
    'https://www.nintendo.com/games',
]

PHISHING_URLS = [
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
    'http://covid-relief-fund.phish.xyz/login',
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
    'http://job-offer-remote.ml/apply-now',
    'http://work-from-home-earn.cf/register',
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
    'http://xn--pypal-4ve.com/login',
    'http://аррӏе.com/id/verify',
    'http://paypal-en.com.tk/login',
    'http://paypal.com.accountverify.tk',
    'http://secure-paypal.com.verify.ml/login',
    'http://signin.ebay.com.account-verify.tk',
    'http://customerservice.amazon.com.help.ml',
    'http://account.microsoft.com.verify-now.tk',
]

if __name__ == '__main__':
    # Augment by repeating with slight variations
    safe_aug = SAFE_URLS * 4       # ~400 safe
    phish_aug = PHISHING_URLS * 4  # ~400 phishing

    all_urls = safe_aug + phish_aug
    labels = [0] * len(safe_aug) + [1] * len(phish_aug)

    X = np.array([extract_features(u) for u in all_urls])
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Ensemble: Random Forest + Gradient Boosting
    rf = RandomForestClassifier(
        n_estimators=300,
        max_depth=15,
        min_samples_split=3,
        min_samples_leaf=1,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1,
    )
    gb = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        random_state=42,
    )
    ensemble = VotingClassifier(
        estimators=[('rf', rf), ('gb', gb)],
        voting='soft',
        weights=[2, 1],
    )

    ensemble.fit(X_train, y_train)

    y_pred = ensemble.predict(X_test)
    y_proba = ensemble.predict_proba(X_test)[:, 1]

    print("=" * 50)
    print("Trust-Flow ML Model — Training Results")
    print("=" * 50)
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # Cross-validation
    cv_scores = cross_val_score(ensemble, X, y, cv=5, scoring='f1')
    print(f"5-Fold CV F1: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
    print()

    # Save
    output = os.path.join(os.path.dirname(__file__), 'model.pkl')
    joblib.dump({
        'model': ensemble,
        'feature_count': FEATURE_COUNT,
        'version': '2.0',
    }, output)
    print(f"Model v2.0 saved → {output}")

    # Quick sanity checks
    test_cases = [
        ('https://www.google.com', 'safe'),
        ('http://paypal-secure-login.xyz/webscr', 'phishing'),
        ('https://github.com/torvalds/linux', 'safe'),
        ('http://192.168.1.1/login', 'phishing'),
        ('https://www.netflix.com/browse', 'safe'),
        ('http://netflix-billing.tk/update', 'phishing'),
    ]
    print("Sanity checks:")
    for url, expected in test_cases:
        feat = np.array([extract_features(url)])
        proba = ensemble.predict_proba(feat)[0]
        predicted = 'phishing' if proba[1] > 0.5 else 'safe'
        status = '✓' if predicted == expected else '✗'
        print(f"  {status} {url[:60]:<60} → {predicted} (phish={proba[1]:.3f})")
