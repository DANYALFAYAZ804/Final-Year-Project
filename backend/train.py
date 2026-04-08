"""
Trust-Flow ML Service — Training Script v4.0
Context-Aware Intelligence: 99%+ Precision target, minimal False Positives.

Upgrades over v3.0:
  - Levenshtein homograph detection against top-50 brand SLDs
  - IDN/Punycode binary flag
  - External resource ratio feature (DOM-signal, training proxy)
  - TLD reputation scoring (weighted float, replaces binary flags)
  - HTTPS bias eliminated; Certificate Authority tier feature added
  - SMOTE oversampling for borderline phishing minority synthesis
  - Tranco/Alexa Top-5k fast-pass whitelist (skips ML, zero FP)
  - Behavioral trigger: password-field / form presence flag
  - XGBoost classifier with Optuna hyperparameter search
  - CalibratedClassifierCV method='isotonic' for better probability mapping
"""

import re
import math
import os
import random
import joblib
import numpy as np
from urllib.parse import urlparse

random.seed(42)
np.random.seed(42)

# ─────────────────────────────────────────────
# TLD Reputation Scores  (float 0.0–1.0)
# Higher = more trusted
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

# Legacy sets kept for backward-compatible feature slots
SUSPICIOUS_TLDS = {t for t, s in TLD_REPUTATION.items() if s < 0.25}
LEGITIMATE_TLDS = {t for t, s in TLD_REPUTATION.items() if s >= 0.70}

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
# Top-50 brand SLDs for homograph detection
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# Tranco / Alexa Top-5k fast-pass whitelist
# (representative sample; in production load full list from file)
# ─────────────────────────────────────────────
WHITELIST_DOMAINS = {
    'google.com','youtube.com','facebook.com','wikipedia.org','twitter.com',
    'instagram.com','linkedin.com','reddit.com','amazon.com','yahoo.com',
    'microsoft.com','apple.com','netflix.com','github.com','stackoverflow.com',
    'twitch.tv','pinterest.com','tumblr.com','wordpress.com','blogspot.com',
    'bbc.com','bbc.co.uk','cnn.com','nytimes.com','theguardian.com',
    'reuters.com','forbes.com','bloomberg.com','wsj.com','techcrunch.com',
    'wired.com','medium.com','quora.com','discord.com','slack.com',
    'zoom.us','dropbox.com','notion.so','trello.com','asana.com',
    'spotify.com','soundcloud.com','twitch.tv','hulu.com','disneyplus.com',
    'paypal.com','stripe.com','ebay.com','etsy.com','shopify.com',
    'adobe.com','salesforce.com','oracle.com','ibm.com','cisco.com',
    'aws.amazon.com','cloud.google.com','azure.microsoft.com',
    'cloudflare.com','godaddy.com','namecheap.com','digitalocean.com',
    'heroku.com','vercel.com','netlify.com','firebase.google.com',
    'npmjs.com','pypi.org','rubygems.org','packagist.org','nuget.org',
    'huggingface.co','kaggle.com','colab.research.google.com',
    'arxiv.org','scholar.google.com','pubmed.ncbi.nlm.nih.gov',
    'python.org','nodejs.org','reactjs.org','vuejs.org','angular.io',
    'tailwindcss.com','mui.com','vitejs.dev','webpack.js.org',
    'nginx.org','apache.org','docker.com','kubernetes.io','helm.sh',
    'w3schools.com','developer.mozilla.org','css-tricks.com',
    'fonts.google.com','unsplash.com','pexels.com','flickr.com',
    'imdb.com','rottentomatoes.com','goodreads.com','audible.com',
    'steampowered.com','epicgames.com','xbox.com','nintendo.com',
    'playstation.com','twitch.tv','mixer.com','itch.io',
    'wolframalpha.com','mathworks.com','tableau.com','powerbi.microsoft.com',
}


# ─────────────────────────────────────────────
# Levenshtein distance (pure Python, no dep)
# ─────────────────────────────────────────────
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
    """Return minimum Levenshtein distance from sld to any brand SLD."""
    if not sld:
        return 99
    min_dist = min(levenshtein(sld, brand) for brand in BRAND_SLDS)
    return min_dist


# ─────────────────────────────────────────────
# Certificate Authority tier
# Let's Encrypt / free CAs → lower trust
# ─────────────────────────────────────────────
FREE_CA_INDICATORS = ['letsencrypt', 'zerossl', 'buypass', 'sectigo-free']
TRUSTED_CA_INDICATORS = ['digicert', 'comodo', 'globalsign', 'verisign', 'entrust', 'geotrust']


def ca_tier_from_url(url_lower: str) -> float:
    """
    Proxy heuristic: infer CA trust tier from observable URL signals.
    At inference time this can be replaced with real cert data from the
    Electron layer; at training time we derive it from domain structure.
    Returns 0.0 (free/unknown) or 1.0 (enterprise CA indicator).
    """
    parsed = urlparse(url_lower if url_lower.startswith('http') else 'https://' + url_lower)
    domain = parsed.netloc.split(':')[0].lstrip('www.')
    parts  = domain.split('.')
    tld    = parts[-1] if len(parts) > 1 else ''
    sld    = parts[-2] if len(parts) > 1 else ''
    # Enterprise domains on high-rep TLDs strongly correlate with trusted CAs
    if tld in ('gov', 'mil', 'edu'):
        return 1.0
    rep = TLD_REPUTATION.get(tld, 0.3)
    if rep >= 0.75 and sld in BRAND_SLDS:
        return 1.0
    if rep < 0.25:
        return 0.0
    return round(rep * 0.6, 2)


# ─────────────────────────────────────────────
# Shannon entropy helper
# ─────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def count_vowels(s: str) -> int:
    return sum(1 for c in s.lower() if c in 'aeiou')


# ─────────────────────────────────────────────
# Whitelist fast-pass check
# Returns True if the URL is in the top-5k whitelist
# with no suspicious path indicators.
# ─────────────────────────────────────────────
SUSPICIOUS_PATH_WORDS = ['login', 'signin', 'verify', 'account', 'password', 'banking', 'payment']

def is_whitelisted(url: str) -> bool:
    """Fast-pass: returns True for top-5k domains with clean paths."""
    url_lower = url.lower()
    try:
        parsed = urlparse(url_lower if url_lower.startswith('http') else 'https://' + url_lower)
        domain = parsed.netloc.split(':')[0].lstrip('www.')
        path   = parsed.path.lower()
    except Exception:
        return False

    # Must match the whitelist exactly (subdomain-aware: check base domain too)
    parts    = domain.split('.')
    base     = '.'.join(parts[-2:]) if len(parts) >= 2 else domain
    in_list  = domain in WHITELIST_DOMAINS or base in WHITELIST_DOMAINS

    if not in_list:
        return False

    # Deep suspicious paths cancel the fast-pass
    if any(w in path for w in SUSPICIOUS_PATH_WORDS):
        return False

    return True


# ─────────────────────────────────────────────
# Feature names — 50 features (v4.0)
# ─────────────────────────────────────────────
FEATURE_NAMES = [
    # URL-level (0–15)
    'url_length', 'domain_len', 'path_len', 'query_len',
    'dot_count', 'hyphen_count', 'underscore_count', 'at_count',
    'slash_count', 'question_count', 'equals_count', 'ampersand_count',
    'percent_count', 'hash_count', 'digit_count', 'special_char_count',
    # Protocol / network (16–17)  — https REMOVED, CA tier added
    'ca_tier', 'has_port',
    # Domain analysis (18–28)
    'is_ip', 'subdomain_count', 'subdomain_len',
    'domain_entropy', 'sld_entropy', 'domain_digit_count', 'domain_hyphen_count',
    'tld_len', 'tld_reputation_score', 'sld_vowel_ratio',
    # Homograph / IDN (29–31)  ← NEW
    'homograph_min_dist', 'homograph_risk_flag', 'is_punycode',
    # Brand / keyword abuse (32–36)
    'brand_in_subdomain', 'brand_in_path', 'brand_in_query', 'brand_in_sld',
    'phishing_word_count',
    # Structural anomalies (37–41)
    'has_double_slash', 'has_hex_encoding', 'has_ip_in_url',
    'total_domain_parts', 'has_fragment',
    # Behavioral signals (42–44)  ← NEW
    'long_url_flag', 'has_password_field', 'external_resource_ratio',
]
FEATURE_COUNT = len(FEATURE_NAMES)  # 45


def extract_features(
    url: str,
    has_password_field: int = 0,
    external_resource_ratio: float = 0.0,
) -> list:
    """
    Extract 45 numeric features from a URL string.

    Extra DOM-level signals (provided by Electron at runtime):
      has_password_field      — 1 if page contains <input type="password"> or <form>
      external_resource_ratio — fraction of images/scripts loaded from external domains
    During training these default to 0 / 0.0; the model learns URL-structure signals
    and the live Electron layer enriches inference with DOM signals.
    """
    url = str(url).strip()
    url_lower = url.lower()

    try:
        parsed   = urlparse(url_lower if url_lower.startswith('http') else 'http://' + url_lower)
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

    # Homograph detection
    hom_dist  = homograph_min_distance(sld)
    hom_flag  = 1 if 1 <= hom_dist <= 2 else 0
    # IDN / Punycode
    is_puny   = 1 if domain_clean.startswith('xn--') or any(p.startswith('xn--') for p in parts) else 0
    # TLD reputation
    tld_rep   = TLD_REPUTATION.get(tld, 0.3)
    # CA tier proxy
    ca_tier   = ca_tier_from_url(url_lower)

    return [
        # URL-level (0–15)
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
        # Protocol / network (16–17)
        ca_tier,
        1 if ':' in domain else 0,
        # Domain analysis (18–27)
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
        # Homograph / IDN (28–30)
        hom_dist,
        hom_flag,
        is_puny,
        # Brand / keyword abuse (31–35)
        int(any(k in subdomain_str for k in BRAND_KEYWORDS)),
        int(any(k in path         for k in BRAND_KEYWORDS)),
        int(any(k in query        for k in BRAND_KEYWORDS)),
        int(any(k in sld          for k in BRAND_KEYWORDS)),
        sum(1 for k in PHISHING_WORDS if k in url_lower),
        # Structural anomalies (36–40)
        1 if '//' in path else 0,
        1 if '%' in url_lower else 0,
        1 if re.search(r'(\d{1,3}\.){3}\d{1,3}', url_lower) else 0,
        len(parts),
        int(bool(fragment)),
        # Behavioral signals (41–43)
        int(len(url) > 75),
        has_password_field,
        float(external_resource_ratio),
    ]


# ─────────────────────────────────────────────
# URL Augmentation
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
PHISH_TLDS = [t for t, s in TLD_REPUTATION.items() if s < 0.25]
LEGIT_TLDS  = ['com', 'org', 'net', 'io', 'co']

# Homograph substitution table for synthetic data
HOMOGRAPH_SUBS = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', 'l'],
    'o': ['0'],
    'l': ['1'],
    'g': ['9'],
    's': ['5'],
}


def _make_homograph(brand: str) -> str:
    """Create a 1-edit homograph of a brand name."""
    for i, ch in enumerate(brand):
        if ch in HOMOGRAPH_SUBS:
            sub = random.choice(HOMOGRAPH_SUBS[ch])
            return brand[:i] + sub + brand[i+1:]
    # fallback: insert hyphen
    mid = len(brand) // 2
    return brand[:mid] + '-' + brand[mid:]


def augment_safe(url: str, n: int = 2) -> list:
    results = [url]
    parsed  = urlparse(url if url.startswith('http') else 'https://' + url)
    domain  = parsed.netloc or url
    for _ in range(n):
        path    = random.choice(SAFE_PATHS)
        variant = f"https://{domain}{path}"
        results.append(variant)
    return results


def augment_phishing(url: str, n: int = 2) -> list:
    results    = [url]
    parsed     = urlparse(url if url.startswith('http') else 'http://' + url)
    base_domain = parsed.netloc.split(':')[0] if parsed.netloc else url
    parts       = base_domain.split('.')
    sld         = parts[-2] if len(parts) >= 2 else base_domain
    tld         = random.choice(PHISH_TLDS)

    for _ in range(n):
        sub     = random.choice(PHISH_SUBDOMAINS)
        path    = random.choice(PHISH_PATHS)
        keyword = random.choice(['secure', 'verify', 'update', 'login', 'account'])
        variant = f"http://{sub}.{sld}-{keyword}.{tld}{path}"
        results.append(variant)
    return results


def generate_homograph_phishing() -> list:
    """Synthesize realistic homograph phishing URLs for training."""
    samples = []
    for brand in random.sample(BRAND_SLDS, min(30, len(BRAND_SLDS))):
        hg    = _make_homograph(brand)
        tld   = random.choice(PHISH_TLDS)
        path  = random.choice(PHISH_PATHS)
        samples.append(f"http://{hg}.{tld}{path}")
        samples.append(f"http://www.{hg}.com{path}")
        sub = random.choice(PHISH_SUBDOMAINS)
        samples.append(f"http://{sub}.{hg}-secure.{tld}{path}")
    return samples


def generate_punycode_phishing() -> list:
    """Simulate Punycode / IDN homograph phishing URLs."""
    brands = random.sample(BRAND_SLDS, min(15, len(BRAND_SLDS)))
    tlds   = random.sample(PHISH_TLDS, min(5, len(PHISH_TLDS)))
    samples = []
    for brand in brands:
        tld  = random.choice(tlds)
        path = random.choice(PHISH_PATHS)
        samples.append(f"http://xn--{brand[:-1]}a-pua.{tld}{path}")
        samples.append(f"http://xn--{brand}-u82d.com{path}")
    return samples


# ─────────────────────────────────────────────
# Base dataset
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
# Unseen generalization test set
# ─────────────────────────────────────────────
UNSEEN_TEST = [
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
    # Homograph unseen
    ('http://xn--googl-fsa.tk/login',              1),
    ('http://g00gle-security.ml/verify',           1),
    ('http://paypa1-secure.cf/webscr',             1),
    ('http://micros0ft-update.tk/activate',        1),
]


def build_dataset():
    """
    Build training dataset:
    1. Base URLs + augmentation
    2. Synthetic homograph + Punycode phishing
    3. Deduplicate
    4. Return feature matrix + labels
    """
    safe_urls, phish_urls = [], []

    for url in BASE_SAFE:
        safe_urls.extend(augment_safe(url, n=3))

    for url in BASE_PHISHING:
        phish_urls.extend(augment_phishing(url, n=3))

    # Synthetic homograph and Punycode phishing
    phish_urls.extend(generate_homograph_phishing())
    phish_urls.extend(generate_punycode_phishing())

    safe_urls  = list(dict.fromkeys(safe_urls))
    phish_urls = list(dict.fromkeys(phish_urls))

    print(f"Dataset: {len(safe_urls)} safe | {len(phish_urls)} phishing")

    all_urls = safe_urls + phish_urls
    labels   = [0] * len(safe_urls) + [1] * len(phish_urls)

    X = np.array([extract_features(u) for u in all_urls])
    y = np.array(labels)
    return X, y


# ─────────────────────────────────────────────
# Training entry point
# ─────────────────────────────────────────────
if __name__ == '__main__':
    import optuna
    import xgboost as xgb
    from imblearn.over_sampling import SMOTE
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, classification_report, roc_auc_score,
    )

    optuna.logging.set_verbosity(optuna.logging.WARNING)

    print("=" * 60)
    print("Trust-Flow ML Model v4.0 — Context-Aware Intelligence")
    print("=" * 60)

    X, y = build_dataset()

    X_train_raw, X_test, y_train_raw, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y,
    )
    print(f"Pre-SMOTE  — Train: {len(X_train_raw)} | Test: {len(X_test)}")

    # ── SMOTE: synthesise borderline phishing minority ──
    sm = SMOTE(random_state=42, k_neighbors=min(5, sum(y_train_raw == 1) - 1))
    X_train, y_train = sm.fit_resample(X_train_raw, y_train_raw)
    print(f"Post-SMOTE — Train: {len(X_train)} "
          f"(safe={sum(y_train==0)}, phish={sum(y_train==1)})")
    print()

    # ── Optuna: find best XGBoost hyperparameters ──
    def objective(trial):
        params = {
            'n_estimators':      trial.suggest_int('n_estimators', 200, 600),
            'max_depth':         trial.suggest_int('max_depth', 3, 8),
            'learning_rate':     trial.suggest_float('learning_rate', 0.03, 0.2, log=True),
            'subsample':         trial.suggest_float('subsample', 0.6, 1.0),
            'colsample_bytree':  trial.suggest_float('colsample_bytree', 0.6, 1.0),
            'min_child_weight':  trial.suggest_int('min_child_weight', 1, 10),
            'gamma':             trial.suggest_float('gamma', 0.0, 1.0),
            'scale_pos_weight':  1,
            'use_label_encoder': False,
            'eval_metric':       'logloss',
            'random_state':      42,
            'n_jobs':            -1,
        }
        clf = xgb.XGBClassifier(**params)
        cv  = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
        scores = cross_val_score(clf, X_train, y_train, cv=cv,
                                 scoring='precision', n_jobs=-1)
        return scores.mean()

    print("Running Optuna hyperparameter search (50 trials) …")
    study = optuna.create_study(direction='maximize',
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=50, show_progress_bar=False)
    best = study.best_params
    print(f"Best params: {best}")
    print(f"Best CV Precision: {study.best_value:.4f}")
    print()

    # ── Train final XGBoost with best params ──
    xgb_clf = xgb.XGBClassifier(
        **best,
        scale_pos_weight=1,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )

    # Isotonic calibration (better than sigmoid for ≥5k samples)
    total_samples = len(X_train)
    cal_method = 'isotonic' if total_samples >= 5000 else 'sigmoid'
    print(f"Calibration method: {cal_method} ({total_samples} training samples)")
    calibrated = CalibratedClassifierCV(xgb_clf, cv=5, method=cal_method)
    calibrated.fit(X_train, y_train)

    # ── Hold-out test performance ──
    y_pred  = calibrated.predict(X_test)
    y_proba = calibrated.predict_proba(X_test)[:, 1]

    print("── Hold-out Test Set ──────────────────────────────────────")
    print(f"Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_pred):.4f}")
    print(f"Recall:    {recall_score(y_test, y_pred):.4f}")
    print(f"F1 Score:  {f1_score(y_test, y_pred):.4f}")
    print(f"ROC-AUC:   {roc_auc_score(y_test, y_proba):.4f}")
    print()
    print(classification_report(y_test, y_pred, target_names=['Safe', 'Phishing']))

    # ── 5-fold CV on full post-SMOTE dataset ──
    cv_obj = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_pre = cross_val_score(xgb_clf, X_train, y_train, cv=cv_obj,
                              scoring='precision', n_jobs=-1)
    cv_auc = cross_val_score(xgb_clf, X_train, y_train, cv=cv_obj,
                              scoring='roc_auc',   n_jobs=-1)
    print(f"5-Fold CV Precision: {cv_pre.mean():.4f} ± {cv_pre.std():.4f}")
    print(f"5-Fold CV ROC-AUC:   {cv_auc.mean():.4f} ± {cv_auc.std():.4f}")
    print()

    # ── Unseen URL generalization test ──
    print("── Unseen URL Generalization Test ─────────────────────────")
    unseen_X      = np.array([extract_features(u) for u, _ in UNSEEN_TEST])
    unseen_labels = np.array([l for _, l in UNSEEN_TEST])
    unseen_pred   = calibrated.predict(unseen_X)
    unseen_proba  = calibrated.predict_proba(unseen_X)[:, 1]

    correct = 0
    for (url, true_label), pred, prob in zip(UNSEEN_TEST, unseen_pred, unseen_proba):
        ok      = pred == true_label
        correct += ok
        status  = 'OK' if ok else 'FAIL'
        kind    = 'safe    ' if true_label == 0 else 'phishing'
        whitelist_note = ' [WHITELIST]' if is_whitelisted(url) else ''
        print(f"  {status} [{kind}] phish={prob:.3f}  {url[:65]}{whitelist_note}")

    print(f"\n  Unseen accuracy: {correct}/{len(UNSEEN_TEST)} = "
          f"{correct/len(UNSEEN_TEST)*100:.0f}%")
    print()

    # ── Feature importance (top 15 from XGBoost) ──
    xgb_raw = xgb.XGBClassifier(
        **best,
        scale_pos_weight=1,
        use_label_encoder=False,
        eval_metric='logloss',
        random_state=42,
        n_jobs=-1,
    )
    xgb_raw.fit(X_train, y_train)
    importances = xgb_raw.feature_importances_
    indices     = np.argsort(importances)[::-1][:15]
    print("── Top-15 Feature Importances ─────────────────────────────")
    for rank, i in enumerate(indices, 1):
        name = FEATURE_NAMES[i] if i < len(FEATURE_NAMES) else f'feature_{i}'
        print(f"  {rank:2}. {name:<35} {importances[i]:.4f}")
    print()

    # ── Save ──
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'model.pkl')
    joblib.dump({
        'model':          calibrated,
        'feature_names':  FEATURE_NAMES,
        'feature_count':  FEATURE_COUNT,
        'version':        '4.0',
        'cal_method':     cal_method,
        'best_xgb_params': best,
    }, output)
    print(f"Model v4.0 saved → {output}")
