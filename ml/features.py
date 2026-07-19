"""
features.py — Python mirror of extension/ml/features.js
════════════════════════════════════════════════════════════════════════════════
Extracts the exact same 42-feature vector used in the browser extension.
This ensures Python-trained weights transfer directly into the JS model.

Feature Index Map (must match FEATURE_NAMES in features.js):
 [00] urlLength              [01] domainLength
 [02] subdomainDepth         [03] hasHttps
 [04] hasIpAddress           [05] hasPortInUrl
 [06] numDots                [07] numHyphens
 [08] numUnderscores         [09] numSlashes
 [10] numAtSymbols           [11] numQuestionMarks
 [12] numEquals              [13] numAmpersands
 [14] numPercents            [15] numDigitsInDomain
 [16] pathLength             [17] queryLength
 [18] hasDoubleSlash         [19] hasDashInDomain
 [20] domainEntropy          [21] pathEntropy
 [22] tldSuspicious          [23] domainAge (placeholder)
 [24] hasSuspiciousKeyword   [25] hasLoginKeyword
 [26] hasBrandKeyword        [27] hasSecureKeyword
 [28] urlEntropyTotal        [29] consonantRatio
 [30] digitRatio             [31] specialCharRatio
 [32] longestWordLength      [33] avgWordLength
 [34] numSubdomains          [35] freeHosting
 [36] urlShortenService      [37] hexEncoding
 [38] dataUriScheme          [39] levenshteinMin
 [40] domainRepeatedChars    [41] pathDepth
"""

import re
import math
from urllib.parse import urlparse, parse_qs
from typing import List, Optional

# ─── Brand list (top targets) ────────────────────────────────────────────────
PHISHING_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
    'instagram', 'twitter', 'netflix', 'ebay', 'chase', 'bankofamerica',
    'wellsfargo', 'citibank', 'linkedin', 'dropbox', 'icloud', 'yahoo',
    'outlook', 'office365', 'steam', 'discord', 'coinbase', 'binance',
    'whatsapp', 'telegram', 'dhl', 'fedex', 'ups', 'usps', 'irs',
    'visa', 'mastercard', 'americanexpress', 'hsbc', 'barclays',
]

SUSPICIOUS_KEYWORDS = [
    'secure', 'account', 'update', 'login', 'verify', 'banking',
    'confirm', 'password', 'credential', 'authentication', 'suspended',
    'verification', 'alert', 'notice', 'limited', 'access', 'support',
    'helpdesk', 'recover', 'restore', 'reset', 'unlock', 'expire',
]

LOGIN_KEYWORDS = [
    'login', 'signin', 'sign-in', 'logon', 'log-in', 'auth',
    'authenticate', 'portal', 'session', 'sso',
]

SECURE_KEYWORDS = [
    'secure', 'ssl', 'https', 'safe', 'protected', 'trust', 'verified',
    'encrypted', 'official', 'legit',
]

SUSPICIOUS_TLDS = set([
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'online',
    'site', 'website', 'space', 'fun', 'rocks', 'buzz', 'click',
    'link', 'live', 'support', 'download', 'zip', 'review', 'cricket',
    'win', 'bid', 'loan', 'science', 'work', 'party', 'trade',
    'date', 'faith', 'racing', 'ren', 'mom', 'country',
])

FREE_HOSTING = set([
    'weebly.com', 'wix.com', 'blogger.com', 'wordpress.com', 'blogspot.com',
    'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'surge.sh',
    'firebaseapp.com', 'web.app', '000webhostapp.com', 'infinityfreeapp.com',
    'freeweb.hu', 'biz.nf', 'yolasite.com', 'jimdo.com',
])

URL_SHORTENERS = set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'clck.ru',
    'short.io', 'bl.ink', 'su.pr', 'twurl.nl',
])

# Top 30 legitimate domains used for Levenshtein distance
LEGIT_DOMAINS = [
    'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'netflix.com', 'microsoft.com', 'apple.com',
    'paypal.com', 'ebay.com', 'dropbox.com', 'github.com', 'reddit.com',
    'wikipedia.org', 'yahoo.com', 'bing.com', 'live.com', 'outlook.com',
    'icloud.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'discord.com', 'steam.com', 'coinbase.com', 'binance.com', 'whatsapp.com',
]


# ─── Utilities ───────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            curr[j] = min(prev[j] + 1, curr[j-1] + 1, prev[j-1] + cost)
        prev = curr
    return prev[lb]


def get_base_domain(hostname: str) -> str:
    """Returns base domain (last 2 parts)."""
    parts = hostname.replace('www.', '').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def parse_url_safe(url: str):
    """Parse URL with http fallback."""
    if not url.startswith(('http://', 'https://', 'ftp://')):
        url = 'http://' + url
    try:
        return urlparse(url)
    except Exception:
        return None


# ─── Main Feature Extractor ───────────────────────────────────────────────────

FEATURE_NAMES = [
    'urlLength', 'domainLength', 'subdomainDepth', 'hasHttps',
    'hasIpAddress', 'hasPortInUrl', 'numDots', 'numHyphens',
    'numUnderscores', 'numSlashes', 'numAtSymbols', 'numQuestionMarks',
    'numEquals', 'numAmpersands', 'numPercents', 'numDigitsInDomain',
    'pathLength', 'queryLength', 'hasDoubleSlash', 'hasDashInDomain',
    'domainEntropy', 'pathEntropy', 'tldSuspicious', 'domainAge',
    'hasSuspiciousKeyword', 'hasLoginKeyword', 'hasBrandKeyword', 'hasSecureKeyword',
    'urlEntropyTotal', 'consonantRatio', 'digitRatio', 'specialCharRatio',
    'longestWordLength', 'avgWordLength', 'numSubdomains', 'freeHosting',
    'urlShortenService', 'hexEncoding', 'dataUriScheme', 'levenshteinMin',
    'domainRepeatedChars', 'pathDepth',
]

NUM_FEATURES = len(FEATURE_NAMES)  # 42


def extract_features(url: str) -> List[float]:
    """
    Extract all 42 features from a URL.
    Returns a normalized float list in [0, 1].
    Mirrors the extractFeatures() function in features.js exactly.
    """
    parsed = parse_url_safe(url)
    if parsed is None:
        return [0.0] * NUM_FEATURES

    hostname  = parsed.hostname or ''
    path      = parsed.path     or ''
    query     = parsed.query    or ''
    scheme    = parsed.scheme   or ''
    full_url  = url.lower()
    url_lower = full_url

    base_domain  = get_base_domain(hostname)
    tld_parts    = hostname.split('.')
    tld          = tld_parts[-1].lower() if tld_parts else ''

    subdomains   = hostname.replace('www.', '').split('.')
    subdomain_depth = max(len(subdomains) - 2, 0)

    # ── [00] urlLength (norm /200)
    f00 = min(len(url) / 200.0, 1.0)

    # ── [01] domainLength (norm /50)
    f01 = min(len(hostname) / 50.0, 1.0)

    # ── [02] subdomainDepth (norm /5)
    f02 = min(subdomain_depth / 5.0, 1.0)

    # ── [03] hasHttps
    f03 = 1.0 if scheme == 'https' else 0.0

    # ── [04] hasIpAddress
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    f04 = 1.0 if ip_pattern.search(hostname) else 0.0

    # ── [05] hasPortInUrl
    f05 = 1.0 if parsed.port and parsed.port not in (80, 443) else 0.0

    # ── [06] numDots (norm /10)
    f06 = min(url.count('.') / 10.0, 1.0)

    # ── [07] numHyphens (norm /5)
    f07 = min(url.count('-') / 5.0, 1.0)

    # ── [08] numUnderscores (norm /5)
    f08 = min(url.count('_') / 5.0, 1.0)

    # ── [09] numSlashes (norm /10)
    f09 = min(url.count('/') / 10.0, 1.0)

    # ── [10] numAtSymbols
    f10 = 1.0 if '@' in url else 0.0

    # ── [11] numQuestionMarks (norm /3)
    f11 = min(url.count('?') / 3.0, 1.0)

    # ── [12] numEquals (norm /5)
    f12 = min(url.count('=') / 5.0, 1.0)

    # ── [13] numAmpersands (norm /5)
    f13 = min(url.count('&') / 5.0, 1.0)

    # ── [14] numPercents (norm /5)
    f14 = min(url.count('%') / 5.0, 1.0)

    # ── [15] numDigitsInDomain (norm /10)
    f15 = min(sum(c.isdigit() for c in hostname) / 10.0, 1.0)

    # ── [16] pathLength (norm /100)
    f16 = min(len(path) / 100.0, 1.0)

    # ── [17] queryLength (norm /100)
    f17 = min(len(query) / 100.0, 1.0)

    # ── [18] hasDoubleSlash
    f18 = 1.0 if '//' in path else 0.0

    # ── [19] hasDashInDomain
    f19 = 1.0 if '-' in hostname else 0.0

    # ── [20] domainEntropy (norm /4)
    f20 = min(shannon_entropy(hostname) / 4.0, 1.0)

    # ── [21] pathEntropy (norm /4)
    f21 = min(shannon_entropy(path) / 4.0, 1.0)

    # ── [22] tldSuspicious
    f22 = 1.0 if tld in SUSPICIOUS_TLDS else 0.0

    # ── [23] domainAge (placeholder — 0.5 unknown, 0 old, 1 new)
    f23 = 0.5  # runtime check not possible in offline training

    # ── [24] hasSuspiciousKeyword
    f24 = 1.0 if any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS) else 0.0

    # ── [25] hasLoginKeyword
    f25 = 1.0 if any(kw in url_lower for kw in LOGIN_KEYWORDS) else 0.0

    # ── [26] hasBrandKeyword
    brand_in_url   = any(b in url_lower for b in PHISHING_BRANDS)
    brand_in_domain = any(b in base_domain for b in PHISHING_BRANDS)
    f26 = 1.0 if (brand_in_url and not brand_in_domain) else 0.0

    # ── [27] hasSecureKeyword
    f27 = 1.0 if any(kw in url_lower for kw in SECURE_KEYWORDS) else 0.0

    # ── [28] urlEntropyTotal (norm /5)
    f28 = min(shannon_entropy(url) / 5.0, 1.0)

    # ── [29] consonantRatio
    consonants = set('bcdfghjklmnpqrstvwxyz')
    letters    = [c for c in url_lower if c.isalpha()]
    f29 = (sum(1 for c in letters if c in consonants) / len(letters)) if letters else 0.0

    # ── [30] digitRatio
    f30 = (sum(c.isdigit() for c in url_lower) / len(url_lower)) if url_lower else 0.0

    # ── [31] specialCharRatio
    specials = sum(not c.isalnum() for c in url_lower)
    f31 = specials / len(url_lower) if url_lower else 0.0

    # ── [32] longestWordLength (norm /30)
    words     = re.split(r'[^a-z0-9]', url_lower)
    nonempty  = [w for w in words if w]
    longest   = max((len(w) for w in nonempty), default=0)
    f32 = min(longest / 30.0, 1.0)

    # ── [33] avgWordLength (norm /15)
    avg_len = (sum(len(w) for w in nonempty) / len(nonempty)) if nonempty else 0
    f33 = min(avg_len / 15.0, 1.0)

    # ── [34] numSubdomains (norm /5)
    f34 = min(subdomain_depth / 5.0, 1.0)

    # ── [35] freeHosting
    f35 = 1.0 if any(base_domain.endswith(fh) for fh in FREE_HOSTING) else 0.0

    # ── [36] urlShortenService
    f36 = 1.0 if any(base_domain == us for us in URL_SHORTENERS) else 0.0

    # ── [37] hexEncoding
    f37 = 1.0 if re.search(r'%[0-9a-fA-F]{2}', url) else 0.0

    # ── [38] dataUriScheme
    f38 = 1.0 if url_lower.startswith('data:') else 0.0

    # ── [39] levenshteinMin (norm /20) — min edit distance to known domains
    lev_min = min(levenshtein(base_domain, d) for d in LEGIT_DOMAINS)
    f39 = min(lev_min / 20.0, 1.0)

    # ── [40] domainRepeatedChars
    repeated = any(hostname[i] == hostname[i+1] == hostname[i+2]
                   for i in range(len(hostname) - 2))
    f40 = 1.0 if repeated else 0.0

    # ── [41] pathDepth (norm /8)
    depth = len([p for p in path.split('/') if p])
    f41 = min(depth / 8.0, 1.0)

    features = [
        f00, f01, f02, f03, f04, f05, f06, f07,
        f08, f09, f10, f11, f12, f13, f14, f15,
        f16, f17, f18, f19, f20, f21, f22, f23,
        f24, f25, f26, f27, f28, f29, f30, f31,
        f32, f33, f34, f35, f36, f37, f38, f39,
        f40, f41,
    ]

    # Clamp all to [0, 1]
    return [max(0.0, min(1.0, float(f))) for f in features]


def batch_extract(urls: List[str], show_progress: bool = True) -> List[List[float]]:
    """Extract features from a list of URLs with optional progress bar."""
    try:
        from tqdm import tqdm
        it = tqdm(urls, desc='Extracting features', unit='url') if show_progress else urls
    except ImportError:
        it = urls
    return [extract_features(url) for url in it]
