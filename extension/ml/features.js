/**
 * AI Phishing Shield — ML Feature Extraction Engine
 * ═══════════════════════════════════════════════════════════════════════════
 * Extracts 42 features from a URL for phishing detection.
 * All computation runs client-side — no network requests.
 *
 * Feature Groups:
 *   [1-10]  URL Structure Features
 *   [11-18] Domain & TLD Features
 *   [19-26] Character-Level Features
 *   [27-32] Path & Query Features
 *   [33-37] Brand / Typosquatting Features
 *   [38-42] Statistical / Entropy Features
 * ═══════════════════════════════════════════════════════════════════════════
 */

'use strict';

// ─── Known Brand List (for typosquatting detection) ───────────────────────────
const KNOWN_BRANDS = [
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'instagram',
  'twitter', 'netflix', 'ebay', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
  'linkedin', 'dropbox', 'icloud', 'yahoo', 'outlook', 'office365', 'onedrive',
  'steam', 'roblox', 'discord', 'twitch', 'snapchat', 'tiktok', 'whatsapp',
  'telegram', 'coinbase', 'binance', 'blockchain', 'metamask', 'dhl', 'fedex',
  'ups', 'usps', 'irs', 'ssa', 'medicare', 'visa', 'mastercard', 'americanexpress',
  'wellsfargo', 'hsbc', 'barclays', 'santander', 'natwest', 'lloyds',
];

// ─── Suspicious TLDs frequently abused by phishers ───────────────────────────
const RARE_TLDS = new Set([
  'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'online', 'site',
  'website', 'space', 'fun', 'rocks', 'buzz', 'click', 'link', 'live',
  'download', 'stream', 'win', 'loan', 'date', 'trade', 'accountant', 'science',
  'faith', 'review', 'party', 'racing', 'bid', 'webcam', 'men', 'cricket',
]);

// ─── Suspicious keywords in URLs ──────────────────────────────────────────────
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'account', 'secure', 'update', 'confirm',
  'banking', 'password', 'credential', 'wallet', 'support', 'helpdesk',
  'suspended', 'unlock', 'alert', 'warning', 'limited', 'recover', 'billing',
  'payment', 'invoice', 'free', 'prize', 'winner', 'congratulations',
];

// ─── Safe (legit) TLDs ────────────────────────────────────────────────────────
const SAFE_TLDS = new Set(['com', 'org', 'net', 'edu', 'gov', 'io', 'co']);


// ═══════════════════════════════════════════════════════════════════════════════
// CORE UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Safely parse a URL — returns null on failure
 */
function safeParseUrl(rawUrl) {
  try {
    // Only prepend http:// if no recognized scheme is present
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl)) {
      rawUrl = 'http://' + rawUrl;
    }
    return new URL(rawUrl);
  } catch {
    return null;
  }
}

/**
 * Shannon entropy of a string — high entropy ≈ random/obfuscated
 * H = -Σ p(c) × log2(p(c))
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum + p * Math.log2(p);
  }, 0);
}

/**
 * Levenshtein distance between two strings
 * Used for typosquatting detection
 */
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

/**
 * Finds the closest brand to a given string, returns { brand, distance, ratio }
 */
function closestBrand(str) {
  let minDist = Infinity;
  let closest = null;
  const lower = str.toLowerCase();

  for (const brand of KNOWN_BRANDS) {
    const dist = levenshtein(lower, brand);
    if (dist < minDist) {
      minDist = dist;
      closest = brand;
    }
  }

  const ratio = closest ? minDist / Math.max(closest.length, lower.length) : 1;
  return { brand: closest, distance: minDist, ratio };
}

/**
 * Count occurrences of a character in a string
 */
function countChar(str, char) {
  return (str.match(new RegExp('\\' + char, 'g')) || []).length;
}

/**
 * Check if a string looks like an IPv4 address
 */
function isIPv4(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/**
 * Decode percent-encoding and check for multi-level encoding
 */
function detectHexEncoding(url) {
  const hexPattern = /%[0-9a-fA-F]{2}/g;
  const matches = url.match(hexPattern) || [];
  return {
    hasHex: matches.length > 0,
    hexCount: matches.length,
    hasDoubleEncoding: url.includes('%25'),
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// MAIN FEATURE EXTRACTOR — returns a normalized 42-feature vector + metadata
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * extractFeatures(url) → { vector: Float32Array(42), ...metadata }
 *
 * @param {string} rawUrl - The URL to analyze
 * @returns {Object} Feature object with vector and human-readable metadata
 */
export function extractFeatures(rawUrl) {
  const parsed = safeParseUrl(rawUrl);

  // ── Defaults for unparseable URLs ─────────────────────────────────────────
  if (!parsed) {
    return _defaultFeatures(rawUrl);
  }

  const fullUrl   = parsed.href;
  const hostname  = parsed.hostname.toLowerCase();
  const pathname  = parsed.pathname;
  const search    = parsed.search;
  const protocol  = parsed.protocol;
  const port      = parsed.port;

  // ── Domain breakdown ───────────────────────────────────────────────────────
  const hostParts    = hostname.replace(/^www\./, '').split('.');
  const tld          = hostParts[hostParts.length - 1] || '';
  const domain       = hostParts[hostParts.length - 2] || '';
  const subdomains   = hostParts.slice(0, -2);
  const subdomainStr = subdomains.join('.');

  // ── Character analysis ─────────────────────────────────────────────────────
  const hexInfo      = detectHexEncoding(fullUrl);
  const urlLower     = fullUrl.toLowerCase();
  const allDigitsSub = /^\d+$/.test(domain);

  // ── Brand / typosquatting ──────────────────────────────────────────────────
  const domainBrandCheck  = closestBrand(domain);
  const subdomainBrandHit = KNOWN_BRANDS.find(b => subdomainStr.includes(b));
  const fullUrlBrandHit   = KNOWN_BRANDS.find(b => urlLower.includes(b) && !hostname.endsWith(`${b}.com`));
  const suspKwHit         = SUSPICIOUS_KEYWORDS.find(k => urlLower.includes(k));

  // ── Path analysis ──────────────────────────────────────────────────────────
  const pathParts    = pathname.split('/').filter(Boolean);
  const queryParams  = [...parsed.searchParams.entries()];

  // ─────────────────────────────────────────────────────────────────────────
  // FEATURE COMPUTATION (42 features, all normalized to [0, 1] for ML)
  // ─────────────────────────────────────────────────────────────────────────

  // [F01] URL total length — normalized (cap at 200)
  const f01_urlLength        = Math.min(fullUrl.length / 200, 1);

  // [F02] Hostname length — normalized (cap at 75)
  const f02_hostLength       = Math.min(hostname.length / 75, 1);

  // [F03] Subdomain depth — number of subdomains (cap at 6)
  const f03_subdomainDepth   = Math.min(subdomains.length / 6, 1);

  // [F04] Has IP address as host
  const f04_hasIp            = isIPv4(hostname) ? 1 : 0;

  // [F05] Missing HTTPS
  const f05_noHttps          = protocol === 'http:' ? 1 : 0;

  // [F06] Non-standard port used (80/443 are standard)
  const f06_suspPort         = (port && port !== '80' && port !== '443') ? 1 : 0;

  // [F07] @ symbol in URL (redirects to different host)
  const f07_hasAt            = fullUrl.includes('@') ? 1 : 0;

  // [F08] Double slash in path (//)
  const f08_hasDoubleSlash   = (pathname.match(/\/\//g) || []).length > 0 ? 1 : 0;

  // [F09] Hyphen count in domain — normalized (cap at 6)
  const f09_hyphenCount      = Math.min(countChar(hostname, '-') / 6, 1);

  // [F10] Dot count in hostname — normalized (cap at 8)
  const f10_dotCount         = Math.min(countChar(hostname, '.') / 8, 1);

  // [F11] Rare / suspicious TLD
  const f11_rareTld          = RARE_TLDS.has(tld.toLowerCase()) ? 1 : 0;

  // [F12] Domain is all digits (e.g., 192-168-1-1.xyz)
  const f12_numericDomain    = allDigitsSub ? 1 : 0;

  // [F13] TLD length — very long TLDs suspicious (normalize at 12)
  const f13_tldLength        = Math.min(tld.length / 12, 1);

  // [F14] Known brand keyword found in subdomain (spoofing)
  const f14_brandInSubdomain = subdomainBrandHit ? 1 : 0;

  // [F15] Known brand keyword anywhere in URL (with domain mismatch)
  const f15_brandInUrl       = fullUrlBrandHit ? 1 : 0;

  // [F16] Typosquatting score — low Levenshtein distance to a brand
  // Ratio 0=exact match (spoof), 1=no similarity. We invert for "suspicion"
  const f16_typoScore        = Math.max(0, 1 - domainBrandCheck.ratio * 2);

  // [F17] Domain registration keyword abuse (login, verify, secure, etc.)
  const f17_suspKeyword      = suspKwHit ? 1 : 0;

  // [F18] Subdomain contains digits
  const f18_subDigits        = /\d/.test(subdomainStr) ? 1 : 0;

  // [F19] Hex encoding present
  const f19_hasHex           = hexInfo.hasHex ? 1 : 0;

  // [F20] Number of hex-encoded chars — normalized (cap at 10)
  const f20_hexCount         = Math.min(hexInfo.hexCount / 10, 1);

  // [F21] Double encoding (%25)
  const f21_doubleEncoding   = hexInfo.hasDoubleEncoding ? 1 : 0;

  // [F22] Count of special chars (-, _, ~, %) in URL — normalized (cap 20)
  const f22_specialChars     = Math.min(
    (fullUrl.match(/[-_~%]/g) || []).length / 20, 1
  );

  // [F23] Count of digits in hostname — normalized (cap 10)
  const f23_hostDigits       = Math.min(
    (hostname.match(/\d/g) || []).length / 10, 1
  );

  // [F24] Count of uppercase letters in hostname — normalized (cap 5)
  const f24_upperCount       = Math.min(
    (parsed.hostname.match(/[A-Z]/g) || []).length / 5, 1
  );

  // [F25] Presence of redirection pattern (url= , redirect=, next=)
  const f25_redirectParam    = /[?&](url|redirect|next|redir|goto|link|return)=/i.test(search) ? 1 : 0;

  // [F26] Multiple question marks or encoded = signs
  const f26_multiQuery       = (fullUrl.match(/\?/g) || []).length > 1 ? 1 : 0;

  // [F27] Path depth — number of slashes in path (cap at 8)
  const f27_pathDepth        = Math.min(pathParts.length / 8, 1);

  // [F28] Path length — normalized (cap 100)
  const f28_pathLength       = Math.min(pathname.length / 100, 1);

  // [F29] Query string length — normalized (cap 100)
  const f29_queryLength      = Math.min(search.length / 100, 1);

  // [F30] Number of query params — normalized (cap at 10)
  const f30_queryParamCount  = Math.min(queryParams.length / 10, 1);

  // [F31] Base64-like pattern in path (long alphanumeric segments)
  const f31_base64Pattern    = /[a-zA-Z0-9+/]{30,}={0,2}/.test(pathname) ? 1 : 0;

  // [F32] Long numeric token in URL (e.g., session token abuse)
  const f32_longNumToken     = /\d{10,}/.test(fullUrl) ? 1 : 0;

  // [F33] Shannon entropy of full hostname
  const f33_hostEntropy      = Math.min(shannonEntropy(hostname) / 5, 1);

  // [F34] Shannon entropy of path
  const f34_pathEntropy      = Math.min(shannonEntropy(pathname) / 5, 1);

  // [F35] Shannon entropy of full URL
  const f35_urlEntropy       = Math.min(shannonEntropy(fullUrl) / 5, 1);

  // [F36] Ratio of digits to total URL length
  const f36_digitRatio       = (fullUrl.match(/\d/g) || []).length / Math.max(fullUrl.length, 1);

  // [F37] Ratio of special chars to total URL length
  const f37_specialRatio     = (fullUrl.match(/[^a-zA-Z0-9]/g) || []).length / Math.max(fullUrl.length, 1);

  // [F38] Consecutive hyphens (--) in hostname
  const f38_consecHyphens    = hostname.includes('--') ? 1 : 0;

  // [F39] Domain starts or ends with hyphen (invalid but used in IDN abuse)
  const f39_hyphenBoundary   = (domain.startsWith('-') || domain.endsWith('-')) ? 1 : 0;

  // [F40] Punycode / IDN homoglyph (xn--)
  const f40_punycode         = hostname.includes('xn--') ? 1 : 0;

  // [F41] Multiple TLD pattern (e.g., paypal.com.phishing.xyz)
  const f41_multipleTld      = hostParts.filter(p => SAFE_TLDS.has(p.toLowerCase())).length > 1 ? 1 : 0;

  // [F42] Fragment identifier abuse (# used to hide real path)
  const f42_fragmentAbuse    = parsed.hash.length > 20 ? 1 : 0;

  // ── Assemble feature vector ────────────────────────────────────────────────
  const vector = new Float32Array([
    f01_urlLength, f02_hostLength, f03_subdomainDepth, f04_hasIp,
    f05_noHttps, f06_suspPort, f07_hasAt, f08_hasDoubleSlash,
    f09_hyphenCount, f10_dotCount, f11_rareTld, f12_numericDomain,
    f13_tldLength, f14_brandInSubdomain, f15_brandInUrl, f16_typoScore,
    f17_suspKeyword, f18_subDigits, f19_hasHex, f20_hexCount,
    f21_doubleEncoding, f22_specialChars, f23_hostDigits, f24_upperCount,
    f25_redirectParam, f26_multiQuery, f27_pathDepth, f28_pathLength,
    f29_queryLength, f30_queryParamCount, f31_base64Pattern, f32_longNumToken,
    f33_hostEntropy, f34_pathEntropy, f35_urlEntropy, f36_digitRatio,
    f37_specialRatio, f38_consecHyphens, f39_hyphenBoundary, f40_punycode,
    f41_multipleTld, f42_fragmentAbuse,
  ]);

  // ── Human-readable metadata (used for explanations) ───────────────────────
  return {
    // Raw vector for ML inference
    vector,

    // URL basics
    url:             fullUrl,
    hostname,
    domain,
    tld,
    protocol,

    // Boolean flags (used by rule engine + flag generator)
    hasIpAddress:      f04_hasIp === 1,
    hasHttps:          f05_noHttps === 0,
    hasSuspiciousPort: f06_suspPort === 1,
    hasAtSymbol:       f07_hasAt === 1,
    hasDoubleSlash:    f08_hasDoubleSlash === 1,
    isRareTLD:         f11_rareTld === 1,
    hasBrandKeyword:   f14_brandInSubdomain === 1 || f15_brandInUrl === 1,
    hasSuspiciousChars:f22_specialChars > 0.1,
    hasHexEncoding:    f19_hasHex === 1,
    hasPunycode:       f40_punycode === 1,
    hasMultipleTld:    f41_multipleTld === 1,
    hasRedirectParam:  f25_redirectParam === 1,
    hasBase64Pattern:  f31_base64Pattern === 1,
    hasConsecHyphens:  f38_consecHyphens === 1,

    // Numeric metrics
    urlLength:         fullUrl.length,
    subdomainDepth:    subdomains.length,
    hyphenCount:       countChar(hostname, '-'),
    dotCount:          countChar(hostname, '.'),
    pathDepth:         pathParts.length,
    queryParamCount:   queryParams.length,
    entropy:           shannonEntropy(fullUrl),
    hostEntropy:       shannonEntropy(hostname),

    // Brand detection
    brandKeyword:       subdomainBrandHit || fullUrlBrandHit || null,
    suspiciousKeyword:  suspKwHit || null,
    typosquatTarget:    domainBrandCheck.brand,
    typosquatDistance:  domainBrandCheck.distance,
    typosquatRatio:     domainBrandCheck.ratio,

    // Is likely typosquat? (distance 1-2 from a known brand)
    isTyposquat: domainBrandCheck.distance <= 2 && domainBrandCheck.distance > 0,
  };
}

/**
 * Returns a zeroed-out feature object for unparseable URLs
 */
function _defaultFeatures(rawUrl) {
  return {
    vector: new Float32Array(42).fill(0),
    url: rawUrl, hostname: '', domain: '', tld: '', protocol: '',
    hasIpAddress: false, hasHttps: false, hasSuspiciousPort: false,
    hasAtSymbol: false, hasDoubleSlash: false, isRareTLD: false,
    hasBrandKeyword: false, hasSuspiciousChars: false, hasHexEncoding: false,
    hasPunycode: false, hasMultipleTld: false, hasRedirectParam: false,
    hasBase64Pattern: false, hasConsecHyphens: false,
    urlLength: rawUrl.length, subdomainDepth: 0, hyphenCount: 0,
    dotCount: 0, pathDepth: 0, queryParamCount: 0,
    entropy: shannonEntropy(rawUrl), hostEntropy: 0,
    brandKeyword: null, suspiciousKeyword: null,
    typosquatTarget: null, typosquatDistance: 99, typosquatRatio: 1,
    isTyposquat: false,
  };
}


// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE DESCRIPTIONS (for UI / explainability)
// ═══════════════════════════════════════════════════════════════════════════════

export const FEATURE_NAMES = [
  'URL Length',          'Hostname Length',    'Subdomain Depth',    'IP Address Host',
  'Missing HTTPS',       'Suspicious Port',    '@ Symbol',           'Double Slash in Path',
  'Hyphen Count',        'Dot Count',          'Rare TLD',           'Numeric Domain',
  'TLD Length',          'Brand in Subdomain', 'Brand in URL',       'Typosquat Score',
  'Suspicious Keyword',  'Digits in Subdomain','Hex Encoding',       'Hex Char Count',
  'Double Encoding',     'Special Chars',      'Host Digits',        'Uppercase in Host',
  'Redirect Param',      'Multiple ?',         'Path Depth',         'Path Length',
  'Query Length',        'Query Param Count',  'Base64 Pattern',     'Long Numeric Token',
  'Host Entropy',        'Path Entropy',       'URL Entropy',        'Digit Ratio',
  'Special Char Ratio',  'Consecutive Hyphens','Hyphen Boundary',    'Punycode/IDN',
  'Multiple TLDs',       'Fragment Abuse',
];

/**
 * Converts a feature vector to a named object for debugging/inspection
 */
export function vectorToNamedObject(vector) {
  const obj = {};
  FEATURE_NAMES.forEach((name, i) => {
    obj[name] = parseFloat(vector[i].toFixed(4));
  });
  return obj;
}


// ═══════════════════════════════════════════════════════════════════════════════
// RULE-BASED SCORER (fast fallback, also used for XAI weight contribution)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Score a feature object using weighted rules.
 * Returns { score: 0-100, contributions: [...] }
 */
export function ruleBasedScore(features) {
  const rules = [
    // ── HIGH-CONFIDENCE phishing signals (weight 20-28) ──────────────────────
    { id: 'ip_addr',        weight: 28, active: features.hasIpAddress,
      label: 'IP Address URL',
      detail: 'Uses a raw IP address instead of a domain name — a classic phishing tactic.' },

    { id: 'at_symbol',      weight: 25, active: features.hasAtSymbol,
      label: '@ Symbol in URL',
      detail: 'The @ symbol tricks browsers into redirecting to a completely different host.' },

    { id: 'typosquat',      weight: 24, active: features.isTyposquat,
      label: `Typosquatting: "${features.domain}" ≈ "${features.typosquatTarget}"`,
      detail: `Domain is only ${features.typosquatDistance} character(s) away from the real "${features.typosquatTarget}" brand. Likely impersonation.` },

    { id: 'punycode',       weight: 22, active: features.hasPunycode,
      label: 'Punycode / IDN Homoglyph Attack',
      detail: 'Uses internationalized domain names (xn--) to mimic real domains with look-alike characters.' },

    { id: 'brand_subdomain',weight: 20, active: features.hasBrandKeyword && features.subdomainDepth > 0,
      label: 'Brand Name Spoofed in Subdomain',
      detail: `Uses "${features.brandKeyword}" in the subdomain to appear legitimate while hiding the real domain.` },

    { id: 'multiple_tld',   weight: 20, active: features.hasMultipleTld,
      label: 'Fake Domain with Multiple TLDs',
      detail: 'Embeds a legitimate TLD (like .com) inside the subdomain to confuse users (e.g., paypal.com.attacker.xyz).' },

    // ── MEDIUM-CONFIDENCE signals (weight 10-18) ─────────────────────────────
    { id: 'double_encoding',weight: 18, active: features.vector?.[20] === 1,
      label: 'Double URL Encoding',
      detail: 'URL is double-encoded (%25XX) — an advanced obfuscation technique used to evade filters.' },

    { id: 'hex_encoding',   weight: 14, active: features.hasHexEncoding,
      label: 'Hex-Encoded Characters',
      detail: 'URL contains percent-encoded characters (%XX) often used to bypass security filters.' },

    { id: 'redirect_param', weight: 14, active: features.hasRedirectParam,
      label: 'Open Redirect Parameter',
      detail: 'URL contains a redirect parameter (url=, next=, goto=) — can silently redirect you elsewhere.' },

    { id: 'rare_tld',       weight: 12, active: features.isRareTLD,
      label: `Suspicious TLD (.${features.tld})`,
      detail: `The .${features.tld} TLD is frequently registered for free and heavily abused by phishing campaigns.` },

    { id: 'deep_subdomain', weight: 12, active: features.subdomainDepth > 3,
      label: 'Excessive Subdomain Depth',
      detail: `${features.subdomainDepth} subdomain levels detected — used to push the real domain out of view.` },

    { id: 'base64',         weight: 10, active: features.hasBase64Pattern,
      label: 'Base64-Encoded Segment',
      detail: 'A long encoded segment in the path is typically used to hide tracking tokens or obfuscated commands.' },

    // ── LOW-CONFIDENCE signals (weight 3-8) — only flag, do not heavily score ─
    { id: 'no_https',       weight: 5,  active: !features.hasHttps,
      label: 'No HTTPS Encryption',
      detail: 'Site does not use HTTPS — your credentials can be intercepted in transit.' },

    { id: 'susp_keyword',   weight: 4,  active: !!features.suspiciousKeyword,
      label: `Suspicious Keyword: "${features.suspiciousKeyword}"`,
      detail: 'URL contains a keyword commonly used in phishing pages to appear official.' },

    { id: 'long_url',       weight: 4,  active: features.urlLength > 120,
      label: 'Excessively Long URL',
      detail: `URL is ${features.urlLength} characters long — used to hide the real domain and confuse users.` },

    { id: 'high_entropy',   weight: 4,  active: features.entropy > 4.8,
      label: 'High URL Entropy',
      detail: `Entropy score ${features.entropy.toFixed(2)} — the URL contains randomized or obfuscated segments.` },

    { id: 'double_slash',   weight: 4,  active: features.hasDoubleSlash,
      label: 'Double Slash in Path',
      detail: 'Unusual double-slash sequences in the URL path can confuse parsers and indicate manipulation.' },

    { id: 'consec_hyphens', weight: 3,  active: features.hasConsecHyphens,
      label: 'Consecutive Hyphens in Domain',
      detail: 'Consecutive hyphens (--) are a common indicator of domain name abuse.' },
  ];

  const activeRules = rules.filter(r => r.active);
  const rawScore = activeRules.reduce((sum, r) => sum + r.weight, 0);
  const score = Math.min(rawScore, 100);

  return {
    score,
    flags: activeRules.map(({ id, label, detail }) => ({ id, label, detail })),
  };
}
