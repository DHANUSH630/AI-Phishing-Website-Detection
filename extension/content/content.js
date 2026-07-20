/**
 * AI Phishing Shield — Content Script (Phase 4 — Full DOM Scanner)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Injected into every page at document_idle.
 *
 * DOM Checks performed:
 *  [01] Password field presence & count
 *  [02] Cross-origin form action (form posts to different domain)
 *  [03] Hidden / honeypot fields harvesting data
 *  [04] Iframe overlay covering large portions of the viewport
 *  [05] Auto-fill disabled on sensitive fields (phisher blocking autofill)
 *  [06] Logo brand vs domain mismatch (Apple logo on non-apple.com)
 *  [07] Fake padlock / HTTPS imagery
 *  [08] External scripts from suspicious domains
 *  [09] Copy/paste & right-click blocking (anti-inspection)
 *  [10] Suspicious meta-refresh redirects
 *  [11] Invisible / zero-opacity form overlays
 *  [12] Missing or mismatched page title vs domain
 *  [13] Credential field outside <form> tag
 *  [14] Data exfiltration via URL parameters (passwords in GET)
 *  [15] Obfuscated inline scripts (eval, atob, long hex strings)
 * ═══════════════════════════════════════════════════════════════════════════
 */

(function () {
  'use strict';

  // ── Guard: avoid double injection ─────────────────────────────────────────
  if (window.__phishingShieldInjected) return;
  window.__phishingShieldInjected = true;

  // ── Known brands for logo/title mismatch ──────────────────────────────────
  const KNOWN_BRANDS = [
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook',
    'instagram', 'twitter', 'netflix', 'ebay', 'chase', 'bankofamerica',
    'wellsfargo', 'citibank', 'linkedin', 'dropbox', 'icloud', 'yahoo',
    'outlook', 'office365', 'steam', 'discord', 'coinbase', 'binance',
    'whatsapp', 'telegram', 'dhl', 'fedex', 'ups', 'usps', 'irs',
    'visa', 'mastercard', 'americanexpress', 'hsbc', 'barclays',
  ];

  // ── Suspicious TLDs for external script checks ────────────────────────────
  const RARE_TLDS = new Set([
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'club', 'online',
    'site', 'website', 'space', 'fun', 'rocks', 'buzz', 'click', 'link',
  ]);

  // ═══════════════════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  function getHostname(url) {
    try { return new URL(url).hostname.toLowerCase(); }
    catch { return ''; }
  }

  function getBaseDomain(hostname) {
    const parts = hostname.replace(/^www\./, '').split('.');
    return parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
  }

  function getTLD(hostname) {
    const parts = hostname.split('.');
    return parts[parts.length - 1] || '';
  }

  function pageHostname() {
    return window.location.hostname.toLowerCase();
  }

  function pageBaseDomain() {
    return getBaseDomain(pageHostname());
  }

  function isVisible(el) {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    if (style.display === 'none')       return false;
    if (style.visibility === 'hidden')  return false;
    if (parseFloat(style.opacity) === 0) return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function coveragePercent(rect) {
    const vw = window.innerWidth  || document.documentElement.clientWidth;
    const vh = window.innerHeight || document.documentElement.clientHeight;
    const area     = rect.width * rect.height;
    const viewport = vw * vh;
    return viewport > 0 ? (area / viewport) * 100 : 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [01] — Password Fields
  // ═══════════════════════════════════════════════════════════════════════════

  function checkPasswordFields() {
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const visiblePwds    = [...passwordInputs].filter(isVisible);

    return {
      hasPasswordField:  visiblePwds.length > 0,
      passwordCount:     visiblePwds.length,
      multiplePasswords: visiblePwds.length > 1,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [02] — Cross-Origin Form Action
  // ═══════════════════════════════════════════════════════════════════════════

  function checkFormActions() {
    const forms = document.querySelectorAll('form');
    const suspicious = [];

    for (const form of forms) {
      const action = form.getAttribute('action') || '';

      // Empty action = submits to current page (OK)
      if (!action || action === '#' || action.startsWith('javascript:')) continue;

      // Relative URLs = same origin (OK)
      if (!action.startsWith('http://') && !action.startsWith('https://')) continue;

      const actionHost = getHostname(action);
      const pageHost   = pageBaseDomain();
      const actionBase = getBaseDomain(actionHost);

      if (actionBase !== pageHost) {
        suspicious.push({
          formId:     form.id || form.name || 'unknown',
          action,
          actionHost,
          pageHost,
        });
      }
    }

    return {
      hasCrossOriginAction: suspicious.length > 0,
      crossOriginForms:     suspicious,
      firstCrossOriginDest: suspicious[0]?.actionHost || null,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [03] — Hidden / Honeypot Fields
  // ═══════════════════════════════════════════════════════════════════════════

  function checkHiddenFields() {
    const sensitiveNames = /\b(user|email|phone|card|ssn|password|pw|pass|login|account|credit|cvv|pin|dob|birth|social)\b/i;
    const allInputs = document.querySelectorAll('input');
    const suspicious = [];

    for (const input of allInputs) {
      const name = input.name || input.id || '';
      if (!sensitiveNames.test(name)) continue;

      const style  = window.getComputedStyle(input);
      const hidden =
        input.type === 'hidden' ||
        style.display    === 'none' ||
        style.visibility === 'hidden' ||
        parseFloat(style.opacity) === 0 ||
        parseFloat(style.height) < 2 ||
        parseFloat(style.width)  < 2 ||
        input.getAttribute('tabindex') === '-1';

      if (hidden) {
        suspicious.push({ name, type: input.type });
      }
    }

    return {
      hasHiddenFields: suspicious.length > 0,
      hiddenFieldCount: suspicious.length,
      hiddenFields:     suspicious,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [04] — Iframe Overlay
  // ═══════════════════════════════════════════════════════════════════════════

  function checkIframeOverlay() {
    const iframes = document.querySelectorAll('iframe');
    const suspicious = [];

    for (const iframe of iframes) {
      const src   = iframe.src || '';
      const style = window.getComputedStyle(iframe);
      const rect  = iframe.getBoundingClientRect();

      // Skip tiny iframes (widgets, captchas, etc.)
      if (rect.width < 200 || rect.height < 200) continue;

      const coverage  = coveragePercent(rect);
      const srcHost   = src ? getHostname(src) : '';
      const crossSrc  = srcHost && getBaseDomain(srcHost) !== pageBaseDomain();

      // Position fixed/absolute covering large area = suspicious
      const isOverlay =
        (style.position === 'fixed' || style.position === 'absolute') &&
        (parseFloat(style.zIndex) > 1000 || style.inset === '0px') &&
        coverage > 40;

      if (isOverlay || (crossSrc && coverage > 50)) {
        suspicious.push({ src: srcHost || 'same-origin', coverage: Math.round(coverage) });
      }
    }

    return {
      hasIframeOverlay: suspicious.length > 0,
      iframeOverlays:   suspicious,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [05] — Autofill Disabled on Sensitive Fields
  // ═══════════════════════════════════════════════════════════════════════════

  function checkAutofill() {
    const sensitiveInputs = document.querySelectorAll(
      'input[type="password"], input[name*="user"], input[name*="email"], input[autocomplete="username"]'
    );

    let disabledCount = 0;
    for (const input of sensitiveInputs) {
      const ac = (input.getAttribute('autocomplete') || '').toLowerCase();
      if (ac === 'off' || ac === 'false' || ac === 'new-password') {
        disabledCount++;
      }
    }

    return {
      autofillDisabled:      disabledCount > 0,
      autofillDisabledCount: disabledCount,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [06] — Brand Logo vs Domain Mismatch
  // ═══════════════════════════════════════════════════════════════════════════

  function checkBrandMismatch() {
    const hostname    = pageHostname();
    const baseDomain  = pageBaseDomain();
    const detectedBrands = new Set();

    // Check page title
    const title = document.title.toLowerCase();
    for (const brand of KNOWN_BRANDS) {
      if (title.includes(brand)) detectedBrands.add(brand);
    }

    // Check logo image alt/src attributes
    const imgs = document.querySelectorAll('img');
    for (const img of imgs) {
      const src = (img.src || '').toLowerCase();
      const alt = (img.alt || '').toLowerCase();
      for (const brand of KNOWN_BRANDS) {
        if (src.includes(brand) || alt.includes(brand)) {
          detectedBrands.add(brand);
        }
      }
    }

    // Check meta og:site_name / application-name
    const metaTags = document.querySelectorAll('meta[property="og:site_name"], meta[name="application-name"]');
    for (const meta of metaTags) {
      const content = (meta.getAttribute('content') || '').toLowerCase();
      for (const brand of KNOWN_BRANDS) {
        if (content.includes(brand)) detectedBrands.add(brand);
      }
    }

    // Check h1/h2 headings
    const headings = document.querySelectorAll('h1, h2');
    for (const h of headings) {
      const text = (h.textContent || '').toLowerCase();
      for (const brand of KNOWN_BRANDS) {
        if (text.includes(brand)) detectedBrands.add(brand);
      }
    }

    // Mismatch: brand detected but not in domain
    const mismatches = [...detectedBrands].filter(brand => !baseDomain.includes(brand));

    return {
      hasBrandMismatch:    mismatches.length > 0,
      detectedBrands:      [...detectedBrands],
      mismatchedBrands:    mismatches,
      primaryMismatch:     mismatches[0] || null,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [07] — Fake HTTPS / Padlock Imagery
  // ═══════════════════════════════════════════════════════════════════════════

  function checkFakeHttps() {
    if (window.location.protocol === 'https:') return { hasFakeHttps: false };

    // Only relevant on HTTP pages — look for padlock imagery
    const padlockTerms = /padlock|secure|ssl|https|lock|verified|trusted/i;
    const imgs = document.querySelectorAll('img');
    let fakePadlock = false;

    for (const img of imgs) {
      if (padlockTerms.test(img.src + ' ' + img.alt + ' ' + img.className)) {
        fakePadlock = true;
        break;
      }
    }

    // Also check for green bar / security-themed text on HTTP
    if (!fakePadlock) {
      const text = document.body?.textContent || '';
      if (/secure connection|256-bit encryption|ssl protected/i.test(text)) {
        fakePadlock = true;
      }
    }

    return { hasFakeHttps: fakePadlock };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [08] — Suspicious External Scripts
  // ═══════════════════════════════════════════════════════════════════════════

  function checkExternalScripts() {
    const scripts = document.querySelectorAll('script[src]');
    const suspicious = [];

    for (const script of scripts) {
      const src  = script.src || '';
      const host = getHostname(src);
      if (!host) continue;

      const base = getBaseDomain(host);
      const tld  = getTLD(host);
      const same = base === pageBaseDomain();

      if (!same && RARE_TLDS.has(tld)) {
        suspicious.push({ src: host });
      }
    }

    return {
      hasSuspiciousScripts: suspicious.length > 0,
      suspiciousScripts:    suspicious,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [09] — Anti-Inspection Techniques
  // ═══════════════════════════════════════════════════════════════════════════

  function checkAntiInspection() {
    const html = document.documentElement.outerHTML || '';

    // Contextmenu / copy blocking
    const blocksContext = /oncontextmenu\s*=\s*["']?\s*return\s+false/i.test(html);
    const blocksCopy    = /oncopy\s*=\s*["']?\s*return\s+false/i.test(html);

    // DevTools detection patterns
    const hasDevtoolsDetect =
      /debugger|disable-devtool|devtools\.open/i.test(html);

    // Disable text selection
    const disablesSelect =
      /onselectstart\s*=\s*["']?\s*return\s+false|user-select\s*:\s*none/i.test(html);

    return {
      hasAntiInspection: blocksContext || blocksCopy || hasDevtoolsDetect || disablesSelect,
      blocksContextMenu: blocksContext,
      blocksCopy,
      hasDevtoolsDetect,
      disablesTextSelect: disablesSelect,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [10] — Meta-Refresh Redirect
  // ═══════════════════════════════════════════════════════════════════════════

  function checkMetaRefresh() {
    const meta = document.querySelector('meta[http-equiv="refresh"]');
    if (!meta) return { hasMetaRefresh: false };

    const content = meta.getAttribute('content') || '';
    const match   = content.match(/url\s*=\s*(.+)/i);
    const target  = match ? match[1].trim().replace(/['"]/g, '') : '';
    const targetHost = target ? getHostname(target) : '';
    const crossOrigin = targetHost && getBaseDomain(targetHost) !== pageBaseDomain();

    const delayMatch = content.match(/^(\d+)/);
    const delay = delayMatch ? parseInt(delayMatch[1]) : 0;

    return {
      hasMetaRefresh:         true,
      metaRefreshTarget:      target,
      metaRefreshCrossOrigin: crossOrigin,
      metaRefreshDelay:       delay,
      metaRefreshSuspicious:  crossOrigin || delay < 3,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [11] — Invisible Form Overlays
  // ═══════════════════════════════════════════════════════════════════════════

  function checkInvisibleOverlays() {
    const overlaySelectors = [
      'div[style*="position: fixed"]',
      'div[style*="position:fixed"]',
      'div[style*="position: absolute"]',
    ];

    const candidates = document.querySelectorAll(overlaySelectors.join(','));
    const suspicious = [];

    for (const el of candidates) {
      const style    = window.getComputedStyle(el);
      const opacity  = parseFloat(style.opacity);
      const zIndex   = parseFloat(style.zIndex) || 0;
      const rect     = el.getBoundingClientRect();
      const coverage = coveragePercent(rect);

      // Invisible high-z-index element covering large area
      if (opacity < 0.05 && zIndex > 100 && coverage > 30) {
        suspicious.push({ tag: el.tagName, coverage: Math.round(coverage), zIndex });
      }
    }

    return {
      hasInvisibleOverlay: suspicious.length > 0,
      invisibleOverlays:   suspicious,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [12] — Page Title vs Domain Mismatch
  // ═══════════════════════════════════════════════════════════════════════════

  function checkTitleMismatch() {
    const title    = document.title.toLowerCase().trim();
    const hostname = pageHostname();

    if (!title || title.length < 3) {
      return { hasTitleMismatch: false, missingTitle: true };
    }

    // Check if title implies a brand that's not in the domain
    for (const brand of KNOWN_BRANDS) {
      if (title.includes(brand) && !hostname.includes(brand)) {
        return {
          hasTitleMismatch: true,
          titleBrand:       brand,
          pageTitle:        document.title,
          hostname,
        };
      }
    }

    return { hasTitleMismatch: false };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [13] — Credential Field Outside <form>
  // ═══════════════════════════════════════════════════════════════════════════

  function checkCredentialOutsideForm() {
    const passwords = document.querySelectorAll('input[type="password"]');
    const orphaned  = [];

    for (const pw of passwords) {
      if (!pw.closest('form')) {
        orphaned.push(pw.name || pw.id || 'unknown');
      }
    }

    return {
      hasOrphanedCredential: orphaned.length > 0,
      orphanedFields:        orphaned,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [14] — Passwords in GET Parameters
  // ═══════════════════════════════════════════════════════════════════════════

  function checkGetPassword() {
    const params = new URLSearchParams(window.location.search);
    const sensitiveKeys = ['password', 'pass', 'pw', 'pwd', 'token', 'secret', 'auth'];
    const found = sensitiveKeys.filter(k => params.has(k));

    return {
      hasPasswordInGet: found.length > 0,
      exposedParams:    found,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CHECK [15] — Obfuscated Inline Scripts
  // ═══════════════════════════════════════════════════════════════════════════

  function checkObfuscatedScripts() {
    const scripts  = document.querySelectorAll('script:not([src])');
    const findings = [];

    for (const script of scripts) {
      const code = script.textContent || '';
      if (code.length < 50) continue;

      const hasEval    = /\beval\s*\(/.test(code);
      const hasAtob    = /\batob\s*\(/.test(code);
      const hasLongHex = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/i.test(code);
      const hasLongB64 = /[A-Za-z0-9+/]{60,}={0,2}/.test(code);

      if (hasEval || hasAtob || hasLongHex) {
        findings.push({
          hasEval, hasAtob, hasLongHex, hasLongB64,
          snippet: code.substring(0, 60) + '…',
        });
      }
    }

    return {
      hasObfuscatedScripts: findings.length > 0,
      obfuscatedCount:      findings.length,
      obfuscatedScripts:    findings,
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // RISK SCORE CALCULATOR
  // Computes a riskBoost (0-60) from DOM findings to add to URL score
  // ═══════════════════════════════════════════════════════════════════════════

  function computeDomRiskBoost(checks) {
    let boost = 0;
    const flags = [];

    if (checks.password.hasPasswordField && checks.formAction.hasCrossOriginAction) {
      boost += 35;
      flags.push({
        id: 'cross_origin_form',
        label: 'Password Sent to Foreign Domain',
        detail: `Login form submits credentials to ${checks.formAction.firstCrossOriginDest} — not the site you're on.`,
      });
    }

    if (checks.password.hasPasswordField && checks.brand.hasBrandMismatch) {
      boost += 30;
      flags.push({
        id: 'brand_login',
        label: `Fake ${checks.brand.primaryMismatch ? checks.brand.primaryMismatch[0].toUpperCase() + checks.brand.primaryMismatch.slice(1) : 'Brand'} Login Page`,
        detail: `Page displays ${checks.brand.mismatchedBrands.join(', ')} branding but domain is ${pageBaseDomain()}.`,
      });
    }

    if (checks.hidden.hasHiddenFields) {
      boost += 18;
      flags.push({
        id: 'hidden_fields',
        label: 'Hidden Data-Harvesting Fields',
        detail: `${checks.hidden.hiddenFieldCount} hidden input field(s) with sensitive names detected — may be silently collecting data.`,
      });
    }

    if (checks.iframe.hasIframeOverlay) {
      boost += 25;
      flags.push({
        id: 'iframe_overlay',
        label: 'Iframe Overlay Detected',
        detail: 'A full-page iframe is overlaying the content — a classic clickjacking / overlay phishing technique.',
      });
    }

    if (checks.autofill.autofillDisabled && checks.password.hasPasswordField) {
      boost += 12;
      flags.push({
        id: 'autofill_off',
        label: 'Password Autofill Blocked',
        detail: "Password managers are blocked from filling credentials — phishing pages do this to prevent autofill detection.",
      });
    }

    if (checks.fakeHttps.hasFakeHttps) {
      boost += 20;
      flags.push({
        id: 'fake_https',
        label: 'Fake HTTPS Security Indicators',
        detail: 'Page displays padlock or "secure" imagery on an unencrypted HTTP connection.',
      });
    }

    if (checks.antiInspect.hasAntiInspection) {
      boost += 10;
      const reasons = [];
      if (checks.antiInspect.blocksContextMenu) reasons.push('right-click blocked');
      if (checks.antiInspect.blocksCopy)        reasons.push('copy blocked');
      if (checks.antiInspect.hasDevtoolsDetect) reasons.push('DevTools detection');
      flags.push({
        id: 'anti_inspect',
        label: 'Anti-Inspection Techniques',
        detail: `Page is blocking: ${reasons.join(', ')}. Phishing pages do this to prevent users from inspecting links.`,
      });
    }

    if (checks.metaRefresh.metaRefreshSuspicious) {
      boost += 15;
      flags.push({
        id: 'meta_refresh',
        label: 'Suspicious Auto-Redirect',
        detail: `Page will auto-redirect ${checks.metaRefresh.metaRefreshCrossOrigin ? 'to a different domain' : 'immediately'} via meta-refresh.`,
      });
    }

    if (checks.obfuscated.hasObfuscatedScripts) {
      boost += 15;
      flags.push({
        id: 'obfuscated_js',
        label: 'Obfuscated JavaScript Detected',
        detail: `${checks.obfuscated.obfuscatedCount} inline script(s) use eval(), atob(), or hex encoding to hide malicious code.`,
      });
    }

    if (checks.titleMismatch.hasTitleMismatch) {
      boost += 10;
      flags.push({
        id: 'title_mismatch',
        label: `Page Title Claims to be ${checks.titleMismatch.titleBrand}`,
        detail: `"${checks.titleMismatch.pageTitle}" — but domain is ${pageHostname()}.`,
      });
    }

    if (checks.orphaned.hasOrphanedCredential) {
      boost += 15;
      flags.push({
        id: 'orphan_pw',
        label: 'Password Field Outside Form',
        detail: 'A password field exists outside any <form> element — credentials may be captured by JavaScript.',
      });
    }

    if (checks.getPassword.hasPasswordInGet) {
      boost += 20;
      flags.push({
        id: 'get_password',
        label: 'Credentials Exposed in URL',
        detail: `Sensitive parameters (${checks.getPassword.exposedParams.join(', ')}) are visible in the URL — anyone can see them.`,
      });
    }

    if (checks.externalScripts.hasSuspiciousScripts) {
      boost += 8;
      flags.push({
        id: 'susp_script',
        label: 'External Scripts from Suspicious Domains',
        detail: `Scripts loaded from: ${checks.externalScripts.suspiciousScripts.map(s => s.src).join(', ')}.`,
      });
    }

    return { boost: Math.min(boost, 60), flags };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN DOM SCAN — runs all checks and reports to service worker
  // ═══════════════════════════════════════════════════════════════════════════

  async function runDomScan() {
    const checks = {
      password:      checkPasswordFields(),
      formAction:    checkFormActions(),
      hidden:        checkHiddenFields(),
      iframe:        checkIframeOverlay(),
      autofill:      checkAutofill(),
      brand:         checkBrandMismatch(),
      fakeHttps:     checkFakeHttps(),
      externalScripts: checkExternalScripts(),
      antiInspect:   checkAntiInspection(),
      metaRefresh:   checkMetaRefresh(),
      invisibleOverlay: checkInvisibleOverlays(),
      titleMismatch: checkTitleMismatch(),
      orphaned:      checkCredentialOutsideForm(),
      getPassword:   checkGetPassword(),
      obfuscated:    checkObfuscatedScripts(),
    };

    const { boost, flags } = computeDomRiskBoost(checks);

    const domResult = {
      // Flattened booleans (used by popup DOM panel)
      hasPasswordField:     checks.password.hasPasswordField,
      passwordCount:        checks.password.passwordCount,
      hasCrossOriginAction: checks.formAction.hasCrossOriginAction,
      firstCrossOriginDest: checks.formAction.firstCrossOriginDest,
      hasHiddenFields:      checks.hidden.hasHiddenFields,
      hiddenFieldCount:     checks.hidden.hiddenFieldCount,
      hasIframeOverlay:     checks.iframe.hasIframeOverlay,
      autofillDisabled:     checks.autofill.autofillDisabled,
      hasBrandMismatch:     checks.brand.hasBrandMismatch,
      detectedBrands:       checks.brand.detectedBrands,
      mismatchedBrands:     checks.brand.mismatchedBrands,
      hasFakeHttps:         checks.fakeHttps.hasFakeHttps,
      hasObfuscatedScripts: checks.obfuscated.hasObfuscatedScripts,
      hasAntiInspection:    checks.antiInspect.hasAntiInspection,
      hasMetaRefresh:       checks.metaRefresh.metaRefreshSuspicious,
      hasTitleMismatch:     checks.titleMismatch.hasTitleMismatch,
      hasOrphanedCredential:checks.orphaned.hasOrphanedCredential,
      hasPasswordInGet:     checks.getPassword.hasPasswordInGet,
      hasInvisibleOverlay:  checks.invisibleOverlay.hasInvisibleOverlay,
      hasSuspiciousScripts: checks.externalScripts.hasSuspiciousScripts,
      hasHttps:             window.location.protocol === 'https:',

      // Risk contribution
      riskBoost: boost,
      flags,

      // Raw check results for debugging
      raw: checks,
    };

    return domResult;
  }

  function triggerOverlay(data) {
    if (typeof window.__pshieldInjectOverlay === 'function') {
      window.__pshieldInjectOverlay(data);
    } else {
      console.error('[PhishShield] Overlay script not loaded in context');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HANDLE INCOMING SCAN RESULT FROM BACKGROUND
  // ═══════════════════════════════════════════════════════════════════════════

  function handleScanResult(result) {
    if (!result) return;

    // Always run DOM scan when we receive a result
    runDomScan().then(domFlags => {
      // Send DOM flags back to service worker to merge into score
      chrome.runtime.sendMessage({ type: 'DOM_FLAGS', payload: domFlags })
        .catch(() => {});

      // Trigger overlay for high-risk pages (score ≥ 61 after DOM boost)
      const totalScore = Math.min((result.score || 0) + domFlags.riskBoost, 100);
      if (totalScore >= 61) {
        triggerOverlay({
          ...result,
          score:    totalScore,
          domFlags,
        });
      }
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MESSAGE LISTENER
  // ═══════════════════════════════════════════════════════════════════════════

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message.type === 'SCAN_RESULT') {
      handleScanResult(message.payload);
      sendResponse({ ok: true });
    }

    if (message.type === 'REQUEST_DOM_SCAN') {
      runDomScan().then(domFlags => sendResponse({ domFlags }));
      return true; // async
    }

    return true;
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // MUTATION OBSERVER — watch for dynamically injected forms (SPA support)
  // ═══════════════════════════════════════════════════════════════════════════

  let scanDebounceTimer = null;

  const observer = new MutationObserver((mutations) => {
    // Check if any mutation added a form or password field
    const relevant = mutations.some(m =>
      [...m.addedNodes].some(node => {
        if (node.nodeType !== Node.ELEMENT_NODE) return false;
        return node.matches?.('form, input[type="password"]') ||
               node.querySelector?.('form, input[type="password"]');
      })
    );

    if (relevant) {
      clearTimeout(scanDebounceTimer);
      scanDebounceTimer = setTimeout(() => {
        runDomScan().then(domFlags => {
          chrome.runtime.sendMessage({ type: 'DOM_FLAGS', payload: domFlags })
            .catch(() => {});
        });
      }, 800);
    }
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree:   true,
  });

  // ═══════════════════════════════════════════════════════════════════════════
  // BOOT — run initial scan after a brief settle delay
  // ═══════════════════════════════════════════════════════════════════════════

  setTimeout(() => {
    runDomScan().then(domFlags => {
      // Send DOM flags to service worker for merging
      chrome.runtime.sendMessage({ type: 'DOM_FLAGS', payload: domFlags })
        .catch(() => {});

      // Independently trigger overlay if DOM alone finds high risk
      // (handles file:// URLs and pages where URL scan is low/absent)
      if (domFlags.riskBoost >= 40) {
        triggerOverlay({
          url:         window.location.href,
          score:       domFlags.riskBoost,
          probability: domFlags.riskBoost / 100,
          level:       { key: domFlags.riskBoost >= 61 ? 'DANGEROUS' : 'SUSPICIOUS', label: domFlags.riskBoost >= 61 ? 'Dangerous' : 'Suspicious' },
          flags:       domFlags.flags || [],
          method:      'dom-only',
          domFlags,
        });
      }
    });
  }, 1200);

  console.log('[AI Phishing Shield] DOM scanner active ✓', {
    hostname: window.location.hostname,
    protocol: window.location.protocol,
  });

})();
