/**
 * AI Phishing Shield — Warning Overlay (Phase 5)
 * ═══════════════════════════════════════════════════════════════════════════
 * Injected into the page when score ≥ 61 (DANGEROUS or CRITICAL).
 * Builds a full-screen blocking overlay with:
 *  - Animated risk score gauge
 *  - Level badge with live pulsing dot
 *  - Full flags breakdown (URL + DOM combined)
 *  - ML probability bar
 *  - "Go Back to Safety" / "Proceed Anyway" buttons
 *  - 15-second countdown auto-back for CRITICAL sites
 *  - All styles namespaced with pshield- prefix
 * ═══════════════════════════════════════════════════════════════════════════
 */

(function () {
  'use strict';

  // ── Guard: only inject once ──────────────────────────────────────────────
  if (document.getElementById('pshield-overlay')) return;

  // ── State ────────────────────────────────────────────────────────────────
  let _countdownTimer  = null;
  let _countdownValue  = 15;
  let _proceedUnlocked = false;

  // ═══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  function esc(str) {
    return String(str || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;')
      .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function getLevelInfo(score) {
    if (score <= 60) return { key: 'suspicious', label: 'Suspicious',  color: '#f59e0b', stroke: '#f59e0b' };
    if (score <= 85) return { key: 'dangerous',  label: 'Dangerous',   color: '#f97316', stroke: '#f97316' };
    return                 { key: 'critical',    label: 'Critical',    color: '#ef4444', stroke: '#ef4444' };
  }

  function truncateHost(url, max = 50) {
    try { return new URL(url).hostname; }
    catch { return String(url).substring(0, max); }
  }

  // Circumference of gauge circle (r=36): 2π × 36 ≈ 226
  const GAUGE_C = 226;

  // ═══════════════════════════════════════════════════════════════════════════
  // CSS INJECTION
  // ═══════════════════════════════════════════════════════════════════════════

  function injectStyles() {
    if (document.getElementById('pshield-styles')) return;
    const link = document.createElement('link');
    link.id   = 'pshield-styles';
    link.rel  = 'stylesheet';
    link.href = chrome.runtime.getURL('content/overlay.css');
    document.head.appendChild(link);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TEMPLATE
  // ═══════════════════════════════════════════════════════════════════════════

  function buildHTML(data) {
    const { score, probability, flags = [], domFlags = null, method, url } = data;
    const level    = getLevelInfo(score);
    const host     = truncateHost(url);
    const isCrit   = level.key === 'critical';
    const confidence = ((probability ?? (score / 100)) * 100).toFixed(1);
    const allFlags   = buildAllFlags(flags, domFlags);

    return `
      <div class="pshield-card ${isCrit ? 'pshield-critical' : ''}" role="dialog" aria-modal="true"
           aria-label="Phishing Warning" aria-live="assertive">

        <!-- ── Header ─────────────────────────────────────────────────── -->
        <div class="pshield-header">
          <div class="pshield-header-top">
            <div class="pshield-icon-wrap">
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/>
                <line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
            </div>
            <div class="pshield-header-text">
              <div class="pshield-warning-label">
                <span class="pshield-warning-dot"></span>
                AI Phishing Shield · Threat Detected
              </div>
              <h1 class="pshield-title">
                ${isCrit ? '⚠ Dangerous Site Blocked' : '⚠ Suspicious Site Detected'}
              </h1>
              <p class="pshield-subtitle">
                <strong>${esc(host)}</strong> has been flagged as a potential phishing site.
                Your credentials and personal data may be at risk.
              </p>
            </div>
          </div>
        </div>

        <!-- ── Score row ──────────────────────────────────────────────── -->
        <div class="pshield-score-row">
          <div class="pshield-gauge" aria-label="Risk score ${score} out of 100">
            <svg class="pshield-gauge-svg" viewBox="0 0 88 88">
              <circle class="pshield-gauge-bg"   cx="44" cy="44" r="36"/>
              <circle class="pshield-gauge-fill" cx="44" cy="44" r="36"
                id="pshield-gauge-arc"
                stroke="${esc(level.stroke)}"
                stroke-dasharray="${GAUGE_C}"
                stroke-dashoffset="${GAUGE_C}"/>
            </svg>
            <div class="pshield-gauge-content">
              <span class="pshield-score-num" style="color:${esc(level.color)}">${score}</span>
              <span class="pshield-score-lbl">/ 100</span>
            </div>
          </div>

          <div class="pshield-score-meta">
            <div class="pshield-level-badge pshield-lvl-${level.key}" style="display: flex; flex-direction: column; align-items: flex-start; gap: 2px; border-radius: 8px; padding: 6px 12px; height: auto;">
              <div style="display: flex; align-items: center; gap: 6px;">
                <span class="pshield-level-dot"></span>
                <strong>${esc(level.label)} Risk</strong>
              </div>
              <div style="font-size: 10px; opacity: 0.9; margin-left: 13px;">Confidence: ${confidence}%</div>
            </div>
            <div class="pshield-score-detail">
              <span>${allFlags.length}</span> suspicious signal${allFlags.length !== 1 ? 's' : ''} detected
              · AI confidence: <span>${confidence}%</span>
              ${allFlags.length > 0 ? `
              <div class="pshield-top-reasons">
                <strong>Reasons:</strong>
                ${allFlags.slice(0, 4).map(f => `• ${esc(f.label)}`).join(' ')}
              </div>
              ` : ''}
              <div class="pshield-prob-bar-wrap">
                <div class="pshield-prob-bar-track">
                  <div class="pshield-prob-bar-fill" id="pshield-prob-bar" style="width:0%"></div>
                </div>
                <span class="pshield-prob-label">${confidence}%</span>
              </div>
            </div>
          </div>
        </div>

        <!-- ── Flags list ─────────────────────────────────────────────── -->
        ${allFlags.length > 0 ? `
        <div class="pshield-flags-section">
          <div class="pshield-section-title">
            Why is this site flagged?
            <span class="pshield-flags-count">${allFlags.length} issue${allFlags.length !== 1 ? 's' : ''}</span>
          </div>
          <ul class="pshield-flags-list" role="list">
            ${allFlags.slice(0, 8).map(f => `
              <li class="pshield-flag-item">
                <div class="pshield-flag-icon" aria-hidden="true">
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                    <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                    <line x1="12" y1="9" x2="12" y2="13"/>
                    <line x1="12" y1="17" x2="12.01" y2="17"/>
                  </svg>
                </div>
                <div class="pshield-flag-body">
                  <div class="pshield-flag-label">${esc(f.label)}</div>
                  <div class="pshield-flag-detail">${esc(f.detail)}</div>
                </div>
              </li>
            `).join('')}
          </ul>
        </div>
        ` : ''}

        <!-- ── Safety tip ─────────────────────────────────────────────── -->
        <div class="pshield-tip">
          <span class="pshield-tip-icon">💡</span>
          <div class="pshield-tip-text">
            <strong>What should you do?</strong> Do not enter any passwords, payment details,
            or personal information on this page. If you arrived here from an email link,
            go directly to the official website by typing its address in a new tab.
          </div>
        </div>

        <!-- ── Countdown (critical only) ─────────────────────────────── -->
        ${isCrit ? `
        <div class="pshield-countdown" id="pshield-countdown">
          Automatically returning to safety in <em id="pshield-timer">15</em>s…
          <br><small>Click "Proceed Anyway" to override (not recommended)</small>
        </div>
        ` : ''}

        <!-- ── Action buttons ─────────────────────────────────────────── -->
        <div class="pshield-actions">
          <button class="pshield-btn pshield-btn-back" id="pshield-btn-back" autofocus>
            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
              <polyline points="15 18 9 12 15 6"/>
            </svg>
            Go Back to Safety
          </button>
          <button class="pshield-btn pshield-btn-proceed" id="pshield-btn-proceed"
            ${isCrit ? 'disabled title="Unlocks in 5 seconds"' : ''}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="12" cy="12" r="10"/>
              <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
            </svg>
            Proceed Anyway (not recommended)
          </button>
        </div>

        <!-- ── Footer ────────────────────────────────────────────────── -->
        <div class="pshield-footer">
          <div class="pshield-footer-brand">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 2L3 7V12C3 16.55 6.84 20.74 12 22C17.16 20.74 21 16.55 21 12V7L12 2Z"/>
            </svg>
            AI Phishing Shield · 100% private, no data sent
          </div>
          <span class="pshield-method-tag">
            ${method === 'neural' ? '🧠 Neural' : method === 'weighted' ? '⚖ ML' : '📋 Rule-based'}
          </span>
        </div>

      </div>
    `;
  }

  // ── Merge URL flags + DOM flags into a single deduplicated list ────────
  function buildAllFlags(urlFlags = [], domFlags = null) {
    const seen = new Set();
    const all  = [];

    for (const f of urlFlags) {
      if (!seen.has(f.id)) { seen.add(f.id); all.push(f); }
    }
    if (domFlags?.flags) {
      for (const f of domFlags.flags) {
        if (!seen.has(f.id)) { seen.add(f.id); all.push(f); }
      }
    }
    return all;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // ANIMATIONS (triggered after DOM insertion)
  // ═══════════════════════════════════════════════════════════════════════════

  function animateGauge(score) {
    requestAnimationFrame(() => {
      setTimeout(() => {
        const arc = document.getElementById('pshield-gauge-arc');
        if (arc) {
          const offset = GAUGE_C - (score / 100) * GAUGE_C;
          arc.style.strokeDashoffset = offset;
        }
        const bar = document.getElementById('pshield-prob-bar');
        if (bar) {
          bar.style.width = `${score}%`;
        }
      }, 150);
    });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // COUNTDOWN (critical sites auto-navigate back)
  // ═══════════════════════════════════════════════════════════════════════════

  function startCountdown(isCritical) {
    if (!isCritical) {
      // For dangerous (non-critical): just unlock proceed button after 5s
      setTimeout(() => unlockProceed(), 5000);
      return;
    }

    _countdownValue = 15;
    const timerEl   = document.getElementById('pshield-timer');

    // Unlock proceed button after 5 seconds even on critical
    setTimeout(() => unlockProceed(), 5000);

    _countdownTimer = setInterval(() => {
      _countdownValue--;
      if (timerEl) timerEl.textContent = _countdownValue;

      if (_countdownValue <= 0) {
        clearInterval(_countdownTimer);
        navigateBack();
      }
    }, 1000);
  }

  function unlockProceed() {
    _proceedUnlocked = true;
    const btn = document.getElementById('pshield-btn-proceed');
    if (btn) {
      btn.disabled = false;
      btn.title    = '';
      btn.style.opacity = '1';
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // NAVIGATION
  // ═══════════════════════════════════════════════════════════════════════════

  function navigateBack() {
    clearInterval(_countdownTimer);
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.replace('about:blank');
    }
  }

  function removeOverlay() {
    clearInterval(_countdownTimer);
    const el = document.getElementById('pshield-overlay');
    if (el) {
      el.style.animation = 'pshield-fade-out 0.25s ease forwards';
      el.addEventListener('animationend', () => el.remove(), { once: true });
      // Fallback
      setTimeout(() => el.remove(), 400);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN INJECT FUNCTION
  // ═══════════════════════════════════════════════════════════════════════════

  function injectOverlay(data) {
    // Don't inject if already dismissed this session
    const sessionKey = `pshield_dismissed_${data.url}`;
    if (sessionStorage.getItem(sessionKey)) return;

    // Inject styles first
    injectStyles();

    // Build the overlay
    const overlay = document.createElement('div');
    overlay.id            = 'pshield-overlay';
    overlay.role          = 'alertdialog';
    overlay.setAttribute('aria-modal', 'true');
    overlay.innerHTML     = buildHTML(data);

    // Freeze page scroll
    document.documentElement.style.overflow = 'hidden';

    // Append to body (or documentElement as fallback)
    ;(document.body || document.documentElement).appendChild(overlay);

    // ── Animate gauge after mount ─────────────────────────────────────
    animateGauge(data.score);

    // ── Start countdown (critical) / unlock timer (dangerous) ─────────
    const isCrit = data.score > 85;
    startCountdown(isCrit);

    // ── Button: Go Back ───────────────────────────────────────────────
    document.getElementById('pshield-btn-back')?.addEventListener('click', () => {
      navigateBack();
    });

    // ── Button: Proceed Anyway ────────────────────────────────────────
    document.getElementById('pshield-btn-proceed')?.addEventListener('click', () => {
      if (!_proceedUnlocked) return;

      // Mark as dismissed for this session so it doesn't re-inject
      try { sessionStorage.setItem(sessionKey, '1'); } catch {}

      // Restore scroll
      document.documentElement.style.overflow = '';

      // Remove overlay with fade-out
      removeOverlay();

      // Notify service worker that user proceeded despite warning
      chrome.runtime.sendMessage({
        type: 'USER_PROCEEDED',
        url:  data.url,
        score: data.score,
      }).catch(() => {});
    });

    // ── Keyboard: Escape = Go Back ────────────────────────────────────
    function onKeyDown(e) {
      if (e.key === 'Escape') {
        document.removeEventListener('keydown', onKeyDown);
        navigateBack();
      }
    }
    document.addEventListener('keydown', onKeyDown);

    // Focus the back button for accessibility
    setTimeout(() => {
      document.getElementById('pshield-btn-back')?.focus();
    }, 500);

    console.log('[AI Phishing Shield] Overlay injected, score:', data.score);
  }

  // ── Expose to content.js parent scope ────────────────────────────────────
  window.__pshieldInjectOverlay = injectOverlay;
  window.__pshieldRemoveOverlay = removeOverlay;

})();
