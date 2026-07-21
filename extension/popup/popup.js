/**
 * AI Phishing Shield — Popup Script (Phase 6 — Complete)
 * 4-tab UI: Scan · Stats · Lists · Settings
 * Full integration with service worker messaging API.
 */
'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

function $(id) { return document.getElementById(id); }

function esc(str) {
  return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function msg(type, extra = {}) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type, ...extra }, res => {
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(res);
    });
  });
}

function truncateHost(url, max = 40) {
  try   { return new URL(url).hostname; }
  catch { return String(url).slice(0, max); }
}

function timeAgo(ts) {
  const d = Date.now() - ts;
  if (d < 60000)  return 'just now';
  if (d < 3600000) return `${Math.floor(d/60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d/3600000)}h ago`;
  return `${Math.floor(d/86400000)}d ago`;
}

function scoreClass(score) {
  if (score <= 30) return 'safe';
  if (score <= 60) return 'warning';
  if (score <= 85) return 'dangerous';
  return 'critical';
}

function scoreBadgeClass(score) {
  if (score <= 30) return 'safe-badge';
  if (score <= 60) return 'warning-badge';
  if (score <= 85) return 'dangerous-badge';
  return 'critical-badge';
}

function scoreLevelText(score) {
  if (score <= 30) return 'Safe';
  if (score <= 60) return 'Suspicious';
  if (score <= 85) return 'Dangerous';
  return 'Critical';
}

let _toastTimer = null;
function toast(message, duration = 2200) {
  const el = $('toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.add('hidden'), duration);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TAB NAVIGATION
// ═══════════════════════════════════════════════════════════════════════════════

const TABS = ['scan', 'stats', 'lists', 'settings'];
let activeTab = 'scan';

function switchTab(name) {
  activeTab = name;
  TABS.forEach(t => {
    $(`tab-${t}`)?.classList.toggle('active', t === name);
    $(`panel-${t}`)?.classList.toggle('hidden', t !== name);
  });
  if (name === 'stats')    loadStats();
  if (name === 'lists')    loadLists();
  if (name === 'settings') loadSettings();
}

TABS.forEach(t => {
  $(`tab-${t}`)?.addEventListener('click', () => switchTab(t));
});

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN TAB
// ═══════════════════════════════════════════════════════════════════════════════

function showState(name) {
  ['loading','safe','danger','nodata'].forEach(s =>
    $(`state-${s}`)?.classList.add('hidden')
  );
  $(`state-${name}`)?.classList.remove('hidden');
}

function setRing(id, score) {
  const el = $(id);
  if (!el) return;
  const offset = 314 - (score / 100) * 314;
  requestAnimationFrame(() => {
    setTimeout(() => { el.style.strokeDashoffset = offset; }, 80);
  });
}

function renderMetaPills(containerId, meta, method) {
  const el = $(containerId);
  if (!el) return;
  const pills = [];
  if (meta?.hasHttps !== undefined)
    pills.push({ label: meta.hasHttps ? '🔒 HTTPS' : '⚠ No HTTPS', cls: meta.hasHttps ? 'pill-ok' : 'pill-warn' });
  if (meta?.tld)
    pills.push({ label: `.${meta.tld}`, cls: 'pill-info' });
  if (meta?.subdomainDepth > 0)
    pills.push({ label: `${meta.subdomainDepth} subdomain${meta.subdomainDepth > 1 ? 's' : ''}`, cls: meta.subdomainDepth > 2 ? 'pill-warn' : 'pill-info' });
  if (method) {
    let label = '📋 Rules';
    let cls = 'pill-info';
    if (method === 'neural') label = '🧠 Neural';
    else if (method === 'weighted') label = '⚖ Weighted';
    else if (method === 'trusted') { label = '🛡 Trusted'; cls = 'pill-ok'; }
    pills.push({ label, cls });
  }

  el.innerHTML = pills.map(p => `<span class="meta-pill ${p.cls}">${esc(p.label)}</span>`).join('');
}

function renderFlags(flags) {
  if (!flags?.length) return;
  $('flags-panel')?.classList.remove('hidden');
  $('flags-count').textContent = `${flags.length} issue${flags.length !== 1 ? 's' : ''}`;
  $('flags-list').innerHTML = flags.map(f => `
    <li class="flag-item">
      <div class="flag-hdr">
        <div class="flag-ico">
          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
        </div>
        <span class="flag-lbl">${esc(f.label)}</span>
      </div>
      <p class="flag-detail">${esc(f.detail)}</p>
    </li>
  `).join('');
}

function renderDomPanel(domFlags) {
  if (!domFlags) return;
  const boost = domFlags.riskBoost || 0;
  if ($('dom-score-tag')) $('dom-score-tag').textContent = boost > 0 ? `+${boost} pts from DOM` : 'DOM: Clean';

  const checks = [
    { label:'Password Field',   ok:!domFlags.hasPasswordField,     icon:'🔑', crit:true },
    { label:'Form Action Safe', ok:!domFlags.hasCrossOriginAction,  icon:'📋', crit:true },
    { label:'No Hidden Fields', ok:!domFlags.hasHiddenFields,       icon:'👁', crit:false },
    { label:'No Iframe Overlay',ok:!domFlags.hasIframeOverlay,      icon:'📦', crit:true },
    { label:'Autofill OK',      ok:!domFlags.autofillDisabled,      icon:'✍️', crit:false },
    { label:'Brand Match',      ok:!domFlags.hasBrandMismatch,      icon:'🏷', crit:true },
    { label:'HTTPS',            ok: domFlags.hasHttps,              icon:'🔒', crit:false },
    { label:'Clean Scripts',    ok:!domFlags.hasSuspiciousScripts,  icon:'📜', crit:false },
    { label:'No Redirect',      ok:!domFlags.hasMetaRefresh,        icon:'↪', crit:false },
    { label:'No Fake Padlock',  ok:!domFlags.hasFakeHttps,          icon:'🛡', crit:false },
    { label:'Title OK',         ok:!domFlags.hasTitleMismatch,      icon:'🏷', crit:false },
    { label:'Form OK',          ok:!domFlags.hasOrphanedCredential, icon:'📝', crit:false },
    { label:'URL Safe',         ok:!domFlags.hasPasswordInGet,      icon:'🔗', crit:true },
    { label:'Clean JS',         ok:!domFlags.hasObfuscatedScripts,  icon:'⚙', crit:false },
    { label:'Right-click OK',   ok:!domFlags.hasAntiInspection,     icon:'🖱', crit:false },
  ];

  const failCount = checks.filter(c => !c.ok).length;
  if (failCount === 0 && boost === 0) return; // hide if all clear

  $('dom-panel')?.classList.remove('hidden');
  $('dom-checks').innerHTML = checks.map(c => `
    <div class="dom-check ${c.ok ? 'ok' : (c.crit ? 'critical' : 'warn')}">
      <span class="dc-icon">${c.icon}</span>
      <span class="dc-text">${esc(c.label)}</span>
      <span class="dc-status">${c.ok ? '✓' : '✗'}</span>
    </div>
  `).join('');
}

function renderScanResult(result) {
  $('flags-panel')?.classList.add('hidden');
  $('dom-panel')?.classList.add('hidden');
  $('diagnostics-panel')?.classList.add('hidden');
  $('tf-fallback-warning')?.classList.add('hidden');

  if (!result) { showState('nodata'); $('logo-status').textContent = 'No data'; return; }

  const { score, url, flags = [], domFlags, meta = {}, method, probability, duration } = result;
  const cls = scoreClass(score);

  // Update logo
  $('logo-icon').className = `logo-icon ${cls}`;
  $('logo-status').textContent = `Score: ${score}/100`;

  if (score <= 30) {
    showState('safe');
    $('score-num-safe').textContent = score;
    $('url-safe').textContent = truncateHost(url);
    setRing('ring-fill-safe', score);
    renderMetaPills('meta-pills-safe', meta, method);
  } else {
    showState('danger');
    $('score-num-danger').textContent = score;
    $('url-danger').textContent = truncateHost(url);

    const ringWrap = $('danger-ring-wrap');
    if (ringWrap) ringWrap.className = `score-ring-wrap ${cls}`;
    setRing('ring-fill-danger', score);

    const badge = $('danger-badge');
    if (badge) badge.className = `status-badge ${scoreBadgeClass(score)}`;
    const confidenceVal = ((probability ?? (score / 100)) * 100).toFixed(1);
    $('level-text').textContent = `${scoreLevelText(score)} (Confidence: ${confidenceVal}%)`;

    const reasonsEl = $('danger-reasons');
    if (reasonsEl) {
      if (flags.length > 0) {
        reasonsEl.innerHTML = `<strong>Reasons:</strong> ${flags.slice(0, 4).map(f => esc(f.label)).join(' • ')}`;
        reasonsEl.classList.remove('hidden');
      } else {
        reasonsEl.classList.add('hidden');
      }
    }

    renderMetaPills('meta-pills-danger', meta, method);
    renderFlags(flags);
  }

  if (domFlags) renderDomPanel(domFlags);

  // Render Diagnostics
  const confidence = ((probability ?? (score / 100)) * 100).toFixed(1);
  const scanTime = duration !== undefined ? `${duration} ms` : '0.1 ms';
  const modelVer = 'v1.1-ensemble';
  const domChecksCount = domFlags ? 15 : 0;
  const featuresCount = `42 URL + ${domChecksCount} DOM`;

  if ($('diag-confidence')) $('diag-confidence').textContent = `${confidence}%`;
  if ($('diag-duration'))   $('diag-duration').textContent   = scanTime;
  if ($('diag-model-ver'))  $('diag-model-ver').textContent  = modelVer;
  if ($('diag-features'))   $('diag-features').textContent   = featuresCount;

  const barFill = $('confidence-bar-fill');
  if (barFill) {
    barFill.style.width = `${confidence}%`;
    if (score <= 30) {
      barFill.style.background = 'var(--green)';
    } else if (score <= 60) {
      barFill.style.background = 'var(--yellow)';
    } else if (score <= 85) {
      barFill.style.background = 'var(--orange)';
    } else {
      barFill.style.background = 'var(--red)';
    }
  }
  $('diagnostics-panel')?.classList.remove('hidden');

  // If TensorFlow model failed to load, warn the user transparently
  if (method && method !== 'neural' && method !== 'dom-only') {
    $('tf-fallback-warning')?.classList.remove('hidden');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATS TAB
// ═══════════════════════════════════════════════════════════════════════════════

async function loadStats() {
  const [statsRes, histRes] = await Promise.all([
    msg('GET_STATS'),
    msg('GET_HISTORY', { limit: 20 }),
  ]);
  const stats   = statsRes?.stats   || {};
  const history = histRes?.history  || [];

  // Stat cards
  $('sv-total').textContent    = stats.totalScanned  || 0;
  $('sv-phishing').textContent = stats.totalPhishing || 0;
  $('sv-safe').textContent     = stats.totalSafe     || 0;
  $('sv-critical').textContent = (stats.totalDangerous || 0) + (stats.totalCritical || 0);

  // Breakdown bar
  const total = stats.totalScanned || 1;
  const pct   = v => `${Math.round((v/total)*100)}%`;
  const safe  = stats.totalSafe || 0;
  const sus   = stats.totalSuspicious || 0;
  const dan   = stats.totalDangerous  || 0;
  const crit  = stats.totalCritical   || 0;

  setTimeout(() => {
    $('bb-safe').style.width       = pct(safe);
    $('bb-suspicious').style.width = pct(sus);
    $('bb-dangerous').style.width  = pct(dan);
    $('bb-critical').style.width   = pct(crit);
  }, 100);

  // History list
  const histEl = $('history-list');
  if (!history.length) {
    histEl.innerHTML = '<li class="history-empty">No scans recorded yet</li>';
    return;
  }

  histEl.innerHTML = history.slice(0, 20).map(h => `
    <li class="history-item">
      <div class="hi-dot ${(h.level || 'safe').toLowerCase()}"></div>
      <span class="hi-host">${esc(h.hostname || truncateHost(h.url))}</span>
      <span class="hi-score">${h.score}</span>
      <span class="hi-time">${timeAgo(h.timestamp)}</span>
    </li>
  `).join('');
}

$('btn-clear-history')?.addEventListener('click', async () => {
  await msg('CLEAR_HISTORY');
  toast('History cleared ✓');
  loadStats();
});

// ═══════════════════════════════════════════════════════════════════════════════
// LISTS TAB
// ═══════════════════════════════════════════════════════════════════════════════

async function loadLists() {
  const res = await msg('GET_LISTS');
  renderDomainList('allow-list-el', res?.allowList || [], 'allow');
  renderDomainList('block-list-el', res?.blockList || [], 'block');
}

function renderDomainList(elId, domains, type) {
  const el = $(elId);
  if (!el) return;
  if (!domains.length) {
    el.innerHTML = `<li style="font-size:10.5px;color:var(--text-3);padding:6px 10px">No domains added yet</li>`;
    return;
  }
  el.innerHTML = domains.map(d => `
    <li class="domain-item" data-domain="${esc(d)}" data-type="${type}">
      <span>${esc(d)}</span>
      <button class="domain-remove" aria-label="Remove ${esc(d)}">×</button>
    </li>
  `).join('');

  el.querySelectorAll('.domain-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domain = btn.closest('.domain-item').dataset.domain;
      const msgType = type === 'allow' ? 'REMOVE_ALLOWLIST' : 'REMOVE_BLOCKLIST';
      await msg(msgType, { hostname: domain });
      toast(`Removed: ${domain}`);
      loadLists();
    });
  });
}

async function addToList(type, inputId) {
  const input   = $(inputId);
  const domain  = (input?.value || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!domain) { toast('Enter a valid domain'); return; }

  const msgType = type === 'allow' ? 'ADD_ALLOWLIST' : 'ADD_BLOCKLIST';
  await msg(msgType, { hostname: domain });
  toast(`Added to ${type === 'allow' ? 'trusted' : 'blocked'}: ${domain}`);
  input.value = '';
  loadLists();
}

$('btn-add-allow')?.addEventListener('click', () => addToList('allow', 'allow-input'));
$('btn-add-block')?.addEventListener('click', () => addToList('block', 'block-input'));

$('allow-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addToList('allow', 'allow-input'); });
$('block-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addToList('block', 'block-input'); });

// ═══════════════════════════════════════════════════════════════════════════════
// SETTINGS TAB
// ═══════════════════════════════════════════════════════════════════════════════

async function loadSettings() {
  const res      = await msg('GET_SETTINGS');
  const settings = res?.settings || {};

  $('set-enabled').checked       = settings.enabled !== false;
  $('set-notifications').checked = settings.notificationsEnabled !== false;
  $('set-badge').checked         = settings.showBadge !== false;
  $('set-warn-threshold').value  = settings.warningThreshold ?? 31;
  $('set-block-threshold').value = settings.blockThreshold ?? 86;
  $('warn-val').textContent      = settings.warningThreshold ?? 31;
  $('block-val').textContent     = settings.blockThreshold ?? 86;

  updateSliderTrack('set-warn-threshold');
  updateSliderTrack('set-block-threshold');

  const mode = settings.scanMode || 'all';
  const modeEl = document.querySelector(`input[name="scan-mode"][value="${mode}"]`);
  if (modeEl) modeEl.checked = true;
}

function updateSliderTrack(id) {
  const el  = $(id);
  if (!el) return;
  const pct = ((el.value - el.min) / (el.max - el.min)) * 100;
  el.style.setProperty('--val', `${pct}%`);
  el.style.background = `linear-gradient(to right, var(--blue) 0%, var(--blue) ${pct}%, var(--bg-3) ${pct}%)`;
}

async function saveSettingDebounced(updates) {
  await msg('SAVE_SETTINGS', { updates });
}

// Toggle handlers
['set-enabled','set-notifications','set-badge'].forEach(id => {
  $(id)?.addEventListener('change', e => {
    const map = { 'set-enabled':'enabled', 'set-notifications':'notificationsEnabled', 'set-badge':'showBadge' };
    saveSettingDebounced({ [map[id]]: e.target.checked });
    toast(`Setting updated ✓`);
  });
});

// Slider handlers
$('set-warn-threshold')?.addEventListener('input', e => {
  $('warn-val').textContent = e.target.value;
  updateSliderTrack('set-warn-threshold');
  saveSettingDebounced({ warningThreshold: parseInt(e.target.value) });
});

$('set-block-threshold')?.addEventListener('input', e => {
  $('block-val').textContent = e.target.value;
  updateSliderTrack('set-block-threshold');
  saveSettingDebounced({ blockThreshold: parseInt(e.target.value) });
});

// Radio scan mode
document.querySelectorAll('input[name="scan-mode"]').forEach(radio => {
  radio.addEventListener('change', e => {
    saveSettingDebounced({ scanMode: e.target.value });
    toast('Scan mode updated ✓');
  });
});

// Reset
$('btn-reset-settings')?.addEventListener('click', async () => {
  await saveSettingDebounced({
    enabled: true, notificationsEnabled: true, showBadge: true,
    warningThreshold: 31, blockThreshold: 86, scanMode: 'all',
  });
  loadSettings();
  toast('Settings reset to defaults ✓');
});

// Support & Donations (Razorpay)
$('btn-donate')?.addEventListener('click', () => {
  // TODO: Replace with your actual Razorpay Payment Button/Page URL from dashboard!
  // Example: https://pages.razorpay.com/pl_yourdonationid
  const razorpayPageUrl = 'https://pages.razorpay.com/pl_yourdonationid';
  chrome.tabs.create({ url: razorpayPageUrl });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SCAN TAB ACTIONS
// ═══════════════════════════════════════════════════════════════════════════════

let _tabId = null;
let _currentHost = null;

$('btn-rescan')?.addEventListener('click', async () => {
  showState('loading');
  $('flags-panel')?.classList.add('hidden');
  $('dom-panel')?.classList.add('hidden');
  $('logo-status').textContent = 'Rescanning…';

  const res = await msg('RESCAN', { tabId: _tabId });
  renderScanResult(res?.result ?? null);
});

$('btn-allowlist')?.addEventListener('click', async () => {
  if (!_currentHost) { toast('No site to trust'); return; }
  await msg('ADD_ALLOWLIST', { hostname: _currentHost });
  toast(`Trusted: ${_currentHost} ✓`);
  // Re-scan shows it as safe
  setTimeout(async () => {
    const res = await msg('RESCAN', { tabId: _tabId });
    renderScanResult(res?.result ?? null);
  }, 400);
});

$('btn-report')?.addEventListener('click', () => {
  chrome.tabs.create({ url: 'https://www.phishtank.com/add_web_phish.php' });
});

$('btn-dashboard')?.addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/index.html') });
});

$('link-privacy')?.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('privacy.html') });
});

// ═══════════════════════════════════════════════════════════════════════════════
// INIT
// ═══════════════════════════════════════════════════════════════════════════════

async function init() {
  showState('loading');
  $('logo-status').textContent = 'Scanning…';

  // Set version
  const manifest = chrome.runtime.getManifest();
  $('footer-version').textContent = `v${manifest.version}`;

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) { showState('nodata'); return; }

    _tabId = tab.id;
    try { _currentHost = new URL(tab.url).hostname.toLowerCase(); } catch {}

    const res = await msg('GET_SCAN_RESULT', { tabId: tab.id });
    renderScanResult(res?.result ?? null);

    // Trust site button label update
    if (_currentHost) {
      const listsRes = await msg('GET_LISTS');
      const isAllowed = (listsRes?.allowList || []).includes(_currentHost);
      const allowBtn  = $('btn-allowlist');
      if (allowBtn) {
        allowBtn.innerHTML = isAllowed
          ? `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 11l3 3L22 4"/></svg> Trusted ✓`
          : `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M9 11l3 3L22 4"/></svg> Trust Site`;
        if (isAllowed) allowBtn.style.color = 'var(--green)';
      }
    }

  } catch (err) {
    console.error('[Popup]', err);
    showState('nodata');
  }
}

init();
