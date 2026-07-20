/**
 * AI Phishing Shield — Background Service Worker (Phase 3 — Complete)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Responsibilities:
 *  ✓ TF.js model loading & management (MV3-compatible)
 *  ✓ URL scanning pipeline: extractFeatures → runInference → store → notify
 *  ✓ Full scan history persistence (last 500 scans)
 *  ✓ Allow-list & block-list management
 *  ✓ Extension settings (threshold, notifications, etc.)
 *  ✓ DOM flag merging from content scripts
 *  ✓ Badge + icon state management
 *  ✓ Complete messaging API for popup & content scripts
 *  ✓ Alarm-based periodic cleanup
 *  ✓ Install/update lifecycle
 * ═══════════════════════════════════════════════════════════════════════════
 */

import { extractFeatures }          from '../ml/features.js';
import { runInference, getTopFeatures, isTrustedHost } from '../ml/model.js';

// ═══════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

const RISK_LEVELS = {
  SAFE:       { key: 'SAFE',       label: 'Safe',       score: [0,  30],  color: '#22c55e', emoji: '✅' },
  SUSPICIOUS: { key: 'SUSPICIOUS', label: 'Suspicious', score: [31, 60],  color: '#f59e0b', emoji: '⚠️' },
  DANGEROUS:  { key: 'DANGEROUS',  label: 'Dangerous',  score: [61, 85],  color: '#f97316', emoji: '🚨' },
  CRITICAL:   { key: 'CRITICAL',   label: 'Critical',   score: [86, 100], color: '#ef4444', emoji: '☠️' },
};

const SKIPPED_SCHEMES = new Set([
  'chrome:', 'chrome-extension:', 'edge:', 'about:', 'data:',
  'javascript:', 'blob:', 'devtools:',
]);

const STORAGE_KEYS = {
  HISTORY:   'phish_history',
  SETTINGS:  'phish_settings',
  ALLOWLIST: 'phish_allowlist',
  BLOCKLIST: 'phish_blocklist',
  STATS:     'phish_stats',
};

const MAX_HISTORY  = 500;

// ─── Default settings ─────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = {
  enabled:              true,
  notificationsEnabled: true,
  warningThreshold:     31,    // score above which to show warning
  blockThreshold:       86,    // score above which to block (inject overlay)
  scanMode:             'all', // 'all' | 'login-only' | 'http-only'
  showBadge:            true,
  autoScanDelay:        500,   // ms after navigation before scan
};

// ═══════════════════════════════════════════════════════════════════════════════
// IN-MEMORY STATE
// ═══════════════════════════════════════════════════════════════════════════════

const scanCache    = new Map();   // tabId → full scanResult
const scanPending  = new Set();   // tabIds currently being scanned
let   settings     = { ...DEFAULT_SETTINGS };
let   allowList    = new Set();
let   blockList    = new Set();

// ═══════════════════════════════════════════════════════════════════════════════
// STORAGE HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

async function loadSettings() {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.SETTINGS);
  settings = { ...DEFAULT_SETTINGS, ...(stored[STORAGE_KEYS.SETTINGS] || {}) };
}

async function saveSettings(updates) {
  settings = { ...settings, ...updates };
  await chrome.storage.local.set({ [STORAGE_KEYS.SETTINGS]: settings });
}

async function loadLists() {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.ALLOWLIST, STORAGE_KEYS.BLOCKLIST,
  ]);
  allowList = new Set(stored[STORAGE_KEYS.ALLOWLIST] || []);
  blockList = new Set(stored[STORAGE_KEYS.BLOCKLIST] || []);
}

async function saveAllowList() {
  await chrome.storage.local.set({ [STORAGE_KEYS.ALLOWLIST]: [...allowList] });
}

async function saveBlockList() {
  await chrome.storage.local.set({ [STORAGE_KEYS.BLOCKLIST]: [...blockList] });
}

/**
 * Append a scan result to persistent history (capped at MAX_HISTORY)
 */
async function appendHistory(result) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
  const history = stored[STORAGE_KEYS.HISTORY] || [];

  // Build slim history entry
  const entry = {
    url:       result.url,
    hostname:  (() => { try { return new URL(result.url).hostname || 'local-file'; } catch { return 'unknown'; } })(),
    score:     result.score,
    level:     result.level.key,
    method:    result.method,
    flagCount: (result.flags || []).length,
    timestamp: result.timestamp,
  };

  history.unshift(entry);
  if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;

  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: history });
}

/**
 * Update aggregate stats
 */
async function updateStats(result) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.STATS);
  const stats = stored[STORAGE_KEYS.STATS] || {
    totalScanned: 0, totalPhishing: 0, totalSafe: 0,
    totalSuspicious: 0, totalDangerous: 0, totalCritical: 0,
    lastScan: null,
  };

  stats.totalScanned++;
  stats.lastScan = result.timestamp;

  const key = result.level.key.toLowerCase();
  if (key === 'safe')       stats.totalSafe++;
  else if (key === 'suspicious') stats.totalSuspicious++;
  else if (key === 'dangerous')  stats.totalDangerous++;
  else if (key === 'critical')   stats.totalCritical++;

  if (result.score > 30) stats.totalPhishing++;

  await chrome.storage.local.set({ [STORAGE_KEYS.STATS]: stats });
}

// ═══════════════════════════════════════════════════════════════════════════════
// BADGE & ICON MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

function getRiskLevel(score) {
  for (const level of Object.values(RISK_LEVELS)) {
    if (score >= level.score[0] && score <= level.score[1]) return level;
  }
  return RISK_LEVELS.SAFE;
}

async function updateBadge(tabId, score) {
  if (!settings.showBadge) {
    chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
    return;
  }

  const level = getRiskLevel(score);
  const text  = score > 30 ? String(Math.round(score)) : '';

  try {
    await chrome.action.setBadgeText({ text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: level.color, tabId });
    await chrome.action.setTitle({
      title: `AI Phishing Shield${text ? ` — ${level.label} (${score})` : ' — Safe'}`,
      tabId,
    });
  } catch (err) {
    // Suppress "No tab with id" errors from closed/invalid tabs
  }
}

function clearBadge(tabId) {
  chrome.action.setBadgeText({ text: '', tabId }).catch(() => {});
}

// ═══════════════════════════════════════════════════════════════════════════════
// NOTIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

function sendNotification(result) {
  if (!settings.notificationsEnabled) return;
  if (result.score < settings.warningThreshold) return;

  const level = result.level;
  try {
    chrome.notifications.create(`phish_${result.tabId}_${Date.now()}`, {
      type:    'basic',
      iconUrl: '../icons/icon48.png',
      title:   `${level.emoji} ${level.label} Site Detected`,
      message: `Risk Score: ${result.score}/100\n${result.flags?.[0]?.label || 'Suspicious activity detected'}`,
      priority: result.score >= 86 ? 2 : 1,
    });
  } catch (_) {
    // Notifications permission may not be granted
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// URL SCREENING (skip, allow-list, block-list)
// ═══════════════════════════════════════════════════════════════════════════════

function shouldSkipUrl(url) {
  try {
    const { protocol, hostname } = new URL(url);
    if (SKIPPED_SCHEMES.has(protocol)) return true;
    if (!hostname)                      return true;
    return false;
  } catch {
    return true;
  }
}

function extractHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return url.toLowerCase(); }
}

function isAllowListed(url) {
  const host = extractHostname(url);
  return allowList.has(host);
}

function isBlockListed(url) {
  const host = extractHostname(url);
  return blockList.has(host);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CORE SCAN PIPELINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Full scan pipeline for a URL.
 * Flow: skip-check → allow/block-list → feature extract → ML inference → store → notify
 */
async function scanUrl(url, tabId) {
  if (!settings.enabled)    return null;
  if (shouldSkipUrl(url))   return null;
  if (scanPending.has(tabId)) return scanCache.get(tabId) || null;

  scanPending.add(tabId);

  try {
    // ── Allow-list fast path ────────────────────────────────────────────────
    if (isAllowListed(url)) {
      const safeResult = makeSafeResult(url, tabId, 'allow-listed');
      cacheAndBroadcast(tabId, safeResult);
      return safeResult;
    }

    // ── Block-list fast path ────────────────────────────────────────────────
    if (isBlockListed(url)) {
      const blockResult = makeBlockedResult(url, tabId);
      cacheAndBroadcast(tabId, blockResult);
      await appendHistory(blockResult);
      await updateStats(blockResult);
      return blockResult;
    }

    // ── ML Inference ────────────────────────────────────────────────────────
    const startT = performance.now();
    const inference = await runInference(url);
    const duration = parseFloat((performance.now() - startT).toFixed(1));

    const result = {
      url,
      tabId,
      score:       inference.score,
      probability: parseFloat(inference.probability.toFixed(4)),
      duration,
      level:       getRiskLevel(inference.score),
      flags:       inference.flags || [],
      topFeatures: getTopFeatures(inference.features.vector, 5),
      method:      inference.method,
      domFlags:    null,     // populated later by content script
      timestamp:   Date.now(),
      // Slim feature metadata (no raw Float32Array)
      meta: {
        hostname:         inference.features.hostname,
        tld:              inference.features.tld,
        hasHttps:         inference.features.hasHttps,
        subdomainDepth:   inference.features.subdomainDepth,
        urlLength:        inference.features.urlLength,
        entropy:          parseFloat(inference.features.entropy.toFixed(3)),
        isTyposquat:      inference.features.isTyposquat,
        typosquatTarget:  inference.features.typosquatTarget,
        brandKeyword:     inference.features.brandKeyword,
      },
    };

    // ── Persist & Broadcast ─────────────────────────────────────────────────
    scanCache.set(tabId, result);
    await chrome.storage.local.set({ [`scan_${tabId}`]: result });
    await updateBadge(tabId, result.score);

    if (result.score > 30) {
      await appendHistory(result);
      await updateStats(result);
      sendNotification(result);
    }

    broadcastToTab(tabId, result);
    return result;

  } catch (err) {
    console.error('[PhishShield] Scan error:', url, err);
    return null;
  } finally {
    scanPending.delete(tabId);
  }
}

function makeSafeResult(url, tabId, reason = 'safe') {
  return {
    url, tabId,
    score: 0, probability: 0,
    level: RISK_LEVELS.SAFE,
    flags: [], topFeatures: [], method: reason,
    domFlags: null, timestamp: Date.now(),
    duration: 0.1,
    meta: { hostname: extractHostname(url), hasHttps: url.startsWith('https') },
  };
}

function makeBlockedResult(url, tabId) {
  return {
    url, tabId,
    score: 100, probability: 1,
    level: RISK_LEVELS.CRITICAL,
    flags: [{ id: 'blocklist', label: 'Manually Blocked', detail: 'This domain is on your personal block list.' }],
    topFeatures: [], method: 'block-listed',
    domFlags: null, timestamp: Date.now(),
    duration: 0.1,
    meta: { hostname: extractHostname(url), hasHttps: false },
  };
}

function cacheAndBroadcast(tabId, result) {
  scanCache.set(tabId, result);
  chrome.storage.local.set({ [`scan_${tabId}`]: result });
  updateBadge(tabId, result.score);
  broadcastToTab(tabId, result);
}

/**
 * Broadcast scan result to the content script of the given tab
 */
function broadcastToTab(tabId, result) {
  chrome.tabs.sendMessage(tabId, { type: 'SCAN_RESULT', payload: result })
    .catch(() => {}); // Content script may not be ready — silently ignore
}

// ═══════════════════════════════════════════════════════════════════════════════
// DOM FLAG MERGING (from content script Phase 4)
// ═══════════════════════════════════════════════════════════════════════════════

async function mergeDomFlags(tabId, domFlags) {
  let result = scanCache.get(tabId);

  if (!result) {
    let tab = null;
    try {
      tab = await chrome.tabs.get(tabId);
    } catch (e) {}
    const url = tab?.url || 'unknown';
    result = {
      url,
      tabId,
      score: 0,
      probability: 0,
      level: RISK_LEVELS.SAFE,
      flags: [],
      topFeatures: [],
      method: 'dom-only',
      domFlags: null,
      timestamp: Date.now(),
      meta: {
        hostname: (() => { try { return new URL(url).hostname || 'local-file'; } catch { return 'unknown'; } })(),
        hasHttps: url.startsWith('https'),
      },
    };
  }

  // Merge DOM flags
  result.domFlags = domFlags;

  const hostname = result.meta?.hostname || extractHostname(result.url) || '';
  const isTrusted = isTrustedHost(hostname);

  // Add DOM flags to the flags array if not a trusted host
  if (!isTrusted) {
    const domFlagItems = domFlags.flags || [];
    result.flags = [...(result.flags || []), ...domFlagItems];
  } else {
    result.flags = [];
  }

  // Boost score based on DOM risk (only if not a trusted host)
  const boost = isTrusted ? 0 : (domFlags.riskBoost || 0);
  let boosted = Math.min(result.score + boost, 100);
  
  if (isTrusted && boosted > 10) {
    boosted = Math.min(boosted, 10);
  }

  result.score  = boosted;
  result.level  = getRiskLevel(boosted);

  // Persist & update
  scanCache.set(tabId, result);
  await chrome.storage.local.set({ [`scan_${tabId}`]: result });
  await updateBadge(tabId, boosted);

  // If score is high enough (and not a trusted site), record in history and send notification
  if (boosted > 30 && !isTrusted) {
    await appendHistory(result);
    await updateStats(result);
    sendNotification(result);
  }

  // Broadcast updated result to content script so it can trigger overlay
  broadcastToTab(tabId, result);
}

// ═══════════════════════════════════════════════════════════════════════════════
// HISTORY & STATS MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════════

async function getHistory(limit = 50) {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
  const history = stored[STORAGE_KEYS.HISTORY] || [];
  return history.slice(0, limit);
}

async function clearHistory() {
  await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: [] });
  await chrome.storage.local.set({
    [STORAGE_KEYS.STATS]: {
      totalScanned: 0,
      totalPhishing: 0,
      totalSafe: 0,
      totalSuspicious: 0,
      totalDangerous: 0,
      totalCritical: 0,
      lastScan: null
    }
  });
  scanCache.clear();
  const allData = await chrome.storage.local.get(null);
  const scanKeys = Object.keys(allData).filter(k => k.startsWith('scan_'));
  if (scanKeys.length > 0) {
    await chrome.storage.local.remove(scanKeys);
  }
}

async function getStats() {
  const stored = await chrome.storage.local.get(STORAGE_KEYS.STATS);
  return stored[STORAGE_KEYS.STATS] || {};
}

// ═══════════════════════════════════════════════════════════════════════════════
// MESSAGE HANDLER — Public API
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Full messaging API used by popup, content scripts, and dashboard.
 *
 * Message types:
 *  GET_SCAN_RESULT  → { tabId }           → { result }
 *  RESCAN           → { tabId }           → { result }
 *  DOM_FLAGS        → { payload }         → { ok }
 *  GET_SETTINGS     → {}                  → { settings }
 *  SAVE_SETTINGS    → { updates }         → { settings }
 *  GET_HISTORY      → { limit? }          → { history }
 *  CLEAR_HISTORY    → {}                  → { ok }
 *  GET_STATS        → {}                  → { stats }
 *  ADD_ALLOWLIST    → { hostname }        → { ok }
 *  REMOVE_ALLOWLIST → { hostname }        → { ok }
 *  ADD_BLOCKLIST    → { hostname }        → { ok }
 *  REMOVE_BLOCKLIST → { hostname }        → { ok }
 *  GET_LISTS        → {}                  → { allowList, blockList }
 *  GET_STATUS       → {}                  → { enabled, version, ... }
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch(err => {
    console.error('[PhishShield] Message error:', err);
    sendResponse({ error: err.message });
  });
  return true; // keep channel open for async response
});

async function handleMessage(message, sender) {
  const { type, payload } = message;

  switch (type) {

    case 'GET_SCAN_RESULT': {
      const tabId = message.tabId;
      const result = scanCache.get(tabId) || null;
      if (!result) {
        // Try loading from storage (after service worker restart)
        const stored = await chrome.storage.local.get(`scan_${tabId}`);
        return { result: stored[`scan_${tabId}`] || null };
      }
      return { result };
    }

    case 'RESCAN': {
      const tabId = message.tabId;
      scanCache.delete(tabId);
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const result = await scanUrl(tab.url, tabId);
        return { result };
      }
      return { result: null };
    }

    case 'DOM_FLAGS': {
      const tabId = sender.tab?.id;
      if (tabId) await mergeDomFlags(tabId, message.payload);
      return { ok: true };
    }

    case 'GET_SETTINGS':
      return { settings };

    case 'SAVE_SETTINGS':
      await saveSettings(message.updates || {});
      return { settings };

    case 'GET_HISTORY':
      return { history: await getHistory(message.limit || 50) };

    case 'CLEAR_HISTORY':
      await clearHistory();
      return { ok: true };

    case 'GET_STATS':
      return { stats: await getStats() };

    case 'ADD_ALLOWLIST': {
      const host = message.hostname?.toLowerCase();
      if (host) { allowList.add(host); await saveAllowList(); }
      return { ok: true, allowList: [...allowList] };
    }

    case 'REMOVE_ALLOWLIST': {
      allowList.delete(message.hostname?.toLowerCase());
      await saveAllowList();
      return { ok: true, allowList: [...allowList] };
    }

    case 'ADD_BLOCKLIST': {
      const host = message.hostname?.toLowerCase();
      if (host) { blockList.add(host); await saveBlockList(); }
      return { ok: true, blockList: [...blockList] };
    }

    case 'REMOVE_BLOCKLIST': {
      blockList.delete(message.hostname?.toLowerCase());
      await saveBlockList();
      return { ok: true, blockList: [...blockList] };
    }

    case 'GET_LISTS':
      return { allowList: [...allowList], blockList: [...blockList] };

    case 'GET_STATUS':
      return {
        enabled:    settings.enabled,
        version:    chrome.runtime.getManifest().version,
        scanCount:  scanCache.size,
        timestamp:  Date.now(),
      };

    case 'USER_PROCEEDED': {
      // User dismissed the warning and proceeded to a dangerous site
      console.warn('[PhishShield] User proceeded despite warning:', message.url, 'score:', message.score);
      // Log to history with a special flag
      const stored = await chrome.storage.local.get(STORAGE_KEYS.HISTORY);
      const history = stored[STORAGE_KEYS.HISTORY] || [];
      history.unshift({
        url:       message.url,
        hostname:  new URL(message.url).hostname,
        score:     message.score,
        level:     'CRITICAL',
        method:    'user-bypassed',
        flagCount: 0,
        timestamp: Date.now(),
        bypassed:  true,
      });
      if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
      await chrome.storage.local.set({ [STORAGE_KEYS.HISTORY]: history });
      return { ok: true };
    }

    default:
      console.warn('[PhishShield] Unknown message type:', type);
      return { error: 'unknown_message_type' };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// NAVIGATION EVENT LISTENERS
// ═══════════════════════════════════════════════════════════════════════════════

// Tab updated (Navigation state changes)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  // Clear old result immediately when navigation starts
  if (changeInfo.status === 'loading' && changeInfo.url) {
    scanCache.delete(tabId);
    clearBadge(tabId);
  }

  // Main frame navigation completed → trigger scan
  if (changeInfo.status === 'complete' && tab.url) {
    if (!settings.enabled) return;

    // Small delay to let page settle (configurable)
    await new Promise(r => setTimeout(r, settings.autoScanDelay));
    await scanUrl(tab.url, tabId);
  }
});

// Tab switched → restore badge from cache
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const cached = scanCache.get(tabId);
  if (cached) {
    await updateBadge(tabId, cached.score);
  } else {
    // Try to restore from storage (after service worker restart)
    const stored = await chrome.storage.local.get(`scan_${tabId}`);
    const result = stored[`scan_${tabId}`];
    if (result) {
      scanCache.set(tabId, result);
      await updateBadge(tabId, result.score);
    } else {
      clearBadge(tabId);
    }
  }
});

// Tab closed → cleanup
chrome.tabs.onRemoved.addListener((tabId) => {
  scanCache.delete(tabId);
  chrome.storage.local.remove(`scan_${tabId}`);
});

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  // Initialize settings on fresh install
  await loadSettings();
  await loadLists();

  if (reason === 'install') {
    console.log('[PhishShield] Extension installed — initializing storage...');
    // Seed empty stats
    await chrome.storage.local.set({
      [STORAGE_KEYS.STATS]:    { totalScanned: 0, totalPhishing: 0, totalSafe: 0, totalSuspicious: 0, totalDangerous: 0, totalCritical: 0 },
      [STORAGE_KEYS.HISTORY]:  [],
      [STORAGE_KEYS.SETTINGS]: DEFAULT_SETTINGS,
      [STORAGE_KEYS.ALLOWLIST]: [],
      [STORAGE_KEYS.BLOCKLIST]: [],
    });

    // Open welcome tab
    chrome.tabs.create({ url: chrome.runtime.getURL('dashboard/index.html') });
  }

  if (reason === 'update') {
    console.log('[PhishShield] Extension updated to v' + chrome.runtime.getManifest().version);
  }
});

// ─── Startup: load persisted settings & lists ─────────────────────────────────
chrome.runtime.onStartup.addListener(async () => {
  await loadSettings();
  await loadLists();
  console.log('[PhishShield] Service worker started, settings loaded ✓');
});

// ─── Boot (immediate, on service worker activation) ───────────────────────────
(async () => {
  await loadSettings();
  await loadLists();
  console.log('[AI Phishing Shield] Service worker initialized ✓', {
    enabled: settings.enabled,
    allowList: allowList.size,
    blockList: blockList.size,
  });
})();
