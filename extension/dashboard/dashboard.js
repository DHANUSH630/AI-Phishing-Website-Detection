/**
 * AI Phishing Shield — Dashboard Script (Phase 7)
 * ═══════════════════════════════════════════════════════════════════════════
 * Reads from chrome.storage via background messaging API.
 * Renders: stat cards, doughnut chart, line activity chart,
 *          heatmap, history table, ranked threats, allow/block lists.
 * ═══════════════════════════════════════════════════════════════════════════
 */

'use strict';

// ══════════════════════════════════════════════════════════
// UTILITIES
// ══════════════════════════════════════════════════════════

const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function msg(type, extra = {}) {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type, ...extra }, res => {
      if (chrome.runtime.lastError) { resolve(null); return; }
      resolve(res);
    });
  });
}

function timeAgo(ts) {
  const d = Date.now() - ts;
  if (d < 60000)    return 'just now';
  if (d < 3600000)  return `${Math.floor(d/60000)}m ago`;
  if (d < 86400000) return `${Math.floor(d/3600000)}h ago`;
  return new Date(ts).toLocaleDateString();
}

function scoreClass(s) {
  if (s <= 30) return 'safe';
  if (s <= 60) return 'suspicious';
  if (s <= 85) return 'dangerous';
  return 'critical';
}

function scoreLevelText(s) {
  if (s <= 30) return 'Safe';
  if (s <= 60) return 'Suspicious';
  if (s <= 85) return 'Dangerous';
  return 'Critical';
}

function truncateUrl(url, max = 45) {
  try {
    const u = new URL(url);
    const s = u.hostname + u.pathname;
    return s.length > max ? s.slice(0, max) + '…' : s;
  } catch { return String(url).slice(0, max); }
}

function animateCount(el, target, duration = 800) {
  const start = performance.now();
  const from  = parseInt(el.textContent) || 0;
  const step  = ts => {
    const p = Math.min((ts - start) / duration, 1);
    const ease = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (target - from) * ease);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

let _toastT = null;
function toast(message, ms = 2500) {
  const el = $('toast');
  el.textContent = message;
  el.classList.remove('hidden');
  clearTimeout(_toastT);
  _toastT = setTimeout(() => el.classList.add('hidden'), ms);
}

// ══════════════════════════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════════════════════════

const SECTIONS = ['overview','history','threats','lists'];
let activeSection = 'overview';

function navigate(section) {
  activeSection = section;
  SECTIONS.forEach(s => {
    $(`section-${s}`)?.classList.toggle('active', s === section);
    document.querySelector(`[data-section="${s}"]`)?.classList.toggle('active', s === section);
  });
  const titles = { overview:'Overview', history:'Scan History', threats:'Threats', lists:'Allow / Block Lists' };
  const subs   = { overview:'Real-time threat analytics', history:'All recorded scans', threats:'Phishing analysis', lists:'Domain management' };
  $('page-title').textContent    = titles[section];
  $('page-subtitle').textContent = subs[section];
  if (section === 'overview') renderOverview();
  if (section === 'history')  renderHistory();
  if (section === 'threats')  renderThreats();
  if (section === 'lists')    renderLists();
}

document.querySelectorAll('.nav-item, .view-all').forEach(el => {
  el.addEventListener('click', e => {
    e.preventDefault();
    const s = el.dataset.section;
    if (s) navigate(s);
  });
});

// ══════════════════════════════════════════════════════════
// DATA LAYER — load everything from service worker
// ══════════════════════════════════════════════════════════

let _stats   = {};
let _history = [];
let _lists   = { allowList: [], blockList: [] };

async function loadAll() {
  const [statsRes, histRes, listsRes] = await Promise.all([
    msg('GET_STATS'),
    msg('GET_HISTORY', { limit: 500 }),
    msg('GET_LISTS'),
  ]);

  _stats   = statsRes?.stats   || {};
  _history = histRes?.history  || [];
  _lists   = listsRes || { allowList: [], blockList: [] };

  // Update version + status
  const manifest = chrome.runtime.getManifest();
  $('sidebar-version').textContent = `v${manifest.version}`;

  // Last scan info
  if (_history.length > 0) {
    const last = _history[0];
    $('last-scan-info').textContent = `Last scan: ${timeAgo(last.timestamp)}`;
  } else {
    $('last-scan-info').textContent = 'No scans yet';
  }
}

// ══════════════════════════════════════════════════════════
// OVERVIEW
// ══════════════════════════════════════════════════════════

let _donutChart = null;
let _lineChart  = null;
let _safePhishChart = null;
let _confidenceHistChart = null;
let _lineRange  = 7;

async function renderOverview() {
  // Stat cards
  animateCount($('sv-total'),    _stats.totalScanned   || 0);
  animateCount($('sv-threats'),  _stats.totalPhishing  || 0);
  animateCount($('sv-safe'),     _stats.totalSafe      || 0);
  animateCount($('sv-critical'), (_stats.totalDangerous||0) + (_stats.totalCritical||0));

  // Daily, weekly, monthly scans count
  const now = Date.now();
  const dailyCount   = _history.filter(h => h.timestamp >= now - 86400000).length;
  const weeklyCount  = _history.filter(h => h.timestamp >= now - 7 * 86400000).length;
  const monthlyCount = _history.filter(h => h.timestamp >= now - 30 * 86400000).length;

  animateCount($('sv-daily'),   dailyCount);
  animateCount($('sv-weekly'),  weeklyCount);
  animateCount($('sv-monthly'), monthlyCount);

  // Threat rate on stat cards
  const total = _stats.totalScanned || 1;
  const threatPct = Math.round(((_stats.totalPhishing||0) / total) * 100);
  $('st-threats').textContent = `${threatPct}%`;

  // Donut chart
  renderDonut();

  // Line chart
  renderLine(_lineRange);

  // Recent threats table (top 8 dangerous+critical)
  const threats = _history.filter(h => h.score > 60).slice(0, 8);
  const tbody = $('recent-threats-body');
  if (!threats.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="table-empty">No threats detected yet 🎉</td></tr>';
  } else {
    tbody.innerHTML = threats.map(h => `
      <tr>
        <td><strong>${esc(h.hostname || new URL(h.url).hostname)}</strong></td>
        <td><span class="score-pill ${scoreClass(h.score)}">${h.score}</span></td>
        <td><span class="level-badge lvl-${scoreClass(h.score)}">${scoreLevelText(h.score)}</span></td>
        <td>${h.flagCount || 0} flags</td>
        <td>${timeAgo(h.timestamp)}</td>
      </tr>
    `).join('');
  }
}

function renderDonut() {
  const safe    = _stats.totalSafe        || 0;
  const sus     = _stats.totalSuspicious  || 0;
  const dan     = _stats.totalDangerous   || 0;
  const crit    = _stats.totalCritical    || 0;
  const total   = safe + sus + dan + crit || 1;

  const pct = Math.round(((sus + dan + crit) / total) * 100);
  $('donut-pct').textContent = `${pct}%`;
  $('breakdown-total').textContent = `${safe + sus + dan + crit} total`;

  const data   = [safe, sus, dan, crit];
  const colors = ['#22c55e','#f59e0b','#f97316','#ef4444'];
  const labels = ['Safe','Suspicious','Dangerous','Critical'];

  if (_donutChart) _donutChart.destroy();

  const ctx = $('chart-donut').getContext('2d');
  _donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: colors.map(c => c + '22'),
        borderColor: colors,
        borderWidth: 2,
        hoverBackgroundColor: colors.map(c => c + '44'),
        hoverBorderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      cutout: '72%',
      plugins: { legend: { display: false }, tooltip: {
        backgroundColor: '#161b22',
        borderColor: 'rgba(255,255,255,.1)',
        borderWidth: 1,
        titleColor: '#e6edf3',
        bodyColor: '#8b949e',
        callbacks: {
          label: ctx => ` ${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed/total*100)}%)`
        }
      }},
      animation: { animateRotate: true, duration: 900 },
    },
  });

  // Legend
  $('donut-legend').innerHTML = labels.map((l,i) => `
    <div class="legend-item">
      <span class="legend-dot" style="background:${colors[i]}"></span>
      <span class="legend-label">${l}</span>
      <span class="legend-val">${data[i]}</span>
      <span class="legend-pct">${Math.round(data[i]/total*100)}%</span>
    </div>
  `).join('');
}

function renderLine(days) {
  _lineRange = days;
  const now   = Date.now();
  const start = now - days * 86400000;

  // Build daily buckets
  const buckets = {};
  for (let i = 0; i < days; i++) {
    const d = new Date(now - i * 86400000);
    buckets[d.toLocaleDateString('en-US',{month:'short',day:'numeric'})] = { safe:0, threat:0 };
  }

  _history.filter(h => h.timestamp >= start).forEach(h => {
    const key = new Date(h.timestamp).toLocaleDateString('en-US',{month:'short',day:'numeric'});
    if (buckets[key]) {
      if (h.score > 60) buckets[key].threat++;
      else              buckets[key].safe++;
    }
  });

  const labelArr  = Object.keys(buckets).reverse();
  const safeArr   = labelArr.map(k => buckets[k].safe);
  const threatArr = labelArr.map(k => buckets[k].threat);

  if (_lineChart) _lineChart.destroy();

  const ctx = $('chart-line').getContext('2d');

  // Gradient fills
  const gSafe   = ctx.createLinearGradient(0,0,0,200);
  gSafe.addColorStop(0,  'rgba(34,197,94,.3)');
  gSafe.addColorStop(1,  'rgba(34,197,94,0)');

  const gThreat = ctx.createLinearGradient(0,0,0,200);
  gThreat.addColorStop(0,  'rgba(239,68,68,.3)');
  gThreat.addColorStop(1,  'rgba(239,68,68,0)');

  _lineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: labelArr,
      datasets: [
        {
          label: 'Safe',
          data: safeArr,
          borderColor: '#22c55e',
          backgroundColor: gSafe,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#22c55e',
          tension: 0.4, fill: true,
        },
        {
          label: 'Threats',
          data: threatArr,
          borderColor: '#ef4444',
          backgroundColor: gThreat,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: '#ef4444',
          tension: 0.4, fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode:'index', intersect:false },
      plugins: {
        legend: {
          labels: { color:'#8b949e', font:{ size:11 }, boxWidth:10, pointStyle:'circle', usePointStyle:true }
        },
        tooltip: {
          backgroundColor:'#161b22', borderColor:'rgba(255,255,255,.1)', borderWidth:1,
          titleColor:'#e6edf3', bodyColor:'#8b949e',
        },
      },
      scales: {
        x: { grid:{ color:'rgba(255,255,255,.04)' }, ticks:{ color:'#484f58', font:{size:10} } },
        y: { grid:{ color:'rgba(255,255,255,.04)' }, ticks:{ color:'#484f58', font:{size:10} }, beginAtZero:true, precision:0 },
      },
      animation: { duration: 700 },
    },
  });
}

// Line range filter buttons
document.querySelectorAll('.filter-btn[data-range]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn[data-range]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderLine(parseInt(btn.dataset.range));
  });
});

// ══════════════════════════════════════════════════════════
// HISTORY TABLE (with search + filter + pagination)
// ══════════════════════════════════════════════════════════

let _histFilter  = 'all';
let _histSearch  = '';
let _histPage    = 0;
const PAGE_SIZE  = 20;

function getFilteredHistory() {
  return _history.filter(h => {
    const cls    = scoreClass(h.score);
    const search = _histSearch.toLowerCase();
    const host   = (h.hostname || '').toLowerCase();
    const url    = (h.url || '').toLowerCase();
    const matchFilter = _histFilter === 'all' || cls === _histFilter;
    const matchSearch = !search || host.includes(search) || url.includes(search);
    return matchFilter && matchSearch;
  });
}

function renderHistory() {
  const filtered = getFilteredHistory();
  const total    = filtered.length;
  const pages    = Math.ceil(total / PAGE_SIZE);
  _histPage      = Math.min(_histPage, Math.max(pages - 1, 0));
  const slice    = filtered.slice(_histPage * PAGE_SIZE, (_histPage + 1) * PAGE_SIZE);

  $('history-count').textContent = `${total} entr${total !== 1 ? 'ies' : 'y'}`;

  const tbody = $('history-body');
  if (!slice.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="table-empty">No scans match your filter</td></tr>';
  } else {
    tbody.innerHTML = slice.map(h => `
      <tr>
        <td><strong>${esc(h.hostname || '')}</strong></td>
        <td class="url-cell" title="${esc(h.url)}">${esc(truncateUrl(h.url))}</td>
        <td><span class="score-pill ${scoreClass(h.score)}">${h.score}</span></td>
        <td><span class="level-badge lvl-${scoreClass(h.score)}">${scoreLevelText(h.score)}</span></td>
        <td><span class="method-tag">${h.method || 'rule'}</span></td>
        <td>${h.flagCount || 0}</td>
        <td>${timeAgo(h.timestamp)}</td>
      </tr>
    `).join('');
  }

  // Pagination
  const pagEl = $('pagination');
  if (pages <= 1) { pagEl.innerHTML = ''; return; }

  pagEl.innerHTML = Array.from({length: pages}, (_,i) => `
    <button class="page-btn ${i === _histPage ? 'active' : ''}" data-page="${i}">${i+1}</button>
  `).join('');

  pagEl.querySelectorAll('.page-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      _histPage = parseInt(btn.dataset.page);
      renderHistory();
    });
  });
}

// Search
$('history-search')?.addEventListener('input', e => {
  _histSearch = e.target.value;
  _histPage   = 0;
  renderHistory();
});

// Filter chips
document.querySelectorAll('.chip[data-filter]').forEach(chip => {
  chip.addEventListener('click', () => {
    document.querySelectorAll('.chip[data-filter]').forEach(c => c.classList.remove('active'));
    chip.classList.add('active');
    _histFilter = chip.dataset.filter;
    _histPage   = 0;
    renderHistory();
  });
});

// ══════════════════════════════════════════════════════════
// THREATS — heatmap + ranked list + method bars + bypassed
// ══════════════════════════════════════════════════════════

function renderThreats() {
  renderSafePhishPie();
  renderConfidenceHist();
  renderHeatmap();
  renderRankedThreats();
  renderTopFeatures();
  renderMethodBars();
  renderBypassed();
}

function renderSafePhishPie() {
  let safeCount = 0;
  let phishCount = 0;

  _history.forEach(h => {
    if (h.score > 60) phishCount++;
    else              safeCount++;
  });

  const total = safeCount + phishCount || 1;

  if (_safePhishChart) _safePhishChart.destroy();

  const ctx = $('chart-safe-phish').getContext('2d');
  _safePhishChart = new Chart(ctx, {
    type: 'pie',
    data: {
      labels: ['Safe Sites', 'Phishing Threats'],
      datasets: [{
        data: [safeCount, phishCount],
        backgroundColor: ['rgba(34,197,94,.15)', 'rgba(239,68,68,.15)'],
        borderColor: ['#22c55e', '#ef4444'],
        borderWidth: 2,
        hoverBackgroundColor: ['rgba(34,197,94,.3)', 'rgba(239,68,68,.3)'],
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 10, padding: 8 }
        },
        tooltip: {
          backgroundColor: '#161b22',
          borderColor: 'rgba(255,255,255,.1)',
          borderWidth: 1,
          titleColor: '#e6edf3',
          bodyColor: '#8b949e',
          callbacks: {
            label: ctx => ` ${ctx.label}: ${ctx.parsed} (${Math.round(ctx.parsed/total*100)}%)`
          }
        }
      }
    }
  });
}

function renderConfidenceHist() {
  // 10 buckets of 10% each (0-10%, 10-20%... 90-100%)
  const BUCKETS = 10;
  const counts = Array(BUCKETS).fill(0);

  _history.forEach(h => {
    // probability is 0-1. Fallback to score/100.
    const prob = h.probability ?? (h.score / 100);
    const b = Math.min(Math.floor(prob * 10), BUCKETS - 1);
    counts[b]++;
  });

  const labels = ['0-10%', '10-20%', '20-30%', '30-40%', '40-50%', '50-60%', '60-70%', '70-80%', '80-90%', '90-100%'];

  if (_confidenceHistChart) _confidenceHistChart.destroy();

  const ctx = $('chart-confidence-hist').getContext('2d');
  _confidenceHistChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Scans count',
        data: counts,
        backgroundColor: 'rgba(59,130,246,.15)',
        borderColor: '#3b82f6',
        borderWidth: 1.5,
        hoverBackgroundColor: 'rgba(59,130,246,.35)',
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#161b22',
          borderColor: 'rgba(255,255,255,.1)',
          borderWidth: 1,
          titleColor: '#e6edf3',
          bodyColor: '#8b949e',
        }
      },
      scales: {
        x: { grid: { color: 'rgba(255,255,255,.03)' }, ticks: { color: '#484f58', font: { size: 9 } } },
        y: { grid: { color: 'rgba(255,255,255,.03)' }, ticks: { color: '#484f58', font: { size: 9 } }, beginAtZero: true, precision: 0 }
      }
    }
  });
}

function renderTopFeatures() {
  const counts = {};

  _history.forEach(h => {
    if (h.flags && Array.isArray(h.flags)) {
      h.flags.forEach(f => {
        const label = f.label || 'Unknown heuristic';
        counts[label] = (counts[label] || 0) + 1;
      });
    }
  });

  const sorted = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const el = $('top-features-list');
  if (!sorted.length) {
    el.innerHTML = '<li class="ranked-empty">No heuristics triggered yet 🎉</li>';
    return;
  }

  el.innerHTML = sorted.map(([label, count], i) => `
    <li class="ranked-item">
      <span class="ranked-num">${i + 1}</span>
      <span class="ranked-host" title="${esc(label)}">${esc(label)}</span>
      <span class="ranked-count" style="background: rgba(249,115,22,.12); color: #f97316; font-size: 9.5px; padding: 2px 8px; border-radius: 999px; font-weight: 700;">${count}×</span>
    </li>
  `).join('');
}

function renderHeatmap() {
  // 20 buckets of 5 score points each (0-4, 5-9, … 95-100)
  const BUCKETS = 20;
  const counts  = Array(BUCKETS).fill(0);

  _history.forEach(h => {
    const b = Math.min(Math.floor(h.score / 5), BUCKETS - 1);
    counts[b]++;
  });

  const max = Math.max(...counts, 1);

  $('heatmap-grid').innerHTML = counts.map((c, i) => {
    const intensity = c / max;
    const score     = i * 5;
    const color     = score <= 30 ? `rgba(34,197,94,${intensity})` :
                      score <= 60 ? `rgba(245,158,11,${intensity})` :
                      score <= 85 ? `rgba(249,115,22,${intensity})` :
                                    `rgba(239,68,68,${intensity})`;
    return `<div class="heatmap-cell" style="background:${color}" title="Score ${score}–${score+4}: ${c} scans"></div>`;
  }).join('');
}

function renderRankedThreats() {
  // Group by hostname, count occurrences at score > 60
  const freq = {};
  _history.filter(h => h.score > 60).forEach(h => {
    const host = h.hostname || '';
    if (!freq[host]) freq[host] = { count: 0, maxScore: 0 };
    freq[host].count++;
    freq[host].maxScore = Math.max(freq[host].maxScore, h.score);
  });

  const ranked = Object.entries(freq)
    .sort((a,b) => b[1].count - a[1].count)
    .slice(0, 8);

  const el = $('top-threats-list');
  if (!ranked.length) {
    el.innerHTML = '<li class="ranked-empty">No threats detected yet 🎉</li>';
    return;
  }

  el.innerHTML = ranked.map(([host, d], i) => `
    <li class="ranked-item">
      <span class="ranked-num">${i + 1}</span>
      <span class="ranked-host">${esc(host)}</span>
      <span class="level-badge lvl-${scoreClass(d.maxScore)}">${d.maxScore}</span>
      <span class="ranked-count">${d.count}×</span>
    </li>
  `).join('');
}

function renderMethodBars() {
  const counts = { neural:0, weighted:0, rules:0, listed:0 };
  _history.forEach(h => {
    const m = h.method || 'rules';
    if (counts[m] !== undefined) counts[m]++;
    else counts.rules++;
  });

  const total  = Object.values(counts).reduce((a,b) => a+b, 1);
  const labels = { neural:'🧠 Neural Network', weighted:'⚖ Weighted ML', rules:'📋 Rule-Based', listed:'📋 Allow/Block List' };

  $('method-bars').innerHTML = Object.entries(counts).map(([key, count]) => `
    <div class="method-row">
      <div class="method-label-row">
        <span class="method-name">${labels[key]}</span>
        <span class="method-count">${count} scans</span>
      </div>
      <div class="method-track">
        <div class="method-fill ${key}" style="width:0%" data-target="${Math.round(count/total*100)}%"></div>
      </div>
    </div>
  `).join('');

  // Animate bars after paint
  setTimeout(() => {
    document.querySelectorAll('.method-fill').forEach(el => {
      el.style.width = el.dataset.target;
    });
  }, 100);
}

function renderBypassed() {
  const bypassed = _history.filter(h => h.bypassed);
  const tbody    = $('bypassed-body');
  if (!bypassed.length) {
    tbody.innerHTML = '<tr><td colspan="3" class="table-empty">No bypassed warnings — great!</td></tr>';
    return;
  }
  tbody.innerHTML = bypassed.slice(0, 20).map(h => `
    <tr>
      <td><strong>${esc(h.hostname || '')}</strong></td>
      <td><span class="score-pill critical">${h.score}</span></td>
      <td>${timeAgo(h.timestamp)}</td>
    </tr>
  `).join('');
}

// ══════════════════════════════════════════════════════════
// LISTS
// ══════════════════════════════════════════════════════════

function renderLists() {
  const { allowList = [], blockList = [] } = _lists;

  $('allow-count').textContent = `${allowList.length} domain${allowList.length !== 1 ? 's' : ''}`;
  $('block-count').textContent = `${blockList.length} domain${blockList.length !== 1 ? 's' : ''}`;

  renderDomainList('d-allow-list', allowList, 'allow');
  renderDomainList('d-block-list', blockList, 'block');
}

function renderDomainList(elId, domains, type) {
  const el = $(elId);
  if (!el) return;
  if (!domains.length) {
    el.innerHTML = '<li class="list-empty">No domains added yet</li>';
    return;
  }
  el.innerHTML = domains.map(d => `
    <li class="domain-row" data-domain="${esc(d)}" data-type="${type}">
      <span>${esc(d)}</span>
      <button class="domain-remove" aria-label="Remove ${esc(d)}">×</button>
    </li>
  `).join('');

  el.querySelectorAll('.domain-remove').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domain  = btn.closest('.domain-row').dataset.domain;
      const msgType = type === 'allow' ? 'REMOVE_ALLOWLIST' : 'REMOVE_BLOCKLIST';
      await msg(msgType, { hostname: domain });
      toast(`Removed: ${domain}`);
      await loadAll();
      renderLists();
    });
  });
}

async function addDomain(type, inputId) {
  const input  = $(inputId);
  const domain = (input?.value || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0];
  if (!domain) { toast('⚠ Enter a valid domain name'); return; }

  const msgType = type === 'allow' ? 'ADD_ALLOWLIST' : 'ADD_BLOCKLIST';
  await msg(msgType, { hostname: domain });
  toast(`✓ Added to ${type === 'allow' ? 'trusted' : 'blocked'}: ${domain}`);
  input.value = '';
  await loadAll();
  renderLists();
}

$('d-btn-add-allow')?.addEventListener('click', () => addDomain('allow', 'd-allow-input'));
$('d-btn-add-block')?.addEventListener('click', () => addDomain('block', 'd-block-input'));
$('d-allow-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addDomain('allow', 'd-allow-input'); });
$('d-block-input')?.addEventListener('keydown', e => { if (e.key === 'Enter') addDomain('block', 'd-block-input'); });

// ══════════════════════════════════════════════════════════
// TOPBAR ACTIONS
// ══════════════════════════════════════════════════════════

$('btn-refresh')?.addEventListener('click', async () => {
  $('btn-refresh').textContent = '⟳ Refreshing…';
  await loadAll();
  navigate(activeSection);
  $('btn-refresh').innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg> Refresh`;
  toast('✓ Data refreshed');
});

$('btn-clear-all')?.addEventListener('click', async () => {
  if (!confirm('Clear all scan history? This cannot be undone.')) return;
  await msg('CLEAR_HISTORY');
  await loadAll();
  navigate(activeSection);
  toast('✓ History cleared');
});

// Sidebar Razorpay Donation click handler
$('sidebar-donate-btn')?.addEventListener('click', () => {
  // TODO: Replace with your actual Razorpay Payment Page/Button URL!
  const razorpayPageUrl = 'https://pages.razorpay.com/pl_yourdonationid';
  chrome.tabs.create({ url: razorpayPageUrl });
});

// ══════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════

async function init() {
  await loadAll();
  navigate('overview');

  // Auto-refresh every 30s
  setInterval(async () => {
    await loadAll();
    if (activeSection === 'overview') renderOverview();
  }, 30000);
}

// Wait for Chart.js to be ready
if (typeof Chart !== 'undefined') {
  init();
} else {
  window.addEventListener('load', init);
}
