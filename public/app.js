// ==========================================
// AETHER SCAN - Client Logic System
// ==========================================

// State Variables
let results = [];
let activeFilter = 'all';
let searchQuery = '';
let eventSource = null;
let currentDomain = '';

// DOM Elements
const scanForm = document.getElementById('scan-form');
const domainInput = document.getElementById('domain-input');
const scanBtn = document.getElementById('scan-btn');
const cancelBtn = document.getElementById('cancel-btn');
const statsPanel = document.getElementById('stats-panel');
const progressContainer = document.getElementById('progress-container');
const progressStatus = document.getElementById('progress-status');
const progressPercent = document.getElementById('progress-percent');
const progressBar = document.getElementById('progress-bar');
const sourceBadges = document.getElementById('source-badges');

// Stats Counters
const statTotal = document.getElementById('stat-total');
const statResolved = document.getElementById('stat-resolved');
const statWeb = document.getElementById('stat-web');
const statOffline = document.getElementById('stat-offline');

// Filter & Control Elements
const filterBtns = document.querySelectorAll('.filter-btn');
const countAll = document.getElementById('count-all');
const countLive = document.getElementById('count-live');
const countResolved = document.getElementById('count-resolved');
const countOffline = document.getElementById('count-offline');
const tableSearch = document.getElementById('table-search');
const exportBtn = document.getElementById('export-btn');
const exportCsvLink = document.getElementById('export-csv');
const exportJsonLink = document.getElementById('export-json');

// Table & Empty State Elements
const resultsTable = document.getElementById('results-table');
const resultsBody = document.getElementById('results-body');
const emptyState = document.getElementById('empty-state');

// Source Badges
const badgeCrt = document.getElementById('badge-crt');
const badgeAv = document.getElementById('badge-av');
const badgeHt = document.getElementById('badge-ht');
const badgeBrute = document.getElementById('badge-brute');

// Source Badge Mappings
const sourceBadgeMap = {
  'crt.sh': badgeCrt,
  'AlienVault OTX': badgeAv,
  'HackerTarget': badgeHt,
  'DNS Brute-force': badgeBrute
};

// Form Submission Event
scanForm.addEventListener('submit', (e) => {
  e.preventDefault();
  initiateScan();
});

// Cancel Button Event
cancelBtn.addEventListener('click', () => {
  stopScan('Scan cancelled by user.');
});

// Filter Buttons Click
filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    activeFilter = btn.dataset.filter;
    renderTable();
  });
});

// Search Input Event
tableSearch.addEventListener('input', (e) => {
  searchQuery = e.target.value.toLowerCase().trim();
  renderTable();
});

// Export Events
exportCsvLink.addEventListener('click', (e) => {
  e.preventDefault();
  exportToCSV();
});

exportJsonLink.addEventListener('click', (e) => {
  e.preventDefault();
  exportToJSON();
});

// Initialize Scan Operation
function initiateScan() {
  const domain = domainInput.value.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');
  if (!domain) return;
  
  currentDomain = domain;
  resetState();
  
  // Update scan buttons
  scanForm.classList.add('scanning');
  scanBtn.disabled = true;
  scanBtn.querySelector('.btn-text').innerText = 'Scanning...';
  cancelBtn.classList.remove('hidden');
  domainInput.disabled = true;
  
  // Show panels & hide welcome state
  statsPanel.classList.remove('hidden');
  progressContainer.classList.remove('hidden');
  emptyState.classList.add('hidden');
  emptyState.classList.remove('scanning-active');
  
  // Set radar animation active inside empty state for scanning vibe
  const radarContainer = document.querySelector('.empty-state');
  radarContainer.classList.add('scanning-active');

  // Open SSE Connection
  const url = `/api/scan?domain=${encodeURIComponent(domain)}`;
  eventSource = new EventSource(url);

  // 1. Info / Progress Events
  eventSource.addEventListener('info', (e) => {
    const data = JSON.parse(e.data);
    updateProgressStatus(data.message);
  });

  // 2. Source Discovery Events
  eventSource.addEventListener('source_found', (e) => {
    const data = JSON.parse(e.data);
    const badgeEl = sourceBadgeMap[data.source];
    if (badgeEl) {
      const countEl = badgeEl.querySelector('.badge-count');
      countEl.innerText = data.count;
      badgeEl.classList.add('active-source');
    }
  });

  // 3. Start Verification
  eventSource.addEventListener('start_verification', (e) => {
    const data = JSON.parse(e.data);
    updateProgressStatus(`Starting verification of ${data.total} unique subdomains...`);
  });

  // 4. Subdomain scan result
  eventSource.addEventListener('result', (e) => {
    const data = JSON.parse(e.data);
    results.push(data);
    updateStatsCounters();
    appendTableRow(data);
  });

  // 5. Overall progress update
  eventSource.addEventListener('progress', (e) => {
    const data = JSON.parse(e.data);
    const percent = Math.round((data.current / data.total) * 100);
    progressBar.style.width = `${percent}%`;
    progressPercent.innerText = `${percent}%`;
    updateProgressStatus(`Verifying: ${data.current} of ${data.total} subdomains completed`);
  });

  // 6. Complete Scan
  eventSource.addEventListener('done', (e) => {
    const data = JSON.parse(e.data);
    stopScan(data.message, true);
  });

  // 7. Error
  eventSource.addEventListener('error', (e) => {
    let errorMsg = 'An error occurred during scanning.';
    if (e.data) {
      try {
        const data = JSON.parse(e.data);
        errorMsg = data.message;
      } catch {}
    }
    stopScan(errorMsg, false);
  });
}

// Reset client UI state before starting
function resetState() {
  results = [];
  activeFilter = 'all';
  searchQuery = '';
  tableSearch.value = '';
  
  // Reset filter buttons active state
  filterBtns.forEach(btn => btn.classList.remove('active'));
  filterBtns[0].classList.add('active');
  
  // Reset Stats Text
  statTotal.innerText = '0';
  statResolved.innerText = '0';
  statWeb.innerText = '0';
  statOffline.innerText = '0';
  
  countAll.innerText = '0';
  countLive.innerText = '0';
  countResolved.innerText = '0';
  countOffline.innerText = '0';

  // Reset Progress elements
  progressBar.style.width = '0%';
  progressPercent.innerText = '0%';
  progressStatus.innerText = 'Initializing...';
  
  // Clear source badge counts
  Object.values(sourceBadgeMap).forEach(badgeEl => {
    badgeEl.querySelector('.badge-count').innerText = '-';
    badgeEl.classList.remove('active-source');
  });

  // Clear Table
  resultsBody.innerHTML = '';
  exportBtn.disabled = true;
}

// Stop scan, close connection & reset buttons
function stopScan(message, success = false) {
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }

  scanForm.classList.remove('scanning');
  scanBtn.disabled = false;
  scanBtn.querySelector('.btn-text').innerText = 'Initiate Scan';
  cancelBtn.classList.add('hidden');
  domainInput.disabled = false;
  
  const radarContainer = document.querySelector('.empty-state');
  radarContainer.classList.remove('scanning-active');

  if (success) {
    progressBar.style.width = '100%';
    progressPercent.innerText = '100%';
    updateProgressStatus(message);
  } else {
    updateProgressStatus(message || 'Scan stopped.');
  }

  // Enable/Disable export button depending on findings
  if (results.length > 0) {
    exportBtn.disabled = false;
  } else {
    // If no results, show empty state again
    emptyState.classList.remove('hidden');
  }
}

// Update progress status text
function updateProgressStatus(text) {
  progressStatus.innerText = text;
}

// Calculate and render stats counters
function updateStatsCounters() {
  const total = results.length;
  const resolved = results.filter(r => r.ip !== null).length;
  const webLive = results.filter(r => r.live === true).length;
  const offline = results.filter(r => r.ip === null).length;

  statTotal.innerText = total;
  statResolved.innerText = resolved;
  statWeb.innerText = webLive;
  statOffline.innerText = offline;

  // Update filter counts
  countAll.innerText = total;
  countLive.innerText = webLive;
  countResolved.innerText = resolved - webLive; // Resolved but no web server
  countOffline.innerText = offline;
}

// Check if a result matches active filter and search query
function matchesFilterAndSearch(item) {
  // Search logic
  const matchesSearch = item.subdomain.includes(searchQuery) || (item.ip && item.ip.includes(searchQuery));
  if (!matchesSearch) return false;

  // Filter logic
  if (activeFilter === 'all') return true;
  if (activeFilter === 'live') return item.live === true;
  if (activeFilter === 'resolved') return item.ip !== null && item.live === false;
  if (activeFilter === 'offline') return item.ip === null;

  return true;
}

// Dynamically append table row
function appendTableRow(item) {
  if (!matchesFilterAndSearch(item)) return;

  const row = createRowElement(item);
  resultsBody.appendChild(row);
}

// Re-render table completely (used for filtering & searching)
function renderTable() {
  resultsBody.innerHTML = '';
  const filtered = results.filter(matchesFilterAndSearch);

  if (filtered.length === 0) {
    const emptyRow = document.createElement('tr');
    emptyRow.innerHTML = `<td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No matching subdomains found.</td>`;
    resultsBody.appendChild(emptyRow);
    return;
  }

  filtered.forEach(item => {
    const row = createRowElement(item);
    resultsBody.appendChild(row);
  });
}

// Helper: generate DOM table row
function createRowElement(item) {
  const tr = document.createElement('tr');
  tr.id = `row-${item.subdomain.replace(/\./g, '-')}`;

  // Subdomain column
  const subTd = document.createElement('td');
  subTd.className = 'subdomain-cell';
  subTd.innerText = item.subdomain;

  // IP Address column
  const ipTd = document.createElement('td');
  ipTd.className = 'ip-cell';
  ipTd.innerText = item.ip || '—';

  // Status column
  const statusTd = document.createElement('td');
  let statusBadge = '';
  if (item.live) {
    statusBadge = `<span class="status-badge status-live">Live</span>`;
  } else if (item.ip) {
    statusBadge = `<span class="status-badge status-dns">DNS Only</span>`;
  } else {
    statusBadge = `<span class="status-badge status-offline">Offline</span>`;
  }
  statusTd.innerHTML = statusBadge;

  // Title / Web Server column
  const webTd = document.createElement('td');
  if (item.live && item.web) {
    const webProtocol = item.web.protocol ? item.web.protocol.toUpperCase() : 'HTTP';
    webTd.innerHTML = `
      <div class="web-details">
        <span class="web-title" title="${escapeHtml(item.web.title)}">${escapeHtml(item.web.title)}</span>
        <span class="web-server">[${webProtocol}] Server: ${escapeHtml(item.web.server)} (HTTP ${item.web.status})</span>
      </div>
    `;
  } else {
    webTd.innerHTML = `<span style="color: var(--text-dim);">N/A</span>`;
  }

  // Sources column
  const sourceTd = document.createElement('td');
  const sourceDiv = document.createElement('div');
  sourceDiv.className = 'source-pills';
  item.sources.forEach(src => {
    const classSuffix = src === 'crt.sh' ? 'crt' : src === 'AlienVault OTX' ? 'av' : src === 'HackerTarget' ? 'ht' : 'brute';
    sourceDiv.innerHTML += `<span class="pill pill-${classSuffix}">${src}</span>`;
  });
  sourceTd.appendChild(sourceDiv);

  // Actions column
  const actionTd = document.createElement('td');
  if (item.live && item.web) {
    const url = `${item.web.protocol}://${item.subdomain}`;
    actionTd.innerHTML = `
      <a href="${url}" target="_blank" class="row-action-btn">
        <span>Visit</span>
      </a>
    `;
  } else {
    actionTd.innerHTML = `
      <button class="row-action-btn" onclick="copyToClipboard('${item.subdomain}')">
        <span>Copy</span>
      </button>
    `;
  }

  tr.appendChild(subTd);
  tr.appendChild(ipTd);
  tr.appendChild(statusTd);
  tr.appendChild(webTd);
  tr.appendChild(sourceTd);
  tr.appendChild(actionTd);

  return tr;
}

// Utility: copy text to clipboard
window.copyToClipboard = function(text) {
  navigator.clipboard.writeText(text).then(() => {
    // Basic visual alert
    const rowEl = document.getElementById(`row-${text.replace(/\./g, '-')}`);
    if (rowEl) {
      const originalBg = rowEl.style.background;
      rowEl.style.background = 'rgba(0, 242, 254, 0.15)';
      setTimeout(() => {
        rowEl.style.background = originalBg;
      }, 500);
    }
  });
};

// Utility: HTML Sanitizer
function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// CSV Export Builder
function exportToCSV() {
  if (results.length === 0) return;

  const headers = ['Subdomain', 'IP Address', 'Status', 'Web Protocol', 'HTTP Status', 'Title', 'Server Header', 'Sources'];
  const rows = results.map(item => [
    item.subdomain,
    item.ip || 'N/A',
    item.live ? 'Live' : (item.ip ? 'DNS Only' : 'Offline'),
    item.web ? item.web.protocol : 'N/A',
    item.web ? item.web.status : 'N/A',
    item.web ? `"${item.web.title.replace(/"/g, '""')}"` : 'N/A',
    item.web ? `"${item.web.server.replace(/"/g, '""')}"` : 'N/A',
    `"${item.sources.join(', ')}"`
  ]);

  const csvContent = "data:text/csv;charset=utf-8," 
    + [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
  
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", `subdomains_${currentDomain}_${new Date().toISOString().slice(0,10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

// JSON Export Builder
function exportToJSON() {
  if (results.length === 0) return;

  const jsonContent = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(results, null, 2));
  const link = document.createElement("a");
  link.setAttribute("href", jsonContent);
  link.setAttribute("download", `subdomains_${currentDomain}_${new Date().toISOString().slice(0,10)}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
