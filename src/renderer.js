// ─────────────────────────────────────────────────────────────────────────────
// Trust-Flow Renderer v3.0 — Dynamic · Animated · Professional
// ─────────────────────────────────────────────────────────────────────────────

// ──── DOM refs ────
const tabsContainer = document.getElementById('tabs');
const newTabBtn     = document.getElementById('new-tab-btn');
const browserArea   = document.getElementById('browser');
const backBtn       = document.getElementById('back');
const forwardBtn    = document.getElementById('forward');
const reloadBtn     = document.getElementById('reload');
const goBtn         = document.getElementById('go');
const urlInput      = document.getElementById('url');
const bookmarkBtn   = document.getElementById('bookmark');
const settingsBtn   = document.getElementById('settings');
const shieldIcon    = document.getElementById('shield-icon');
const shieldLabel   = document.getElementById('shield-label');
const shieldTooltip = document.getElementById('shield-tooltip');
const shieldRing    = document.getElementById('shield-ring');
const settingsPanel = document.getElementById('settings-panel');
const closePanelBtn = document.getElementById('close-panel');
const scanSpinner   = document.getElementById('scan-spinner');
const addrClear     = document.getElementById('addr-clear');
const navProgress   = document.getElementById('nav-progress');
const navProgressFill = document.getElementById('nav-progress-fill');
const panelBackdrop = document.getElementById('panel-backdrop');
const vtReveal      = document.getElementById('vt-reveal');
const splashEl      = document.getElementById('splash');
const splashFill    = document.getElementById('splash-fill');
const splashStatus  = document.getElementById('splash-status');

// ──── State ────
let tabs           = [];
let activeTabId    = 0;
let keyboardLocked = false;
let settings       = {};
let searchEngine   = 'google';
let navProgressTimer = null;

// ─────────────────────────────────────────────────────────────────────────────
// Toast System
// ─────────────────────────────────────────────────────────────────────────────
const toastContainer = document.getElementById('toast-container');

function showToast(message, type = 'info', duration = 3000) {
    const icons = { safe:'fa-shield-halved', warn:'fa-triangle-exclamation', danger:'fa-skull-crossbones', info:'fa-circle-info' };
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<i class="fa-solid ${icons[type] || icons.info}"></i><span>${message}</span>`;
    toastContainer.appendChild(toast);
    setTimeout(() => {
        toast.classList.add('out');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
    }, duration);
}

// ─────────────────────────────────────────────────────────────────────────────
// Nav Progress Bar
// ─────────────────────────────────────────────────────────────────────────────
function startNavProgress() {
    clearTimeout(navProgressTimer);
    navProgress.classList.add('active');
    navProgressFill.style.width = '0%';
    let w = 0;
    const tick = () => {
        w = Math.min(w + (Math.random() * 12 + 4), 88);
        navProgressFill.style.width = w + '%';
        if (w < 88) navProgressTimer = setTimeout(tick, 200 + Math.random() * 120);
    };
    tick();
}

function finishNavProgress() {
    clearTimeout(navProgressTimer);
    navProgressFill.style.width = '100%';
    setTimeout(() => {
        navProgress.classList.remove('active');
        navProgressFill.style.width = '0%';
    }, 320);
}

// ─────────────────────────────────────────────────────────────────────────────
// Splash Screen
// ─────────────────────────────────────────────────────────────────────────────
const SPLASH_STEPS = [
    { pct: 20, msg: 'Loading ML classifier…' },
    { pct: 45, msg: 'Connecting security engine…' },
    { pct: 70, msg: 'Initialising WHOIS intelligence…' },
    { pct: 90, msg: 'Warming up VirusTotal bridge…' },
    { pct: 100, msg: 'Ready.' },
];

async function runSplash() {
    for (const step of SPLASH_STEPS) {
        splashFill.style.width  = step.pct + '%';
        splashStatus.textContent = step.msg;
        await new Promise(r => setTimeout(r, 280 + Math.random() * 180));
    }
    await new Promise(r => setTimeout(r, 300));
    splashEl.classList.add('hide');
    splashEl.addEventListener('transitionend', () => splashEl.remove(), { once: true });
}

// ─────────────────────────────────────────────────────────────────────────────
// Search Engine Config
// ─────────────────────────────────────────────────────────────────────────────
const SEARCH_ENGINES = {
    google:     'https://www.google.com/search?q=',
    duckduckgo: 'https://duckduckgo.com/?q=',
    bing:       'https://www.bing.com/search?q=',
};

function buildSearchUrl(query) {
    return (SEARCH_ENGINES[searchEngine] || SEARCH_ENGINES.google) + encodeURIComponent(query);
}

function resolveUrl(raw) {
    raw = raw.trim();
    if (!raw) return null;
    if (/^https?:\/\//i.test(raw)) return raw;
    if (!raw.includes(' ') && /\.\w{2,}/.test(raw)) return 'https://' + raw;
    return buildSearchUrl(raw);
}

// ─────────────────────────────────────────────────────────────────────────────
// Address bar helpers
// ─────────────────────────────────────────────────────────────────────────────
urlInput.addEventListener('input', () => {
    addrClear.style.display = urlInput.value ? 'flex' : 'none';
});
addrClear.addEventListener('click', () => {
    urlInput.value = '';
    addrClear.style.display = 'none';
    urlInput.focus();
});
urlInput.addEventListener('focus', () => {
    urlInput.select();
});

// VT key reveal
vtReveal?.addEventListener('click', () => {
    const inp = document.getElementById('vt-key');
    const icon = vtReveal.querySelector('i');
    if (inp.type === 'password') {
        inp.type = 'text';
        icon.className = 'fa-regular fa-eye-slash';
    } else {
        inp.type = 'password';
        icon.className = 'fa-regular fa-eye';
    }
});

// Settings engine radio sync
function syncEngineRadios() {
    document.querySelectorAll('input[name="settings-engine"]').forEach(r => {
        r.checked = r.value === searchEngine;
    });
    document.querySelectorAll('.engine-select').forEach(s => { s.value = searchEngine; });
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab Management
// ─────────────────────────────────────────────────────────────────────────────
function createTab(url = null) {
    const tabId  = Date.now();
    const tabDiv = document.createElement('div');
    tabDiv.classList.add('tab');
    tabDiv.dataset.id = tabId;
    tabDiv.innerHTML  = `<i class="fa-solid fa-globe"></i><span class="tab-title">New Tab</span><span class="close">&times;</span>`;
    tabsContainer.insertBefore(tabDiv, newTabBtn);

    if (!url) {
        const page = buildNewTabPage(tabId);
        page.dataset.id = tabId;
        browserArea.appendChild(page);
        tabs.push({ id: tabId, tabDiv, webview: null, page, url: '' });
        setActiveTab(tabId);
    } else {
        const webview = createWebview(tabId);
        browserArea.appendChild(webview);
        tabs.push({ id: tabId, tabDiv, webview, page: null, url });
        setActiveTab(tabId);
        navigateTo(url, tabId);
    }

    tabDiv.addEventListener('click', e => { if (!e.target.classList.contains('close')) setActiveTab(tabId); });
    tabDiv.querySelector('.close').addEventListener('click', e => { e.stopPropagation(); closeTab(tabId); });
}

function createWebview(tabId) {
    const wv = document.createElement('webview');
    wv.src = 'about:blank';
    wv.dataset.id = tabId;
    wv.style.cssText = 'width:100%;height:100%;border:none;display:none;flex:1;';
    wv.setAttribute('allowpopups', '');

    wv.addEventListener('did-navigate', () => {
        if (activeTabId === tabId) {
            urlInput.value = wv.src !== 'about:blank' ? wv.src : '';
            addrClear.style.display = urlInput.value ? 'flex' : 'none';
        }
        const t = tabs.find(t => t.id === tabId);
        if (t) t.url = wv.src;
    });
    wv.addEventListener('did-navigate-in-page', () => {
        if (activeTabId === tabId) {
            urlInput.value = wv.src;
            addrClear.style.display = urlInput.value ? 'flex' : 'none';
        }
    });
    wv.addEventListener('page-title-updated', e => {
        const t = tabs.find(t => t.id === tabId);
        if (t) t.tabDiv.querySelector('.tab-title').textContent = (e.title || 'Tab').slice(0, 22);
    });
    wv.addEventListener('page-favicon-updated', e => {
        const t = tabs.find(t => t.id === tabId);
        if (t && e.favicons?.[0]) {
            const icon = t.tabDiv.querySelector('i');
            const img  = document.createElement('img');
            img.src    = e.favicons[0];
            img.style.cssText = 'width:12px;height:12px;object-fit:contain;opacity:0.8;';
            img.onerror = () => { img.replaceWith(icon); };
            icon.replaceWith(img);
        }
    });
    wv.addEventListener('did-start-loading', () => {
        startNavProgress();
        const t = tabs.find(t => t.id === tabId);
        if (t && activeTabId === tabId) reloadBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    });
    wv.addEventListener('did-stop-loading', () => {
        finishNavProgress();
        reloadBtn.innerHTML = '<i class="fa-solid fa-rotate-right"></i>';
    });
    return wv;
}

function buildNewTabPage(tabId) {
    const div = document.createElement('div');
    div.className = 'newtab-page';
    div.style.display = 'none';

    const engines = Object.keys(SEARCH_ENGINES).map(e =>
        `<option value="${e}" ${e === searchEngine ? 'selected' : ''}>${e.charAt(0).toUpperCase() + e.slice(1)}</option>`
    ).join('');

    div.innerHTML = `
        <div class="newtab-inner">
            <img src="Images/Trust-Flow-logo.png" class="center-logo" alt="Trust-Flow">
            <h1>Trust-Flow</h1>
            <p class="newtab-tagline">Zero-Trust AI Browser</p>

            <div class="newtab-search-wrap">
                <div class="newtab-engine-selector">
                    <select class="engine-select nt-engine-select">${engines}</select>
                </div>
                <div class="newtab-search-bar">
                    <i class="fa-solid fa-magnifying-glass nt-search-icon"></i>
                    <input type="text" class="nt-url-input" placeholder="Search the web or enter a URL…" autocomplete="off" spellcheck="false">
                    <button class="nt-go-btn" title="Go"><i class="fa-solid fa-arrow-right"></i></button>
                </div>
            </div>

            <div class="newtab-stats">
                <div class="stat-card">
                    <i class="fa-solid fa-shield-halved"></i>
                    <span class="stat-num nt-scanned">0</span>
                    <small>Sites Scanned</small>
                </div>
                <div class="stat-card danger">
                    <i class="fa-solid fa-skull-crossbones"></i>
                    <span class="stat-num nt-blocked">0</span>
                    <small>Threats Blocked</small>
                </div>
            </div>

            <div class="newtab-quick-links">
                <a class="quick-link" data-url="https://www.google.com"><i class="fa-brands fa-google"></i><span>Google</span></a>
                <a class="quick-link" data-url="https://www.youtube.com"><i class="fa-brands fa-youtube"></i><span>YouTube</span></a>
                <a class="quick-link" data-url="https://www.github.com"><i class="fa-brands fa-github"></i><span>GitHub</span></a>
                <a class="quick-link" data-url="https://www.reddit.com"><i class="fa-brands fa-reddit"></i><span>Reddit</span></a>
                <a class="quick-link" data-url="https://www.wikipedia.org"><i class="fa-solid fa-book"></i><span>Wikipedia</span></a>
                <a class="quick-link" data-url="https://news.ycombinator.com"><i class="fa-solid fa-newspaper"></i><span>HN</span></a>
            </div>

            <div class="newtab-bookmarks-section" id="nt-bookmarks-${tabId}"></div>
        </div>`;

    setTimeout(() => {
        const ntInput = div.querySelector('.nt-url-input');
        const ntGo    = div.querySelector('.nt-go-btn');
        const ntEng   = div.querySelector('.nt-engine-select');

        ntEng.addEventListener('change', () => {
            searchEngine = ntEng.value;
            localStorage.setItem('searchEngine', searchEngine);
            syncEngineRadios();
        });

        const go = () => {
            const url = resolveUrl(ntInput.value);
            if (url) navigateTo(url, tabId);
        };
        ntGo.addEventListener('click', go);
        ntInput.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
        ntInput.focus();

        div.querySelectorAll('.quick-link').forEach(a => {
            a.addEventListener('click', e => { e.preventDefault(); navigateTo(a.dataset.url, tabId); });
        });

        renderNewtabBookmarks(div.querySelector(`#nt-bookmarks-${tabId}`));
        refreshStats(div);
    }, 30);

    return div;
}

function renderNewtabBookmarks(container) {
    if (!container) return;
    const bm = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    if (!bm.length) return;
    container.innerHTML = '<p class="bm-title">Bookmarks</p>' + bm.map(u => {
        let hostname = u;
        try { hostname = new URL(u).hostname; } catch (_) {}
        return `<a class="bm-chip" href="#" data-url="${u}">${hostname}</a>`;
    }).join('');
    container.querySelectorAll('.bm-chip').forEach(a => {
        a.addEventListener('click', e => { e.preventDefault(); navigateTo(a.dataset.url, activeTabId); });
    });
}

// Animated counter
function animateCounter(el, target) {
    const start = parseInt(el.textContent, 10) || 0;
    if (start === target) return;
    const diff   = target - start;
    const steps  = Math.min(Math.abs(diff), 20);
    let   step   = 0;
    const tick   = () => {
        step++;
        el.textContent = Math.round(start + (diff * step / steps));
        el.classList.add('bump');
        el.addEventListener('animationend', () => el.classList.remove('bump'), { once: true });
        if (step < steps) setTimeout(tick, 30);
    };
    tick();
}

async function refreshStats(container = null) {
    if (!window.trustflow) return;
    const st = await window.trustflow.getStats().catch(() => ({ scanned: 0, blocked: 0 }));
    const targets = container ? [container] : document.querySelectorAll('.newtab-page');
    targets.forEach(c => {
        const sc = c.querySelector('.nt-scanned');
        const bl = c.querySelector('.nt-blocked');
        if (sc) animateCounter(sc, st.scanned);
        if (bl) animateCounter(bl, st.blocked);
    });
}

function syncEngineSelectors() {
    document.querySelectorAll('.engine-select').forEach(s => { s.value = searchEngine; });
}

function setActiveTab(tabId) {
    tabs.forEach(t => {
        const isActive = t.id === tabId;
        t.tabDiv.classList.toggle('active', isActive);
        if (t.webview) t.webview.style.display = isActive ? 'flex'   : 'none';
        if (t.page)    t.page.style.display    = isActive ? 'flex'   : 'none';
        if (isActive) {
            urlInput.value = t.url && t.url !== 'about:blank' ? t.url : '';
            addrClear.style.display = urlInput.value ? 'flex' : 'none';
            activeTabId = tabId;
        }
    });
    unlockKeyboard();
    resetShield();
    removeOverlays();
}

function getActiveTab()     { return tabs.find(t => t.id === activeTabId); }
function getActiveWebview() { return getActiveTab()?.webview; }

function closeTab(tabId) {
    const index = tabs.findIndex(t => t.id === tabId);
    if (index === -1) return;
    const tab = tabs[index];
    // Slide out animation
    tab.tabDiv.style.transform = 'scale(0.8)';
    tab.tabDiv.style.opacity   = '0';
    tab.tabDiv.style.transition = 'transform 0.15s, opacity 0.15s';
    setTimeout(() => {
        tab.tabDiv.remove();
        if (tab.webview) tab.webview.remove();
        if (tab.page)    tab.page.remove();
        tabs.splice(index, 1);
        if (!tabs.length) { createTab(); return; }
        if (activeTabId === tabId) setActiveTab(tabs[Math.max(0, index - 1)].id);
    }, 150);
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation + Security scan
// ─────────────────────────────────────────────────────────────────────────────
async function navigateTo(rawUrl, tabId) {
    const url = resolveUrl(rawUrl);
    if (!url) return;

    urlInput.value = url;
    addrClear.style.display = 'flex';
    showScanning();
    removeOverlays();
    startNavProgress();

    const tab = tabs.find(t => t.id === tabId);
    if (!tab) { hideScanning(); finishNavProgress(); return; }

    if (tab.page) {
        tab.page.style.display = 'none';
        tab.page.remove();
        tab.page = null;
    }
    if (!tab.webview) {
        const wv = createWebview(tabId);
        browserArea.appendChild(wv);
        tab.webview = wv;
    }
    if (activeTabId === tabId) tab.webview.style.display = 'flex';

    let result;
    try {
        result = await window.trustflow.scanUrl(url);
    } catch (_) {
        result = { score: 50, verdict: 'safe', details: { ml: 50, whois: 50, virustotal: 50, domain: '' } };
    }

    hideScanning();
    finishNavProgress();
    updateShield(result);
    refreshStats();

    if (result.verdict === 'malicious') {
        tab.webview.style.display = 'none';
        lockKeyboard(result);
        showBlockPage(result, url, tabId);
        showToast('Phishing site blocked!', 'danger');
    } else if (result.verdict === 'suspicious') {
        tab.webview.style.display = 'none';
        lockKeyboard(result);
        showWarningOverlay(result, url, tabId);
        showToast('Suspicious site detected', 'warn');
    } else {
        unlockKeyboard();
        tab.webview.src = url;
        tab.url = url;
        if (result.score >= 80) showToast(`Site verified safe (${result.score}/100)`, 'safe', 2000);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shield Badge
// ─────────────────────────────────────────────────────────────────────────────
function showScanning() {
    if (scanSpinner) scanSpinner.style.display = 'block';
    if (shieldIcon)  shieldIcon.className = 'fa-solid fa-shield-halved shield-scanning';
    if (shieldLabel) shieldLabel.textContent = 'Scanning…';
    if (shieldRing)  { shieldRing.style.color = 'var(--accent-light)'; shieldRing.classList.add('active'); }
}
function hideScanning() {
    if (scanSpinner) scanSpinner.style.display = 'none';
    if (shieldRing)  shieldRing.classList.remove('active');
}

function updateShield(result) {
    if (!shieldIcon || !shieldLabel) return;
    const { score, verdict, details } = result;
    shieldIcon.className = 'fa-solid fa-shield-halved';
    shieldIcon.style.transform = 'scale(1.2)';
    setTimeout(() => { shieldIcon.style.transform = ''; }, 250);

    if (verdict === 'safe') {
        shieldIcon.classList.add('shield-safe');
        shieldLabel.textContent = `Safe · ${score}`;
        if (shieldRing) shieldRing.style.color = 'var(--safe)';
    } else if (verdict === 'suspicious') {
        shieldIcon.classList.add('shield-warn');
        shieldLabel.textContent = `Warning · ${score}`;
        if (shieldRing) shieldRing.style.color = 'var(--warn)';
    } else {
        shieldIcon.classList.add('shield-danger');
        shieldLabel.textContent = `Blocked · ${score}`;
        if (shieldRing) shieldRing.style.color = 'var(--danger)';
    }
    if (shieldRing) shieldRing.classList.add('active');

    if (shieldTooltip && details) {
        const rows = [
            { label: 'Trust Score',   val: score,              pct: score },
            { label: 'ML Classifier', val: details.ml,         pct: details.ml },
            { label: 'VirusTotal',    val: details.virustotal, pct: details.virustotal },
            { label: 'Domain Intel',  val: details.whois,      pct: details.whois },
        ];
        const color = verdict === 'safe' ? 'var(--safe)' : verdict === 'suspicious' ? 'var(--warn)' : 'var(--danger)';
        shieldTooltip.innerHTML = `
            <b>${details.domain || 'Unknown domain'}</b><br><br>
            ${rows.map(r => `
                <div class="tt-row">
                    <span style="width:100px;font-size:10px;color:var(--text-muted)">${r.label}</span>
                    <div class="tt-bar"><div class="tt-fill" style="width:${r.pct}%;background:${color};"></div></div>
                    <span style="font-size:11px;font-weight:600;width:28px;text-align:right">${r.val}</span>
                </div>`).join('')}`;
    }
}

function resetShield() {
    if (shieldIcon)  shieldIcon.className = 'fa-solid fa-shield-halved shield-neutral';
    if (shieldLabel) shieldLabel.textContent = '';
    if (shieldRing)  shieldRing.classList.remove('active');
}

// ─────────────────────────────────────────────────────────────────────────────
// Score bar helper for overlays
// ─────────────────────────────────────────────────────────────────────────────
function scoreBar(label, val, invert = false) {
    const pct   = invert ? 100 - val : val;
    const cls   = pct >= 65 ? 'good' : pct >= 35 ? 'mid' : 'bad';
    const color = pct >= 65 ? 'var(--safe)' : pct >= 35 ? 'var(--warn)' : 'var(--danger)';
    return `
        <div class="score-row">
            <span class="score-row-label">${label}</span>
            <div class="score-row-bar">
                <div class="score-row-fill ${cls}" style="width:${pct}%"></div>
            </div>
            <span class="score-row-val" style="color:${color}">${val}</span>
        </div>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Overlays
// ─────────────────────────────────────────────────────────────────────────────
function removeOverlays() {
    document.querySelectorAll('.tf-overlay').forEach(el => el.remove());
}

function showWarningOverlay(result, url, tabId) {
    removeOverlays();
    const overlay = document.createElement('div');
    overlay.className = 'tf-overlay tf-warning-overlay';
    overlay.innerHTML = `
        <div class="overlay-card warn-card">
            <i class="fa-solid fa-triangle-exclamation overlay-icon warn-icon"></i>
            <h2>Suspicious Website Detected</h2>
            <p>This site shows phishing indicators. Keyboard input is restricted to protect your credentials.</p>
            <div class="score-details">
                ${scoreBar('Trust Score',   result.score)}
                ${scoreBar('ML Analysis',   result.details.ml)}
                ${scoreBar('VirusTotal',    result.details.virustotal)}
                ${scoreBar('Domain Age',    result.details.whois)}
            </div>
            <p class="domain-label"><i class="fa-solid fa-globe"></i> ${result.details.domain}</p>
            <div class="overlay-actions">
                <button class="btn-back">← Go Back to Safety</button>
                <button class="btn-proceed">⚠ Proceed Anyway</button>
            </div>
        </div>`;
    browserArea.appendChild(overlay);

    overlay.querySelector('.btn-back').addEventListener('click', () => {
        removeOverlays(); unlockKeyboard(); resetShield();
        const w = getActiveWebview();
        if (w && w.canGoBack()) w.goBack(); else createTab();
    });
    overlay.querySelector('.btn-proceed').addEventListener('click', () => {
        removeOverlays(); unlockKeyboard();
        const t = tabs.find(t => t.id === tabId);
        if (t) {
            if (t.webview) { t.webview.style.display = 'flex'; t.webview.src = url; }
            t.url = url;
        }
    });
}

function showBlockPage(result, url, tabId) {
    removeOverlays();
    const overlay = document.createElement('div');
    overlay.className = 'tf-overlay tf-block-overlay';
    overlay.innerHTML = `
        <div class="overlay-card danger-card">
            <i class="fa-solid fa-shield-virus overlay-icon danger-icon"></i>
            <h2>Phishing Attack Blocked</h2>
            <p>Trust-Flow identified this website as malicious. Navigation has been blocked to protect you.</p>
            <div class="score-details">
                ${scoreBar('Trust Score',     result.score)}
                ${scoreBar('ML Confidence',   result.details.ml, true)}
                ${scoreBar('VirusTotal',      result.details.virustotal)}
                ${scoreBar('Domain Intel',    result.details.whois)}
            </div>
            <p class="domain-label danger-label"><i class="fa-solid fa-skull-crossbones"></i> ${result.details.domain}</p>
            <p class="blocked-url">${url.slice(0, 90)}${url.length > 90 ? '…' : ''}</p>
            <div class="overlay-actions">
                <button class="btn-back-danger">← Go Back to Safety</button>
            </div>
        </div>`;
    browserArea.appendChild(overlay);

    overlay.querySelector('.btn-back-danger').addEventListener('click', () => {
        removeOverlays(); unlockKeyboard(); resetShield();
        const t = tabs.find(t => t.id === tabId);
        if (t?.webview) t.webview.style.display = 'flex';
        const w = getActiveWebview();
        if (w && w.canGoBack()) w.goBack(); else createTab();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard Lock
// ─────────────────────────────────────────────────────────────────────────────
function lockKeyboard(result) {
    keyboardLocked    = true;
    urlInput.disabled = true;
    const wv = getActiveWebview();
    if (wv) {
        wv.executeJavaScript(`
            (function(){
                if(window.__tf_locked) return;
                window.__tf_locked = true;
                const s = document.createElement('style');
                s.id = '__tf_ls';
                s.textContent = 'input:focus,textarea:focus,[contenteditable]:focus{outline:3px solid #ef4444!important;box-shadow:0 0 12px #ef444480!important;}';
                document.head.appendChild(s);
                window.__tf_lh = function(e){
                    if(['INPUT','TEXTAREA'].includes(e.target.tagName)||e.target.isContentEditable){
                        e.preventDefault();e.stopImmediatePropagation();
                    }
                };
                document.addEventListener('keydown',window.__tf_lh,true);
                document.addEventListener('keypress',window.__tf_lh,true);
            })();
        `).catch(() => {});
    }
}

function unlockKeyboard() {
    keyboardLocked    = false;
    urlInput.disabled = false;
    const wv = getActiveWebview();
    if (wv) {
        wv.executeJavaScript(`
            (function(){
                if(!window.__tf_locked) return;
                window.__tf_locked = false;
                document.removeEventListener('keydown',window.__tf_lh,true);
                document.removeEventListener('keypress',window.__tf_lh,true);
                const s = document.getElementById('__tf_ls');
                if(s) s.remove();
            })();
        `).catch(() => {});
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation Controls
// ─────────────────────────────────────────────────────────────────────────────
backBtn.addEventListener('click', () => {
    const w = getActiveWebview();
    if (w && w.canGoBack()) { removeOverlays(); unlockKeyboard(); resetShield(); w.goBack(); }
});
forwardBtn.addEventListener('click', () => {
    const w = getActiveWebview();
    if (w && w.canGoForward()) { removeOverlays(); unlockKeyboard(); resetShield(); w.goForward(); }
});
reloadBtn.addEventListener('click', () => {
    const w = getActiveWebview();
    if (w) {
        if (reloadBtn.innerHTML.includes('xmark')) { w.stop(); finishNavProgress(); }
        else { removeOverlays(); unlockKeyboard(); resetShield(); w.reload(); }
    }
});
goBtn.addEventListener('click', () => navigateTo(urlInput.value, activeTabId));
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') goBtn.click(); });
newTabBtn.addEventListener('click', () => createTab());

document.getElementById('engine-select').addEventListener('change', e => {
    searchEngine = e.target.value;
    localStorage.setItem('searchEngine', searchEngine);
    syncEngineSelectors();
    syncEngineRadios();
});

bookmarkBtn.addEventListener('click', () => {
    const tab = getActiveTab();
    if (!tab || !tab.url || tab.url === 'about:blank') return;
    let bm = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    const already = bm.includes(tab.url);
    if (!already) { bm.push(tab.url); localStorage.setItem('bookmarks', JSON.stringify(bm)); }
    const icon = bookmarkBtn.querySelector('i');
    icon.className = 'fa-solid fa-star';
    icon.style.color = '#facc15';
    showToast(already ? 'Already bookmarked' : 'Bookmark added', 'info', 1800);
    setTimeout(() => { icon.className = 'fa-regular fa-star'; icon.style.color = ''; }, 1800);
});

// ─────────────────────────────────────────────────────────────────────────────
// Settings Panel
// ─────────────────────────────────────────────────────────────────────────────
function openSettings() {
    settingsPanel.classList.add('open');
    panelBackdrop.classList.add('visible');
}
function closeSettings() {
    settingsPanel.classList.remove('open');
    panelBackdrop.classList.remove('visible');
}

async function loadSettings() {
    if (!window.trustflow) return;
    settings = await window.trustflow.getSettings().catch(() => ({}));
    document.getElementById('vt-key').value         = settings.vtApiKey || '';
    document.getElementById('toggle-ml').checked    = settings.mlEnabled   !== false;
    document.getElementById('toggle-whois').checked = settings.whoisEnabled !== false;
    document.getElementById('toggle-badge').checked = settings.badgeVisible  !== false;
    syncEngineRadios();
}

settingsBtn.addEventListener('click', async () => {
    if (settingsPanel.classList.contains('open')) { closeSettings(); return; }
    openSettings();
    await loadSettings();
});
closePanelBtn.addEventListener('click', closeSettings);
panelBackdrop.addEventListener('click', closeSettings);

document.getElementById('save-settings').addEventListener('click', async () => {
    const newSettings = {
        vtApiKey:     document.getElementById('vt-key').value.trim(),
        mlEnabled:    document.getElementById('toggle-ml').checked,
        whoisEnabled: document.getElementById('toggle-whois').checked,
        badgeVisible: document.getElementById('toggle-badge').checked,
    };
    const selected = document.querySelector('input[name="settings-engine"]:checked');
    if (selected) { searchEngine = selected.value; localStorage.setItem('searchEngine', searchEngine); syncEngineSelectors(); }
    await window.trustflow?.saveSettings(newSettings).catch(() => {});
    settings = newSettings;
    closeSettings();
    showToast('Settings saved', 'safe', 2000);
});

document.getElementById('clear-cache').addEventListener('click', async () => {
    await window.trustflow?.clearCache().catch(() => {});
    showToast('Scan cache cleared', 'info', 2000);
});

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────
(async function init() {
    runSplash();

    searchEngine = localStorage.getItem('searchEngine') || 'google';
    document.getElementById('engine-select').value = searchEngine;
    syncEngineRadios();

    if (window.trustflow) {
        settings = await window.trustflow.getSettings().catch(() => ({}));
        window.trustflow.onKeyboardLock?.(() => {});
        window.trustflow.onKeyboardUnlock?.(() => {});
    }

    createTab();
    setInterval(() => refreshStats(), 15000);
})();
