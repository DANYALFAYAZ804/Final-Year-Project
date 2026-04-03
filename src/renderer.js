// ─────────────────────────────────────────────────────────────────────────────
// Trust-Flow Renderer — Full Browser with Chromium Search Engine + Security UI
// ─────────────────────────────────────────────────────────────────────────────

// ──── DOM refs ────
const tabsContainer = document.querySelector('.tabs');
const newTabBtn     = document.querySelector('.new-tab');
const browserArea   = document.querySelector('.browser');
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
const settingsPanel = document.getElementById('settings-panel');
const closePanelBtn = document.getElementById('close-panel');
const scanSpinner   = document.getElementById('scan-spinner');

// ──── State ────
let tabs         = [];
let activeTabId  = 0;
let keyboardLocked = false;
let settings     = {};
let searchEngine = 'google'; // default

// ─────────────────────────────────────────────────────────────────────────────
// Search Engine Config
// ─────────────────────────────────────────────────────────────────────────────
const SEARCH_ENGINES = {
    google:     'https://www.google.com/search?q=',
    duckduckgo: 'https://duckduckgo.com/?q=',
    bing:       'https://www.bing.com/search?q=',
};

function buildSearchUrl(query) {
    const base = SEARCH_ENGINES[searchEngine] || SEARCH_ENGINES.google;
    return base + encodeURIComponent(query);
}

function resolveUrl(raw) {
    raw = raw.trim();
    if (!raw) return null;
    // Already a full URL
    if (/^https?:\/\//i.test(raw)) return raw;
    // Looks like a domain (has a dot, no spaces)
    if (!raw.includes(' ') && /\.\w{2,}/.test(raw)) return 'https://' + raw;
    // Treat as a search query
    return buildSearchUrl(raw);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab Management
// ─────────────────────────────────────────────────────────────────────────────
function createTab(url = null) {
    const tabId = Date.now();

    const tabDiv = document.createElement('div');
    tabDiv.classList.add('tab');
    tabDiv.dataset.id = tabId;
    tabDiv.innerHTML = `<i class="fa-solid fa-globe"></i><span class="tab-title">New Tab</span><span class="close">&times;</span>`;
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

    tabDiv.addEventListener('click', (e) => { if (!e.target.classList.contains('close')) setActiveTab(tabId); });
    tabDiv.querySelector('.close').addEventListener('click', (e) => { e.stopPropagation(); closeTab(tabId); });
}

function createWebview(tabId) {
    const wv = document.createElement('webview');
    wv.src = 'about:blank';
    wv.dataset.id = tabId;
    wv.style.cssText = 'width:100%;height:100%;border:none;display:none;flex:1;';
    wv.setAttribute('allowpopups', '');

    wv.addEventListener('did-navigate', () => {
        if (activeTabId === tabId) urlInput.value = wv.src !== 'about:blank' ? wv.src : '';
        const t = tabs.find(t => t.id === tabId);
        if (t) t.url = wv.src;
    });
    wv.addEventListener('did-navigate-in-page', () => {
        if (activeTabId === tabId) urlInput.value = wv.src;
    });
    wv.addEventListener('page-title-updated', (e) => {
        const t = tabs.find(t => t.id === tabId);
        if (t) t.tabDiv.querySelector('.tab-title').textContent = (e.title || 'Tab').slice(0, 22);
    });
    wv.addEventListener('did-start-loading', () => {
        const t = tabs.find(t => t.id === tabId);
        if (t && activeTabId === tabId) reloadBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    });
    wv.addEventListener('did-stop-loading', () => {
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
            <img src="Images/Gemini_3.png" class="center-logo" alt="Trust-Flow">
            <h1>Trust-Flow</h1>
            <p class="newtab-tagline">Zero-Trust AI Browser</p>

            <div class="newtab-search-wrap">
                <div class="newtab-engine-selector">
                    <select class="engine-select nt-engine-select">${engines}</select>
                </div>
                <div class="newtab-search-bar">
                    <i class="fa-solid fa-magnifying-glass nt-search-icon"></i>
                    <input type="text" class="nt-url-input" placeholder="Search the web or enter a URL…" autocomplete="off" spellcheck="false">
                    <button class="nt-go-btn"><i class="fa-solid fa-arrow-right"></i></button>
                </div>
            </div>

            <div class="newtab-stats">
                <div class="stat-card"><i class="fa-solid fa-shield-halved"></i><span class="nt-scanned">0</span><small>Sites Scanned</small></div>
                <div class="stat-card danger"><i class="fa-solid fa-skull-crossbones"></i><span class="nt-blocked">0</span><small>Threats Blocked</small></div>
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
        </div>
    `;

    setTimeout(() => {
        const ntInput = div.querySelector('.nt-url-input');
        const ntGo    = div.querySelector('.nt-go-btn');
        const ntEng   = div.querySelector('.nt-engine-select');

        ntEng.addEventListener('change', () => {
            searchEngine = ntEng.value;
            localStorage.setItem('searchEngine', searchEngine);
            syncEngineSelectors();
        });

        const go = () => {
            const url = resolveUrl(ntInput.value);
            if (url) navigateTo(url, tabId);
        };
        ntGo.addEventListener('click', go);
        ntInput.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
        ntInput.focus();

        // Quick links
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

async function refreshStats(container = null) {
    if (!window.trustflow) return;
    const st = await window.trustflow.getStats().catch(() => ({ scanned: 0, blocked: 0 }));
    if (container) {
        const sc = container.querySelector('.nt-scanned');
        const bl = container.querySelector('.nt-blocked');
        if (sc) sc.textContent = st.scanned;
        if (bl) bl.textContent = st.blocked;
    }
}

function syncEngineSelectors() {
    document.querySelectorAll('.engine-select').forEach(s => { s.value = searchEngine; });
}

function setActiveTab(tabId) {
    tabs.forEach(t => {
        const isActive = t.id === tabId;
        t.tabDiv.classList.toggle('active', isActive);
        if (t.webview) t.webview.style.display = isActive ? 'flex' : 'none';
        if (t.page)    t.page.style.display    = isActive ? 'flex' : 'none';
        if (isActive) {
            urlInput.value = t.url && t.url !== 'about:blank' ? t.url : '';
            activeTabId = tabId;
        }
    });
    unlockKeyboard();
    resetShield();
    removeOverlays();
}

function getActiveTab()    { return tabs.find(t => t.id === activeTabId); }
function getActiveWebview(){ return getActiveTab()?.webview; }

function closeTab(tabId) {
    const index = tabs.findIndex(t => t.id === tabId);
    if (index === -1) return;
    const tab = tabs[index];
    tab.tabDiv.remove();
    if (tab.webview) tab.webview.remove();
    if (tab.page)    tab.page.remove();
    tabs.splice(index, 1);
    if (!tabs.length) { createTab(); return; }
    if (activeTabId === tabId) setActiveTab(tabs[Math.max(0, index - 1)].id);
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation + Security scan
// ─────────────────────────────────────────────────────────────────────────────
async function navigateTo(rawUrl, tabId) {
    const url = resolveUrl(rawUrl);
    if (!url) return;

    urlInput.value = url;
    showScanning();
    removeOverlays();

    const tab = tabs.find(t => t.id === tabId);
    if (!tab) { hideScanning(); return; }

    // Dismiss new tab page
    if (tab.page) {
        tab.page.style.display = 'none';
        tab.page.remove();
        tab.page = null;
    }

    // Ensure webview exists
    if (!tab.webview) {
        const wv = createWebview(tabId);
        browserArea.appendChild(wv);
        tab.webview = wv;
    }
    if (activeTabId === tabId) tab.webview.style.display = 'flex';

    // Security scan
    let result;
    try {
        result = await window.trustflow.scanUrl(url);
    } catch (_) {
        result = { score: 50, verdict: 'safe', details: { ml: 50, whois: 50, virustotal: 50, domain: '' } };
    }

    hideScanning();
    updateShield(result);
    refreshStats();

    if (result.verdict === 'malicious') {
        tab.webview.style.display = 'none';
        lockKeyboard(result);
        showBlockPage(result, url, tabId);
    } else if (result.verdict === 'suspicious') {
        tab.webview.style.display = 'none';
        lockKeyboard(result);
        showWarningOverlay(result, url, tabId);
    } else {
        unlockKeyboard();
        tab.webview.src = url;
        tab.url = url;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shield Badge
// ─────────────────────────────────────────────────────────────────────────────
function showScanning() {
    if (scanSpinner) scanSpinner.style.display = 'block';
    if (shieldIcon)  shieldIcon.className = 'fa-solid fa-shield-halved shield-scanning';
    if (shieldLabel) shieldLabel.textContent = 'Scanning…';
}
function hideScanning() {
    if (scanSpinner) scanSpinner.style.display = 'none';
}
function updateShield(result) {
    if (!shieldIcon || !shieldLabel) return;
    const { score, verdict, details } = result;
    shieldIcon.className = 'fa-solid fa-shield-halved';
    if (verdict === 'safe')       { shieldIcon.classList.add('shield-safe');   shieldLabel.textContent = `Safe (${score})`; }
    else if (verdict === 'suspicious') { shieldIcon.classList.add('shield-warn');   shieldLabel.textContent = `Warning (${score})`; }
    else                          { shieldIcon.classList.add('shield-danger'); shieldLabel.textContent = `Blocked (${score})`; }

    if (shieldTooltip) {
        shieldTooltip.innerHTML = `
            <b>${details.domain}</b><br>
            Trust Score: <b>${score}/100</b><br>
            ML Classifier: ${details.ml}/100<br>
            VirusTotal: ${details.virustotal}/100<br>
            Domain Intelligence: ${details.whois}/100`;
    }
}
function resetShield() {
    if (shieldIcon)  shieldIcon.className = 'fa-solid fa-shield-halved shield-neutral';
    if (shieldLabel) shieldLabel.textContent = '';
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
        <div class="overlay-card">
            <i class="fa-solid fa-triangle-exclamation overlay-icon warn-icon"></i>
            <h2>Suspicious Website Detected</h2>
            <p>This site shows phishing indicators. Keyboard input is restricted to protect your credentials.</p>
            <div class="score-details">
                <div class="score-item"><span>Trust Score</span><b>${result.score}/100</b></div>
                <div class="score-item"><span>ML Analysis</span><b>${result.details.ml}/100</b></div>
                <div class="score-item"><span>VirusTotal</span><b>${result.details.virustotal}/100</b></div>
                <div class="score-item"><span>Domain Age</span><b>${result.details.whois}/100</b></div>
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
        const tab = tabs.find(t => t.id === tabId);
        if (tab) {
            if (tab.webview) { tab.webview.style.display = 'flex'; tab.webview.src = url; }
            tab.url = url;
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
            <p>Trust-Flow identified this website as malicious. Navigation has been blocked.</p>
            <div class="score-details">
                <div class="score-item bad"><span>Trust Score</span><b>${result.score}/100</b></div>
                <div class="score-item bad"><span>ML Confidence</span><b>${100 - result.details.ml}% phishing</b></div>
                <div class="score-item bad"><span>VirusTotal</span><b>${result.details.virustotal}/100</b></div>
                <div class="score-item bad"><span>Domain Intelligence</span><b>${result.details.whois}/100</b></div>
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
        const tab = tabs.find(t => t.id === tabId);
        if (tab && tab.webview) tab.webview.style.display = 'flex';
        const w = getActiveWebview();
        if (w && w.canGoBack()) w.goBack(); else createTab();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard Lock
// ─────────────────────────────────────────────────────────────────────────────
function lockKeyboard(result) {
    keyboardLocked = true;
    urlInput.disabled = true;
    urlInput.style.opacity = '0.4';
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
    keyboardLocked = false;
    urlInput.disabled = false;
    urlInput.style.opacity = '';
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
        if (reloadBtn.innerHTML.includes('xmark')) { w.stop(); }
        else { removeOverlays(); unlockKeyboard(); resetShield(); w.reload(); }
    }
});
goBtn.addEventListener('click', () => navigateTo(urlInput.value, activeTabId));
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') goBtn.click(); });
newTabBtn.addEventListener('click', () => createTab());

// Address bar engine selector
document.getElementById('engine-select').addEventListener('change', (e) => {
    searchEngine = e.target.value;
    localStorage.setItem('searchEngine', searchEngine);
    syncEngineSelectors();
});

bookmarkBtn.addEventListener('click', () => {
    const tab = getActiveTab();
    if (!tab || !tab.url || tab.url === 'about:blank') return;
    let bm = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    if (!bm.includes(tab.url)) { bm.push(tab.url); localStorage.setItem('bookmarks', JSON.stringify(bm)); }
    bookmarkBtn.querySelector('i').style.color = '#facc15';
    setTimeout(() => { bookmarkBtn.querySelector('i').style.color = ''; }, 1500);
});

// ─────────────────────────────────────────────────────────────────────────────
// Settings Panel
// ─────────────────────────────────────────────────────────────────────────────
async function loadSettings() {
    if (!window.trustflow) return;
    settings = await window.trustflow.getSettings().catch(() => ({}));
    document.getElementById('vt-key').value             = settings.vtApiKey || '';
    document.getElementById('toggle-ml').checked        = settings.mlEnabled !== false;
    document.getElementById('toggle-whois').checked     = settings.whoisEnabled !== false;
    document.getElementById('toggle-badge').checked     = settings.badgeVisible !== false;
    const engSel = document.getElementById('settings-engine');
    if (engSel) engSel.value = searchEngine;
}

settingsBtn.addEventListener('click', async () => {
    settingsPanel.classList.toggle('open');
    if (settingsPanel.classList.contains('open')) await loadSettings();
});
closePanelBtn.addEventListener('click', () => settingsPanel.classList.remove('open'));

document.getElementById('save-settings').addEventListener('click', async () => {
    const newSettings = {
        vtApiKey:     document.getElementById('vt-key').value.trim(),
        mlEnabled:    document.getElementById('toggle-ml').checked,
        whoisEnabled: document.getElementById('toggle-whois').checked,
        badgeVisible: document.getElementById('toggle-badge').checked,
    };
    const eng = document.getElementById('settings-engine');
    if (eng) { searchEngine = eng.value; localStorage.setItem('searchEngine', searchEngine); syncEngineSelectors(); }
    await window.trustflow.saveSettings(newSettings).catch(() => {});
    settings = newSettings;
    settingsPanel.classList.remove('open');
});

document.getElementById('clear-cache').addEventListener('click', async () => {
    await window.trustflow.clearCache().catch(() => {});
    const btn = document.getElementById('clear-cache');
    btn.textContent = 'Cleared!';
    setTimeout(() => { btn.textContent = 'Clear Scan Cache'; }, 1500);
});

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────
(async function init() {
    searchEngine = localStorage.getItem('searchEngine') || 'google';
    document.getElementById('engine-select').value = searchEngine;

    if (window.trustflow) {
        settings = await window.trustflow.getSettings().catch(() => ({}));
        window.trustflow.onKeyboardLock(() => {});
        window.trustflow.onKeyboardUnlock(() => {});
    }
    createTab();
    setInterval(() => refreshStats(), 15000);
})();
