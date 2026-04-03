// ─────────────────────────────────────────────────────────────────────────────
// Trust-Flow Renderer — Full Security UI + Browser Logic
// ─────────────────────────────────────────────────────────────────────────────

// ──── DOM refs ────
const tabsContainer   = document.querySelector('.tabs');
const newTabBtn       = document.querySelector('.new-tab');
const browserArea     = document.querySelector('.browser');
const backBtn         = document.getElementById('back');
const forwardBtn      = document.getElementById('forward');
const reloadBtn       = document.getElementById('reload');
const goBtn           = document.getElementById('go');
const urlInput        = document.getElementById('url');
const bookmarkBtn     = document.getElementById('bookmark');
const settingsBtn     = document.getElementById('settings');
const shieldIcon      = document.getElementById('shield-icon');
const shieldLabel     = document.getElementById('shield-label');
const shieldTooltip   = document.getElementById('shield-tooltip');
const settingsPanel   = document.getElementById('settings-panel');
const closePanelBtn   = document.getElementById('close-panel');
const scanSpinner     = document.getElementById('scan-spinner');
const statsScanned    = document.getElementById('stats-scanned');
const statsBlocked    = document.getElementById('stats-blocked');

// ──── State ────
let tabs = [];
let activeTabId = 0;
let keyboardLocked = false;
let lockHandler = null;
let currentVerdict = null;
let settings = {};

// ─────────────────────────────────────────────────────────────────────────────
// Tab Management
// ─────────────────────────────────────────────────────────────────────────────
function createTab(url = null) {
    const tabId = Date.now();

    const tabDiv = document.createElement('div');
    tabDiv.classList.add('tab');
    tabDiv.dataset.id = tabId;
    tabDiv.innerHTML = `<i class="fa-solid fa-globe"></i> <span class="tab-title">New Tab</span> <span class="close">&times;</span>`;
    tabsContainer.insertBefore(tabDiv, newTabBtn);

    // If no url: show new tab page inside an iframe-less div
    if (!url) {
        const page = buildNewTabPage();
        page.dataset.id = tabId;
        browserArea.appendChild(page);
        tabs.push({ id: tabId, tabDiv, webview: null, page, url: '' });
        setActiveTab(tabId);
        tabDiv.addEventListener('click', () => setActiveTab(tabId));
        tabDiv.querySelector('.close').addEventListener('click', e => { e.stopPropagation(); closeTab(tabId); });
        return;
    }

    const webview = document.createElement('webview');
    webview.src = 'about:blank';
    webview.dataset.id = tabId;
    webview.style.cssText = 'width:100%;height:100%;border:none;display:none;';
    browserArea.appendChild(webview);

    tabs.push({ id: tabId, tabDiv, webview, page: null, url });
    setActiveTab(tabId);

    tabDiv.addEventListener('click', () => setActiveTab(tabId));
    tabDiv.querySelector('.close').addEventListener('click', e => { e.stopPropagation(); closeTab(tabId); });

    webview.addEventListener('did-navigate', () => {
        if (activeTabId === tabId) {
            urlInput.value = webview.src;
            const t = tabs.find(t => t.id === tabId);
            if (t) t.url = webview.src;
        }
    });
    webview.addEventListener('did-navigate-in-page', () => {
        if (activeTabId === tabId) urlInput.value = webview.src;
    });
    webview.addEventListener('page-title-updated', (e) => {
        tabDiv.querySelector('.tab-title').textContent = e.title?.slice(0, 20) || 'Tab';
    });

    // Navigate after registration
    navigateTo(url, tabId);
}

function buildNewTabPage() {
    const div = document.createElement('div');
    div.className = 'newtab-page';
    div.style.display = 'none';
    div.innerHTML = `
        <img src="Images/Gemini_3.png" class="center-logo" alt="Trust-Flow">
        <h1>Trust-Flow</h1>
        <p class="newtab-tagline">Zero-Trust AI Browser</p>
        <div class="newtab-search">
            <input type="text" id="newtab-url-input" placeholder="Search Google or type a URL" class="search" autocomplete="off">
            <button id="newtab-go"><i class="fa-solid fa-magnifying-glass"></i></button>
        </div>
        <div class="newtab-stats">
            <div class="stat-card"><i class="fa-solid fa-shield-halved"></i><span id="nt-scanned">0</span><small>Sites Scanned</small></div>
            <div class="stat-card danger"><i class="fa-solid fa-skull-crossbones"></i><span id="nt-blocked">0</span><small>Threats Blocked</small></div>
        </div>
        <div class="newtab-bookmarks" id="newtab-bookmarks"></div>
    `;
    setTimeout(() => {
        renderNewtabBookmarks(div);
        refreshStats(div);
        const ntInput = div.querySelector('#newtab-url-input');
        const ntGo = div.querySelector('#newtab-go');
        const go = () => {
            let val = ntInput.value.trim();
            if (!val) return;
            if (!/^https?:\/\//i.test(val)) val = 'https://' + val;
            navigateTo(val, activeTabId);
        };
        ntGo.addEventListener('click', go);
        ntInput.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
    }, 50);
    return div;
}

function renderNewtabBookmarks(container) {
    const bm = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    const bmDiv = container.querySelector('#newtab-bookmarks');
    if (!bmDiv || !bm.length) return;
    bmDiv.innerHTML = '<p class="bm-title">Bookmarks</p>' + bm.map(u =>
        `<a class="bm-chip" href="#" data-url="${u}">${new URL(u).hostname}</a>`
    ).join('');
    bmDiv.querySelectorAll('.bm-chip').forEach(a => {
        a.addEventListener('click', e => { e.preventDefault(); navigateTo(a.dataset.url, activeTabId); });
    });
}

async function refreshStats(container = null) {
    if (!window.trustflow) return;
    const st = await window.trustflow.getStats();
    if (statsScanned) statsScanned.textContent = st.scanned;
    if (statsBlocked) statsBlocked.textContent = st.blocked;
    if (container) {
        const sc = container.querySelector('#nt-scanned');
        const bl = container.querySelector('#nt-blocked');
        if (sc) sc.textContent = st.scanned;
        if (bl) bl.textContent = st.blocked;
    }
}

function setActiveTab(tabId) {
    tabs.forEach(t => {
        const isActive = t.id === tabId;
        t.tabDiv.classList.toggle('active', isActive);
        if (t.webview) t.webview.style.display = isActive ? 'block' : 'none';
        if (t.page) t.page.style.display = isActive ? 'flex' : 'none';
        if (isActive) {
            urlInput.value = t.url || '';
            activeTabId = tabId;
        }
    });
    unlockKeyboard();
    resetShield();
}

function getActiveTab() { return tabs.find(t => t.id === activeTabId); }
function getActiveWebview() { return getActiveTab()?.webview; }

function closeTab(tabId) {
    const index = tabs.findIndex(t => t.id === tabId);
    if (index === -1) return;
    const tab = tabs[index];
    tab.tabDiv.remove();
    if (tab.webview) tab.webview.remove();
    if (tab.page) tab.page.remove();
    tabs.splice(index, 1);
    if (activeTabId === tabId && tabs.length) setActiveTab(tabs[Math.max(0, index - 1)].id);
    if (!tabs.length) createTab();
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation with Security Scanning
// ─────────────────────────────────────────────────────────────────────────────
async function navigateTo(rawUrl, tabId) {
    let url = rawUrl.trim();
    if (!url) return;

    // Search query?
    if (!/^https?:\/\//i.test(url) && !url.includes('.')) {
        url = 'https://www.google.com/search?q=' + encodeURIComponent(url);
    } else if (!/^https?:\/\//i.test(url)) {
        url = 'https://' + url;
    }

    urlInput.value = url;
    showScanning();

    let result;
    try {
        result = await window.trustflow.scanUrl(url);
    } catch (e) {
        result = { score: 50, verdict: 'safe', details: { ml: 50, whois: 50, virustotal: 50, domain: '' } };
    }

    hideScanning();
    updateShield(result);
    refreshStats();

    const tab = tabs.find(t => t.id === tabId);
    if (!tab) return;

    // Hide new tab page if it was shown
    if (tab.page) {
        tab.page.style.display = 'none';
        tab.page = null;
    }

    if (result.verdict === 'malicious') {
        lockKeyboard(result);
        showBlockPage(result, url, tabId);
    } else if (result.verdict === 'suspicious') {
        showWarningOverlay(result, url, tabId);
    } else {
        unlockKeyboard();
        removeOverlays();
        if (tab.webview) {
            tab.webview.src = url;
            tab.webview.style.display = 'block';
        } else {
            // Create webview for this tab
            const webview = document.createElement('webview');
            webview.src = url;
            webview.dataset.id = tabId;
            webview.style.cssText = 'width:100%;height:100%;border:none;';
            browserArea.appendChild(webview);
            tab.webview = webview;
            webview.addEventListener('did-navigate', () => {
                if (activeTabId === tabId) urlInput.value = webview.src;
            });
            webview.addEventListener('page-title-updated', (e) => {
                tab.tabDiv.querySelector('.tab-title').textContent = e.title?.slice(0, 20) || 'Tab';
            });
        }
        tab.url = url;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shield Badge
// ─────────────────────────────────────────────────────────────────────────────
function showScanning() {
    if (scanSpinner) scanSpinner.style.display = 'block';
    if (shieldIcon) { shieldIcon.className = 'fa-solid fa-shield-halved shield-scanning'; }
    if (shieldLabel) shieldLabel.textContent = 'Scanning...';
}

function hideScanning() {
    if (scanSpinner) scanSpinner.style.display = 'none';
}

function updateShield(result) {
    if (!shieldIcon || !shieldLabel) return;
    if (settings.badgeVisible === false) { shieldIcon.style.display = 'none'; return; }
    shieldIcon.style.display = '';

    const { score, verdict, details } = result;
    shieldIcon.className = 'fa-solid fa-shield-halved';
    if (verdict === 'safe') {
        shieldIcon.classList.add('shield-safe');
        shieldLabel.textContent = `Safe (${score})`;
    } else if (verdict === 'suspicious') {
        shieldIcon.classList.add('shield-warn');
        shieldLabel.textContent = `Warning (${score})`;
    } else {
        shieldIcon.classList.add('shield-danger');
        shieldLabel.textContent = `Blocked (${score})`;
    }

    if (shieldTooltip) {
        shieldTooltip.innerHTML = `
            <b>${details.domain}</b><br>
            Trust Score: <b>${score}/100</b><br>
            ML Classifier: ${details.ml}/100<br>
            VirusTotal: ${details.virustotal}/100<br>
            Domain Intelligence: ${details.whois}/100
        `;
    }
}

function resetShield() {
    if (!shieldIcon || !shieldLabel) return;
    shieldIcon.className = 'fa-solid fa-shield-halved shield-neutral';
    shieldLabel.textContent = '';
}

// ─────────────────────────────────────────────────────────────────────────────
// Warning Overlay (Suspicious)
// ─────────────────────────────────────────────────────────────────────────────
function removeOverlays() {
    document.querySelectorAll('.tf-overlay').forEach(el => el.remove());
}

function showWarningOverlay(result, url, tabId) {
    removeOverlays();
    lockKeyboard(result);

    const overlay = document.createElement('div');
    overlay.className = 'tf-overlay tf-warning-overlay';
    overlay.innerHTML = `
        <div class="overlay-card">
            <i class="fa-solid fa-triangle-exclamation overlay-icon warn-icon"></i>
            <h2>Suspicious Website Detected</h2>
            <p>This site shows signs of phishing. Keyboard input is restricted to protect your credentials.</p>
            <div class="score-details">
                <div class="score-item"><span>Trust Score</span><b>${result.score}/100</b></div>
                <div class="score-item"><span>ML Analysis</span><b>${result.details.ml}/100</b></div>
                <div class="score-item"><span>VirusTotal</span><b>${result.details.virustotal}/100</b></div>
                <div class="score-item"><span>Domain Age</span><b>${result.details.whois}/100</b></div>
            </div>
            <p class="domain-label"><i class="fa-solid fa-globe"></i> ${result.details.domain}</p>
            <div class="overlay-actions">
                <button class="btn-back"><i class="fa-solid fa-arrow-left"></i> Go Back to Safety</button>
                <button class="btn-proceed"><i class="fa-solid fa-triangle-exclamation"></i> Proceed Anyway</button>
            </div>
        </div>
    `;
    browserArea.appendChild(overlay);

    overlay.querySelector('.btn-back').addEventListener('click', () => {
        removeOverlays();
        unlockKeyboard();
        resetShield();
        const w = getActiveWebview();
        if (w && w.canGoBack()) w.goBack(); else createTab();
    });
    overlay.querySelector('.btn-proceed').addEventListener('click', () => {
        removeOverlays();
        unlockKeyboard();
        const tab = tabs.find(t => t.id === tabId);
        if (tab) {
            if (!tab.webview) {
                const webview = document.createElement('webview');
                webview.src = url;
                webview.dataset.id = tabId;
                webview.style.cssText = 'width:100%;height:100%;border:none;';
                browserArea.appendChild(webview);
                tab.webview = webview;
            } else {
                tab.webview.src = url;
                tab.webview.style.display = 'block';
            }
            tab.url = url;
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Block Page (Malicious)
// ─────────────────────────────────────────────────────────────────────────────
function showBlockPage(result, url, tabId) {
    removeOverlays();

    // Hide webview entirely
    const tab = tabs.find(t => t.id === tabId);
    if (tab && tab.webview) tab.webview.style.display = 'none';

    const overlay = document.createElement('div');
    overlay.className = 'tf-overlay tf-block-overlay';
    overlay.innerHTML = `
        <div class="overlay-card danger-card">
            <i class="fa-solid fa-shield-virus overlay-icon danger-icon"></i>
            <h2>Phishing Attack Blocked</h2>
            <p>This website was identified as malicious. Navigation has been prevented and keyboard input is locked.</p>
            <div class="score-details">
                <div class="score-item bad"><span>Trust Score</span><b>${result.score}/100</b></div>
                <div class="score-item bad"><span>ML Confidence</span><b>${100 - result.details.ml}% phishing</b></div>
                <div class="score-item bad"><span>VirusTotal</span><b>${result.details.virustotal}/100</b></div>
                <div class="score-item bad"><span>Domain Age</span><b>${result.details.whois}/100</b></div>
            </div>
            <p class="domain-label danger-label"><i class="fa-solid fa-skull-crossbones"></i> ${result.details.domain}</p>
            <p class="blocked-url">${url.slice(0, 80)}${url.length > 80 ? '...' : ''}</p>
            <div class="overlay-actions">
                <button class="btn-back-danger"><i class="fa-solid fa-arrow-left"></i> Go Back to Safety</button>
            </div>
        </div>
    `;
    browserArea.appendChild(overlay);

    overlay.querySelector('.btn-back-danger').addEventListener('click', () => {
        removeOverlays();
        unlockKeyboard();
        resetShield();
        if (tab && tab.webview) tab.webview.style.display = 'block';
        const w = getActiveWebview();
        if (w && w.canGoBack()) w.goBack(); else createTab();
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// Keyboard Locking
// ─────────────────────────────────────────────────────────────────────────────
function lockKeyboard(result) {
    keyboardLocked = true;
    urlInput.disabled = true;
    urlInput.style.opacity = '0.4';

    // Lock input inside webview
    const wv = getActiveWebview();
    if (wv) {
        try {
            wv.executeJavaScript(`
                (function() {
                    if (window.__tf_locked) return;
                    window.__tf_locked = true;
                    const style = document.createElement('style');
                    style.id = '__tf_lock_style';
                    style.textContent = 'input:focus, textarea:focus, [contenteditable]:focus { outline: 3px solid #ef4444 !important; box-shadow: 0 0 12px #ef444480 !important; }';
                    document.head.appendChild(style);
                    window.__tf_lockHandler = function(e) {
                        const tag = e.target.tagName;
                        if (['INPUT','TEXTAREA'].includes(tag) || e.target.isContentEditable) {
                            e.preventDefault(); e.stopImmediatePropagation();
                        }
                    };
                    document.addEventListener('keydown', window.__tf_lockHandler, true);
                    document.addEventListener('keypress', window.__tf_lockHandler, true);
                    document.addEventListener('input', window.__tf_lockHandler, true);
                })();
            `).catch(() => {});
        } catch (_) {}
    }
}

function unlockKeyboard() {
    keyboardLocked = false;
    urlInput.disabled = false;
    urlInput.style.opacity = '';

    const wv = getActiveWebview();
    if (wv) {
        try {
            wv.executeJavaScript(`
                (function() {
                    if (!window.__tf_locked) return;
                    window.__tf_locked = false;
                    document.removeEventListener('keydown', window.__tf_lockHandler, true);
                    document.removeEventListener('keypress', window.__tf_lockHandler, true);
                    document.removeEventListener('input', window.__tf_lockHandler, true);
                    const s = document.getElementById('__tf_lock_style');
                    if (s) s.remove();
                })();
            `).catch(() => {});
        } catch (_) {}
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPC — keyboard lock events from main process
// ─────────────────────────────────────────────────────────────────────────────
if (window.trustflow) {
    window.trustflow.onKeyboardLock((data) => { /* handled per-navigate */ });
    window.trustflow.onKeyboardUnlock((data) => { /* handled per-navigate */ });
}

// ─────────────────────────────────────────────────────────────────────────────
// Navigation Controls
// ─────────────────────────────────────────────────────────────────────────────
backBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (w && w.canGoBack()) { removeOverlays(); unlockKeyboard(); resetShield(); w.goBack(); }
});
forwardBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (w && w.canGoForward()) { removeOverlays(); unlockKeyboard(); resetShield(); w.goForward(); }
});
reloadBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (w) { removeOverlays(); unlockKeyboard(); resetShield(); w.reload(); }
});
goBtn.addEventListener('click', () => { navigateTo(urlInput.value, activeTabId); });
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') goBtn.click(); });
newTabBtn.addEventListener('click', () => createTab());

bookmarkBtn.addEventListener('click', () => {
    const tab = getActiveTab();
    const url = tab?.url;
    if (!url) return;
    let bm = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    if (!bm.includes(url)) bm.push(url);
    localStorage.setItem('bookmarks', JSON.stringify(bm));
    bookmarkBtn.querySelector('i').style.color = '#facc15';
    setTimeout(() => { bookmarkBtn.querySelector('i').style.color = ''; }, 1500);
});

// ─────────────────────────────────────────────────────────────────────────────
// Settings Panel
// ─────────────────────────────────────────────────────────────────────────────
async function loadSettings() {
    if (!window.trustflow) return;
    settings = await window.trustflow.getSettings();
    document.getElementById('vt-key').value = settings.vtApiKey || '';
    document.getElementById('toggle-ml').checked = settings.mlEnabled !== false;
    document.getElementById('toggle-whois').checked = settings.whoisEnabled !== false;
    document.getElementById('toggle-badge').checked = settings.badgeVisible !== false;
}

settingsBtn.addEventListener('click', async () => {
    settingsPanel.classList.toggle('open');
    if (settingsPanel.classList.contains('open')) await loadSettings();
});

closePanelBtn.addEventListener('click', () => settingsPanel.classList.remove('open'));

document.getElementById('save-settings').addEventListener('click', async () => {
    const newSettings = {
        vtApiKey: document.getElementById('vt-key').value.trim(),
        mlEnabled: document.getElementById('toggle-ml').checked,
        whoisEnabled: document.getElementById('toggle-whois').checked,
        badgeVisible: document.getElementById('toggle-badge').checked,
    };
    await window.trustflow.saveSettings(newSettings);
    settings = newSettings;
    settingsPanel.classList.remove('open');
});

document.getElementById('clear-cache').addEventListener('click', async () => {
    await window.trustflow.clearCache();
    const btn = document.getElementById('clear-cache');
    btn.textContent = 'Cleared!';
    setTimeout(() => { btn.textContent = 'Clear Scan Cache'; }, 1500);
});

// ─────────────────────────────────────────────────────────────────────────────
// Init
// ─────────────────────────────────────────────────────────────────────────────
(async function init() {
    if (window.trustflow) {
        settings = await window.trustflow.getSettings().catch(() => ({}));
    }
    createTab();
    setInterval(refreshStats, 10000);
})();
