const tabsContainer = document.querySelector('.tabs');
const newTabBtn = document.querySelector('.new-tab');
const browserArea = document.querySelector('.browser');
const backBtn = document.getElementById('back');
const forwardBtn = document.getElementById('forward');
const reloadBtn = document.getElementById('reload');
const goBtn = document.getElementById('go');
const urlInput = document.getElementById('url');
const bookmarkBtn = document.getElementById('bookmark');
const settingsBtn = document.getElementById('settings');

let tabs = [];
let activeTabId = 0;

function createTab(url = 'https://www.google.com') {
    const tabId = Date.now();

    const tabDiv = document.createElement('div');
    tabDiv.classList.add('tab');
    tabDiv.dataset.id = tabId;
    tabDiv.innerHTML = `<i class="fa-solid fa-globe"></i> New Tab <span class="close">&times;</span>`;
    tabsContainer.insertBefore(tabDiv, newTabBtn);

    const webview = document.createElement('webview');
    webview.src = url;
    webview.dataset.id = tabId;
    webview.style.width = '100%';
    webview.style.height = '100%';
    browserArea.appendChild(webview);

    tabs.push({ id: tabId, tabDiv, webview });

    setActiveTab(tabId);

    tabDiv.addEventListener('click', () => setActiveTab(tabId));

    tabDiv.querySelector('.close').addEventListener('click', e => {
        e.stopPropagation();
        closeTab(tabId);
    });

    webview.addEventListener('did-navigate', () => {
        if (activeTabId === tabId) urlInput.value = webview.src;
    });

    webview.addEventListener('did-navigate-in-page', () => {
        if (activeTabId === tabId) urlInput.value = webview.src;
    });
}

function setActiveTab(tabId) {
    tabs.forEach(t => {
        if (t.id === tabId) {
            t.tabDiv.classList.add('active');
            t.webview.style.display = 'block';
            urlInput.value = t.webview.src;
            activeTabId = tabId;
        } else {
            t.tabDiv.classList.remove('active');
            t.webview.style.display = 'none';
        }
    });
}

function getActiveWebview() {
    return tabs.find(t => t.id === activeTabId)?.webview;
}

function closeTab(tabId) {
    const index = tabs.findIndex(t => t.id === tabId);
    if (index !== -1) {
        const tab = tabs[index];
        tab.tabDiv.remove();
        tab.webview.remove();
        tabs.splice(index, 1);
        if (activeTabId === tabId && tabs.length) setActiveTab(tabs[0].id);
    }
}

backBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (w && w.canGoBack()) w.goBack();
});
forwardBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (w && w.canGoForward()) w.goForward();
});
reloadBtn.addEventListener('click', () => { const w = getActiveWebview(); if (w) w.reload(); });
goBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (!w) return;
    let url = urlInput.value.trim(); if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
    w.src = url;
});
urlInput.addEventListener('keydown', e => { if (e.key === 'Enter') goBtn.click(); });

newTabBtn.addEventListener('click', () => createTab());

bookmarkBtn.addEventListener('click', () => {
    const w = getActiveWebview(); if (!w) return;
    let bookmarks = JSON.parse(localStorage.getItem('bookmarks') || '[]');
    if (!bookmarks.includes(w.src)) bookmarks.push(w.src);
    localStorage.setItem('bookmarks', JSON.stringify(bookmarks));
    alert('Bookmark added!');
});

settingsBtn.addEventListener('click', () => alert('Settings placeholder'));

createTab();