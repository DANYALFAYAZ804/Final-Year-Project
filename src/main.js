import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import https from 'https';
import * as configStore from './config-store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ──────────────────────────────────────────────
// Whitelist of known authentic domains
// ──────────────────────────────────────────────
const WHITELIST_DOMAINS = new Set([
    'google.com','youtube.com','facebook.com','wikipedia.org','twitter.com',
    'instagram.com','linkedin.com','reddit.com','amazon.com','yahoo.com',
    'microsoft.com','apple.com','netflix.com','github.com','stackoverflow.com',
    'twitch.tv','pinterest.com','tumblr.com','wordpress.com','blogspot.com',
    'bbc.com','bbc.co.uk','cnn.com','nytimes.com','theguardian.com',
    'reuters.com','forbes.com','bloomberg.com','wsj.com','techcrunch.com',
    'wired.com','medium.com','quora.com','discord.com','slack.com',
    'zoom.us','dropbox.com','notion.so','trello.com','asana.com',
    'spotify.com','soundcloud.com','hulu.com','disneyplus.com',
    'paypal.com','stripe.com','ebay.com','etsy.com','shopify.com',
    'adobe.com','salesforce.com','oracle.com','ibm.com','cisco.com',
    'cloudflare.com','godaddy.com','namecheap.com','digitalocean.com',
    'heroku.com','vercel.com','netlify.com',
    'npmjs.com','pypi.org','huggingface.co','kaggle.com',
    'arxiv.org','python.org','nodejs.org',
    'reactjs.org','vuejs.org','angular.io','tailwindcss.com',
    'docker.com','kubernetes.io','w3schools.com','developer.mozilla.org',
    'fonts.google.com','unsplash.com','imdb.com','steampowered.com',
    'epicgames.com','xbox.com','nintendo.com','playstation.com',
    'wolframalpha.com','mathworks.com','tableau.com','aws.amazon.com',
    'cloud.google.com','azure.microsoft.com','firebase.google.com',
    'scholar.google.com','maps.google.com','drive.google.com',
]);

const SUSPICIOUS_PATH_WORDS = ['login','signin','verify','account','password','banking','payment'];

function isWhitelisted(url) {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
        const path = parsed.pathname.toLowerCase();
        const parts = hostname.split('.');
        const base = parts.length >= 2 ? parts.slice(-2).join('.') : hostname;
        if (!WHITELIST_DOMAINS.has(hostname) && !WHITELIST_DOMAINS.has(base)) return false;
        if (SUSPICIOUS_PATH_WORDS.some(w => path.includes(w))) return false;
        return true;
    } catch (_) {
        return false;
    }
}

// ──────────────────────────────────────────────
// Stats tracking
// ──────────────────────────────────────────────
let statsScanned = 0;
let statsBlocked = 0;

// ──────────────────────────────────────────────
// WHOIS cache  { domain -> { score, ts } }
// ──────────────────────────────────────────────
const whoisCache = new Map();
const WHOIS_TTL_MS = 10 * 60 * 1000;

// ──────────────────────────────────────────────
// ML service URL — now points at the Railway-hosted backend.
// Can still be overridden with the ML_SERVICE_URL env var
// (e.g. for local development against a locally-run backend).
// ──────────────────────────────────────────────
const ML_SERVICE_URL = process.env.ML_SERVICE_URL
    || 'https://final-year-project-production-9edf.up.railway.app';

let mlReady = false;

function startMlService() {
    console.log(`[ML] Using remote ML service at ${ML_SERVICE_URL}`);
    probeMLHealth();
}

function probeMLHealth(retries = 10, delayMs = 2000) {
    httpGet(`${ML_SERVICE_URL}/health`).then(res => {
        if (res.status === 200) {
            mlReady = true;
            console.log('[ML] Remote service healthy:', res.body);
        } else if (retries > 0) {
            setTimeout(() => probeMLHealth(retries - 1, delayMs), delayMs);
        }
    }).catch(() => {
        if (retries > 0) setTimeout(() => probeMLHealth(retries - 1, delayMs), delayMs);
        else console.error('[ML] Remote service unreachable after retries.');
    });
}

// ──────────────────────────────────────────────
// Helper: HTTP request → JSON
// ──────────────────────────────────────────────
function httpPost(url, body) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(body);
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.request({
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname,
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
            timeout: 3000,
        }, (res) => {
            let buf = '';
            res.on('data', (c) => buf += c);
            res.on('end', () => {
                try { resolve(JSON.parse(buf)); } catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.write(data);
        req.end();
    });
}

function httpGet(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        const req = lib.request({
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + (parsed.search || ''),
            method: 'GET',
            headers,
            timeout: 5000,
        }, (res) => {
            let buf = '';
            res.on('data', (c) => buf += c);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(buf) }); }
                catch (e) { reject(e); }
            });
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
        req.end();
    });
}

// ──────────────────────────────────────────────
// ML Classifier — calls the Railway-hosted /predict endpoint
// ──────────────────────────────────────────────
async function checkWebsite(url) {
    const response = await fetch(`${ML_SERVICE_URL}/predict`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
    });

    return await response.json();
}

async function scoreML(url) {
    if (!mlReady) return 0.5;
    try {
        const result = await checkWebsite(url);
        return typeof result.score === 'number' ? result.score : 0.5;
    } catch (_) { return 0.5; }
}

// ──────────────────────────────────────────────
// WHOIS Domain Intelligence
// ──────────────────────────────────────────────
function extractDomain(url) {
    try { return new URL(url).hostname; } catch (_) { return url; }
}

async function scoreWHOIS(url) {
    const domain = extractDomain(url);
    const now = Date.now();
    if (whoisCache.has(domain)) {
        const cached = whoisCache.get(domain);
        if (now - cached.ts < WHOIS_TTL_MS) return cached.score;
    }
    try {
        const rdapUrl = `https://rdap.org/domain/${domain}`;
        const res = await httpGet(rdapUrl);
        if (res.status !== 200) throw new Error('RDAP error');
        const events = res.body.events || [];
        const regEvent = events.find(e => e.eventAction === 'registration');
        let score = 0.5;
        if (regEvent) {
            const ageDays = (now - new Date(regEvent.eventDate).getTime()) / (1000 * 60 * 60 * 24);
            if (ageDays < 30) score = 0.1;
            else if (ageDays < 180) score = 0.5;
            else score = 0.9;
        }
        whoisCache.set(domain, { score, ts: now });
        return score;
    } catch (_) {
        whoisCache.set(domain, { score: 0.5, ts: now });
        return 0.5;
    }
}

// ──────────────────────────────────────────────
// VirusTotal
// ──────────────────────────────────────────────
async function scoreVirusTotal(url) {
    const apiKey = configStore.get('vtApiKey');
    if (!apiKey) return 0.5;

    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const headers = { 'x-apikey': apiKey };

    async function fetchResult() {
        const res = await httpGet(`https://www.virustotal.com/api/v3/urls/${urlId}`, headers);
        if (res.status === 200) {
            const stats = res.body?.data?.attributes?.last_analysis_stats || {};
            const malicious = (stats.malicious || 0) + (stats.suspicious || 0);
            const total = Object.values(stats).reduce((a, b) => a + b, 0);
            return total > 0 ? Math.max(0, 1 - malicious / total) : 0.5;
        }
        return null;
    }

    try {
        let score = await fetchResult();
        if (score !== null) return score;
        await httpPost('https://www.virustotal.com/api/v3/urls', { url });
        await new Promise(r => setTimeout(r, 2000));
        for (let i = 0; i < 3; i++) {
            score = await fetchResult();
            if (score !== null) return score;
            await new Promise(r => setTimeout(r, 2000));
        }
        return 0.5;
    } catch (_) { return 0.5; }
}

// ──────────────────────────────────────────────
// Trust Score Engine
// ──────────────────────────────────────────────
async function computeTrustScore(url, settings) {
    if (isWhitelisted(url)) {
        return {
            score: 100,
            verdict: 'safe',
            details: { ml: 100, whois: 100, virustotal: 100, domain: extractDomain(url) },
        };
    }

    const [mlScore, whoisScore, vtScore] = await Promise.all([
        settings.mlEnabled !== false ? scoreML(url) : Promise.resolve(0.5),
        settings.whoisEnabled !== false ? scoreWHOIS(url) : Promise.resolve(0.5),
        scoreVirusTotal(url),
    ]);

    const weighted = (mlScore * 0.50) + (vtScore * 0.35) + (whoisScore * 0.15);
    const finalScore = Math.round(weighted * 100);

    let verdict;
    if (finalScore >= 75) verdict = 'safe';
    else if (finalScore >= 40) verdict = 'suspicious';
    else verdict = 'malicious';

    return {
        score: finalScore,
        verdict,
        details: {
            ml: Math.round(mlScore * 100),
            whois: Math.round(whoisScore * 100),
            virustotal: Math.round(vtScore * 100),
            domain: extractDomain(url),
        },
    };
}

// ──────────────────────────────────────────────
// Default settings
// ──────────────────────────────────────────────
function getSettings() {
    return {
        mlEnabled: configStore.get('mlEnabled') !== 'false',
        whoisEnabled: configStore.get('whoisEnabled') !== 'false',
        badgeVisible: configStore.get('badgeVisible') !== 'false',
        vtApiKey: configStore.get('vtApiKey') || '',
    };
}

// ──────────────────────────────────────────────
// Electron App
// ──────────────────────────────────────────────
let mainWindow = null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        icon: path.join(app.getAppPath(), 'Images', 'Trust-Flow-logo.png'),
        autoHideMenuBar: true,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            contextIsolation: true,
            nodeIntegration: false,
            enableRemoteModule: false,
            webviewTag: true,
        },
    });

    mainWindow.setAlwaysOnTop(true, 'screen');

    if (typeof MAIN_WINDOW_VITE_DEV_SERVER_URL !== 'undefined' && MAIN_WINDOW_VITE_DEV_SERVER_URL) {
        mainWindow.loadURL(MAIN_WINDOW_VITE_DEV_SERVER_URL);
    } else if (typeof MAIN_WINDOW_VITE_NAME !== 'undefined') {
        mainWindow.loadFile(path.join(__dirname, `../renderer/${MAIN_WINDOW_VITE_NAME}/index.html`));
    } else {
        mainWindow.loadFile(path.join(app.getAppPath(), 'index.html'));
    }
}

// ──────────────────────────────────────────────
// IPC Handlers
// ──────────────────────────────────────────────
ipcMain.handle('scan-url', async (event, url) => {
    const settings = getSettings();
    statsScanned++;
    const result = await computeTrustScore(url, settings);
    if (result.verdict === 'malicious') statsBlocked++;
    if (mainWindow) {
        if (result.verdict !== 'safe') {
            mainWindow.webContents.send('keyboard-lock', result);
        } else {
            mainWindow.webContents.send('keyboard-unlock', result);
        }
    }
    return result;
});

ipcMain.handle('get-settings', () => getSettings());

ipcMain.handle('save-settings', (event, settings) => {
    if ('vtApiKey' in settings) configStore.set('vtApiKey', settings.vtApiKey, true);
    if ('mlEnabled' in settings) configStore.set('mlEnabled', String(settings.mlEnabled));
    if ('whoisEnabled' in settings) configStore.set('whoisEnabled', String(settings.whoisEnabled));
    if ('badgeVisible' in settings) configStore.set('badgeVisible', String(settings.badgeVisible));
    return true;
});

ipcMain.handle('clear-cache', () => { whoisCache.clear(); return true; });
ipcMain.handle('get-stats', () => ({ scanned: statsScanned, blocked: statsBlocked }));

// ──────────────────────────────────────────────
// App lifecycle
// ──────────────────────────────────────────────
app.whenReady().then(() => {
    startMlService();
    createWindow();
    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });