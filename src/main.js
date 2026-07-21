import { app, BrowserWindow, ipcMain } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';
import https from 'https';
import fs from 'fs';
import * as configStore from './config-store.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ──────────────────────────────────────────────
// Load a project-root .env file (if present) so local overrides
// like BACKEND_URL persist permanently across terminal sessions,
// instead of needing to be set manually every time before `npm start`.
//
// Dev-mode ONLY. Packaged builds used to also bundle a copy of this
// file (via forge.config.js's extraResource) so a local override could
// follow into an installed .msi/.exe — but that created two independent
// .env files that could silently drift out of sync: fixing the source
// .env did nothing for an already-packaged build still reading its own
// stale bundled copy, which looked like the fix hadn't worked at all.
// Packaged builds now always resolve BACKEND_URL from a real OS
// environment variable (if one is explicitly set on that machine) or
// the hardcoded Railway fallback below — never from a bundled file that
// can go stale unnoticed.
// ──────────────────────────────────────────────
function loadDotEnv() {
    if (app.isPackaged) return;
    try {
        // Try several candidate roots: getAppPath() resolves differently
        // depending on how the app was launched (raw `electron .` or
        // bundled via electron-forge's Vite plugin into `.vite/build/`),
        // so check the project root from every angle rather than just one.
        const candidates = [
            process.cwd(),
            path.join(__dirname, '..'),
            path.join(__dirname, '..', '..'),
        ];
        try { candidates.push(app.getAppPath()); } catch (_) {}

        let envPath = null;
        for (const dir of candidates) {
            const candidate = path.join(dir, '.env');
            if (fs.existsSync(candidate)) { envPath = candidate; break; }
        }
        if (!envPath) return;

        const lines = fs.readFileSync(envPath, 'utf8').split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eq = trimmed.indexOf('=');
            if (eq === -1) continue;
            const key = trimmed.slice(0, eq).trim();
            let value = trimmed.slice(eq + 1).trim();
            if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
                value = value.slice(1, -1);
            }
            if (!(key in process.env)) process.env[key] = value;
        }
    } catch (_) { /* ignore — falls back to defaults / real env vars */ }
}
loadDotEnv();

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
// Backend base URL — the single source of truth for BOTH the ML scoring
// endpoints (/predict, /health) and the auth endpoints (/auth/*). These
// were already governed by one constant, but it was named ML_SERVICE_URL,
// which reads as "only affects ML scoring" — that misleading name is what
// made a URL mismatch look like the likely cause when auth started
// failing. There has only ever been one backend URL; keep it that way and
// name it accordingly so this class of confusion can't happen again.
//
// Overridden via BACKEND_URL in the project's .env file (loaded above) or
// a real env var. ML_SERVICE_URL is still honored as a fallback so any
// existing deployment config that already sets it keeps working.
// ──────────────────────────────────────────────
const BACKEND_URL = process.env.BACKEND_URL || process.env.ML_SERVICE_URL
    || 'https://final-year-project-production-9edf.up.railway.app';

let mlReady = false;

// The current logged-in session's token, held in memory only (never
// written to disk unless the user also checked "Stay logged in", which
// is handled separately via config-store). This is what lets completed
// scans be attributed to the right account and persisted server-side via
// POST /scan-url, for every logged-in session — not just "Stay logged
// in" ones, since a token is issued on every successful login/signup
// regardless of that checkbox.
let currentSessionToken = null;

function startMlService() {
    console.log(`[Backend] Using backend at ${BACKEND_URL} for both ML scoring and auth.`);
    probeMLHealth();
}

function probeMLHealth(retries = 10, delayMs = 2000) {
    httpGet(`${BACKEND_URL}/health`).then(res => {
        if (res.status === 200) {
            mlReady = true;
            console.log('[ML] Remote service healthy:', res.body);
        } else if (retries > 0) {
            setTimeout(() => probeMLHealth(retries - 1, delayMs), delayMs);
        } else {
            // Giving up here permanently disabled ML scoring for the rest of
            // the session (scoreML() short-circuits to 0.5 while !mlReady),
            // which is a real problem against a free-tier host like Railway
            // that can take longer than the initial burst to wake up from a
            // cold start. Keep retrying slowly in the background instead of
            // stopping forever.
            console.error('[ML] Remote service unreachable after initial retries; retrying periodically in the background.');
            setTimeout(() => probeMLHealth(3, 15000), 15000);
        }
    }).catch(() => {
        if (retries > 0) setTimeout(() => probeMLHealth(retries - 1, delayMs), delayMs);
        else {
            console.error('[ML] Remote service unreachable after initial retries; retrying periodically in the background.');
            setTimeout(() => probeMLHealth(3, 15000), 15000);
        }
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
// Fetch with a per-attempt timeout + retry/backoff, for one-shot
// user-facing requests (auth). This mirrors the retry/backoff idea
// already used by probeMLHealth() for the background ML health check,
// but bounded to a handful of short attempts instead of running
// indefinitely, since a real user is actively waiting on the result
// (a login click) rather than it happening silently on a timer.
// ──────────────────────────────────────────────
function fetchWithTimeout(url, options = {}, timeoutMs = 8000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    return fetch(url, { ...options, signal: controller.signal }).finally(() => clearTimeout(timer));
}

async function fetchJsonWithRetry(url, options, { retries = 2, timeoutMs = 8000, backoffMs = 1500 } = {}) {
    let lastErr;
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const response = await fetchWithTimeout(url, options, timeoutMs);
            return await response.json();
        } catch (e) {
            lastErr = e;
            if (attempt < retries) await new Promise(r => setTimeout(r, backoffMs * (attempt + 1)));
        }
    }
    throw lastErr;
}

// ──────────────────────────────────────────────
// Page Content Inspection — fetches the page's raw HTML (before it's ever
// shown in the webview) and checks for phishing-relevant signals that the
// URL string alone can't reveal: a password field, and how much of the
// page's resources are loaded from other domains. Both feed the ML
// backend's has_password_field / external_resource_ratio parameters,
// which the backend has supported since the start but nothing was ever
// actually sending.
// ──────────────────────────────────────────────
function fetchHtml(url, maxRedirects = 3) {
    return new Promise((resolve) => {
        const attempt = (targetUrl, redirectsLeft) => {
            let parsed;
            try { parsed = new URL(targetUrl); } catch (_) { return resolve(null); }
            const lib = parsed.protocol === 'https:' ? https : http;
            const req = lib.request({
                hostname: parsed.hostname,
                port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
                path: parsed.pathname + (parsed.search || ''),
                method: 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml',
                },
                timeout: 4000,
            }, (res) => {
                if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirectsLeft > 0) {
                    res.resume();
                    const nextUrl = new URL(res.headers.location, targetUrl).toString();
                    attempt(nextUrl, redirectsLeft - 1);
                    return;
                }
                let buf = '';
                let size = 0;
                res.setEncoding('utf8');
                res.on('data', (c) => {
                    size += Buffer.byteLength(c);
                    if (size > 1_500_000) { req.destroy(); return; } // cap ~1.5MB, plenty for head+visible markup
                    buf += c;
                });
                res.on('end', () => resolve({ html: buf, finalUrl: targetUrl }));
            });
            req.on('error', () => resolve(null));
            req.on('timeout', () => { req.destroy(); resolve(null); });
            req.end();
        };
        attempt(url, maxRedirects);
    });
}

function analyzePageContent(html, pageUrl) {
    let pageHost = '';
    try { pageHost = new URL(pageUrl).hostname.replace(/^www\./, ''); } catch (_) {}

    const hasPasswordField = /<input\b[^>]*\btype\s*=\s*["']?password["']?[^>]*>/i.test(html) ? 1 : 0;

    const resourceRegex = /<(?:script|img|iframe)\b[^>]*\bsrc\s*=\s*["']([^"']+)["']|<link\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi;
    let match;
    let total = 0;
    let external = 0;
    while ((match = resourceRegex.exec(html)) !== null) {
        const ref = match[1] || match[2];
        if (!ref || ref.startsWith('data:') || ref.startsWith('#')) continue;
        total++;
        try {
            const refHost = new URL(ref, pageUrl).hostname.replace(/^www\./, '');
            if (refHost && refHost !== pageHost) external++;
        } catch (_) { /* relative or malformed — treat as same-origin, don't count */ }
    }
    const externalResourceRatio = total > 0 ? Math.round((external / total) * 100) / 100 : 0;

    return { hasPasswordField, externalResourceRatio };
}

async function inspectPage(url) {
    const result = await fetchHtml(url);
    if (!result || !result.html) return { hasPasswordField: 0, externalResourceRatio: 0 };
    return analyzePageContent(result.html, result.finalUrl || url);
}

// ──────────────────────────────────────────────
// ML Classifier — calls the Railway-hosted /predict endpoint
// ──────────────────────────────────────────────
async function checkWebsite(url, signals = {}) {
    const response = await fetch(`${BACKEND_URL}/predict`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url,
            has_password_field: signals.hasPasswordField || 0,
            external_resource_ratio: signals.externalResourceRatio || 0,
            force_scan: (signals.hasPasswordField || 0) === 1, // ensure backend doesn't skip scoring on a whitelisted-looking domain when a password field is present
        }),
    });

    return await response.json();
}

async function scoreML(url, signals) {
    if (!mlReady) return 0.5;
    try {
        const result = await checkWebsite(url, signals);
        return typeof result.score === 'number' ? result.score : 0.5;
    } catch (_) { return 0.5; }
}

// ──────────────────────────────────────────────
// Auth — check-email / signup / login / session-validation against the
// backend's user database. Each uses fetchJsonWithRetry so a single slow
// or dropped connection attempt (e.g. Railway waking from a cold start)
// doesn't surface as an immediate hard failure to the user.
// ──────────────────────────────────────────────
async function authCheckEmail(email) {
    return fetchJsonWithRetry(`${BACKEND_URL}/auth/check-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
    });
}

async function authSignup(email, fullName, password) {
    return fetchJsonWithRetry(`${BACKEND_URL}/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, full_name: fullName, password }),
    });
}

async function authLogin(email, password) {
    return fetchJsonWithRetry(`${BACKEND_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });
}

async function authValidateSession(token) {
    // A shorter, lighter retry budget than the other auth calls — this
    // one runs silently at app launch (before any UI is shown), so it
    // shouldn't hold up startup as long as a user-initiated login click can.
    return fetchJsonWithRetry(`${BACKEND_URL}/auth/validate-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: token }),
    }, { retries: 1, timeoutMs: 6000, backoffMs: 1000 });
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
    // Inspect the page's actual HTML first — a password field on an
    // otherwise-clean-looking domain (e.g. Google's own Safe Browsing test
    // page, or any compromised/free hosting page) should never get a free
    // pass just because the domain or URL string looks harmless.
    const signals = await inspectPage(url).catch(() => ({ hasPasswordField: 0, externalResourceRatio: 0 }));

    if (isWhitelisted(url) && signals.hasPasswordField !== 1) {
        return {
            score: 100,
            verdict: 'safe',
            details: { ml: 100, whois: 100, virustotal: 100, domain: extractDomain(url) },
        };
    }

    const [mlScore, whoisScore, vtScore] = await Promise.all([
        settings.mlEnabled !== false ? scoreML(url, signals) : Promise.resolve(0.5),
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

// Icon lives in src/assets, which Vite doesn't automatically carry into the
// packaged output. In dev it's read straight from the project's src/ folder;
// once packaged, forge.config.js's `extraResource: ['src/assets']` copies it
// into the app's resources folder instead, so we read it from there.
function getAssetPath(filename) {
    if (app.isPackaged) {
        return path.join(process.resourcesPath, 'assets', filename);
    }
    return path.join(__dirname, '..', '..', 'src', 'assets', filename);
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1400,
        height: 900,
        icon: getAssetPath('Trust-Flow-logo.png'),
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

// Best-effort persistence of a completed scan under the logged-in
// account. Fire-and-forget: a DB hiccup on the backend must never block
// or slow down browsing, so this is never awaited by the scan-url
// handler below and any failure is only logged, not surfaced to the UI.
function saveScanRecord(url, result) {
    if (!currentSessionToken) return; // not logged in this run — nothing to attribute it to
    fetchJsonWithRetry(`${BACKEND_URL}/scan-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            session_token: currentSessionToken,
            url,
            verdict: result.verdict,
            threat_score: result.score,
        }),
    }, { retries: 1, timeoutMs: 6000, backoffMs: 1000 }).catch((e) => {
        console.error(`[Scan] Failed to persist scan record against ${BACKEND_URL}:`, e.message);
    });
}

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
    saveScanRecord(url, result);
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

ipcMain.handle('logout', () => {
    configStore.remove('userEmail'); // cleanup for any pre-existing cached value
    configStore.remove('session'); // clears any persisted "Stay logged in" session
    currentSessionToken = null;
    return true;
});

ipcMain.handle('auth-check-email', async (event, email) => {
    try {
        return await authCheckEmail(email);
    } catch (e) {
        console.error(`[Auth] check-email failed against ${BACKEND_URL} after retries:`, e.message);
        return { status: 'error', reason: 'network', message: "Couldn't reach the server after several attempts. Check your connection and try again." };
    }
});

ipcMain.handle('auth-signup', async (event, { email, fullName, password, staySignedIn }) => {
    try {
        const result = await authSignup(email, fullName, password);
        persistOrClearSession(result, staySignedIn);
        return result;
    } catch (e) {
        console.error(`[Auth] signup failed against ${BACKEND_URL} after retries:`, e.message);
        return { status: 'error', reason: 'network', message: "Couldn't reach the server after several attempts. Check your connection and try again." };
    }
});

ipcMain.handle('auth-login', async (event, { email, password, staySignedIn }) => {
    try {
        const result = await authLogin(email, password);
        persistOrClearSession(result, staySignedIn);
        return result;
    } catch (e) {
        console.error(`[Auth] login failed against ${BACKEND_URL} after retries:`, e.message);
        return { status: 'error', reason: 'network', message: "Couldn't reach the server after several attempts. Check your connection and try again." };
    }
});

// Persists the session token returned by a successful login/signup only if
// the user opted into "Stay logged in"; otherwise makes sure no stale
// session lingers from an earlier opt-in, so unchecking the box behaves
// the way a user would expect the next time they open the app.
function persistOrClearSession(result, staySignedIn) {
    if (result?.status !== 'success') return;
    // Kept in memory for this run regardless of "Stay logged in" — that
    // checkbox only controls whether it also survives to the NEXT launch.
    currentSessionToken = result.session_token || null;
    if (staySignedIn && result.session_token && result.expires_at) {
        // config-store's encrypted path (safeStorage.encryptString) only
        // accepts a string, not an object — serialize to JSON ourselves
        // and parse it back out on the read side below.
        configStore.set('session', JSON.stringify({ token: result.session_token, expiresAt: result.expires_at }), true);
    } else {
        configStore.remove('session');
    }
}

function readStoredSession() {
    const raw = configStore.get('session');
    if (!raw) return null;
    try { return JSON.parse(raw); } catch (_) { return null; }
}

ipcMain.handle('try-resume-session', async () => {
    const stored = readStoredSession();
    if (!stored || !stored.token || !stored.expiresAt) return false;

    // Local expiry check first — no point calling the backend at all if
    // the token is already past its 30-day lifetime on the client side.
    if (Date.now() > stored.expiresAt) {
        configStore.remove('session');
        return false;
    }

    try {
        const result = await authValidateSession(stored.token);
        if (result.status === 'success') {
            currentSessionToken = stored.token; // resumed — scans can be saved again this run
            return true;
        }
        // Backend explicitly rejected it (expired/invalid/account gone).
        configStore.remove('session');
        return false;
    } catch (e) {
        // Couldn't reach the backend to confirm (offline/unreachable) —
        // fail safe by requiring login for THIS launch, but deliberately
        // keep the stored token rather than deleting it: a connectivity
        // blip shouldn't force a "remember me" user to log in again once
        // the backend comes back, only an explicit server-side rejection
        // or the 30-day local expiry should do that.
        console.error(`[Auth] session validation failed against ${BACKEND_URL} after retries:`, e.message);
        return false;
    }
});

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