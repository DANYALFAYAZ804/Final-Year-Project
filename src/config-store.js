const { safeStorage, app } = require('electron');
const path = require('path');
const fs = require('fs');

const CONFIG_FILE = path.join(app.getPath('userData'), 'trustflow-config.json');

function loadRaw() {
    try {
        if (fs.existsSync(CONFIG_FILE)) {
            return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
        }
    } catch (_) {}
    return {};
}

function saveRaw(data) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(data), 'utf8');
}

function get(key) {
    const raw = loadRaw();
    if (!(key in raw)) return null;
    const entry = raw[key];
    if (entry && entry.encrypted) {
        try {
            return safeStorage.decryptString(Buffer.from(entry.value, 'base64'));
        } catch (_) { return null; }
    }
    return entry.value;
}

function set(key, value, encrypt = false) {
    const raw = loadRaw();
    if (encrypt && safeStorage.isEncryptionAvailable()) {
        const encrypted = safeStorage.encryptString(value);
        raw[key] = { encrypted: true, value: encrypted.toString('base64') };
    } else {
        raw[key] = { encrypted: false, value };
    }
    saveRaw(raw);
}

function remove(key) {
    const raw = loadRaw();
    delete raw[key];
    saveRaw(raw);
}

module.exports = { get, set, remove };
