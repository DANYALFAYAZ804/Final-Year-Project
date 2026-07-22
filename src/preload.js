const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('trustflow', {
    scanUrl: (url) => ipcRenderer.invoke('scan-url', url),
    onKeyboardLock: (callback) => ipcRenderer.on('keyboard-lock', (_, data) => callback(data)),
    onKeyboardUnlock: (callback) => ipcRenderer.on('keyboard-unlock', (_, data) => callback(data)),
    getSettings: () => ipcRenderer.invoke('get-settings'),
    saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
    clearCache: () => ipcRenderer.invoke('clear-cache'),
    getStats: () => ipcRenderer.invoke('get-stats'),
    logout: () => ipcRenderer.invoke('logout'),
    tryResumeSession: () => ipcRenderer.invoke('try-resume-session'),
    authCheckEmail: (email) => ipcRenderer.invoke('auth-check-email', email),
    authLogin: (credentials) => ipcRenderer.invoke('auth-login', credentials),
    authSignup: (credentials) => ipcRenderer.invoke('auth-signup', credentials),
});
