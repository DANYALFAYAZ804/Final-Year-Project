const { app, BrowserWindow } = require('electron');
const path = require('path');

function createWindow() {
    const win = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(__dirname, 'renderer.js'), // preload script
            contextIsolation: true,        // isolates renderer JS
            nodeIntegration: false,        // prevents node in renderer
            enableRemoteModule: false,
        }
    });

    win.loadFile('index.html');

    // Optional: Open DevTools
    // win.webContents.openDevTools();
}

app.whenReady().then(() => {
    createWindow();

    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});