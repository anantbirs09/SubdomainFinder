const { app, BrowserWindow, shell } = require('electron');
const path = require('path');

function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 1280,
    height: 850,
    minWidth: 800,
    minHeight: 600,
    title: "ABS Scan",
    backgroundColor: '#070a13',
    icon: path.join(__dirname, 'public', 'favicon.ico'), // placeholder if icon exists
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true
    }
  });

  // Hide the default menu bar
  mainWindow.removeMenu();

  // Load the web application running on local port 3000
  mainWindow.loadURL('http://localhost:3000');

  // Intercept new window requests (e.g. target="_blank" links) and open them in default external browser
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http://') || url.startsWith('https://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });
}

// When Electron is ready, start Express and create the window
app.whenReady().then(() => {
  // Start the background scan server
  require('./server.js');
  
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
