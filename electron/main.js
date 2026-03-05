/**
 * FCTT Electron Main Process
 * - Loads React frontend from Vite dev server (dev) or dist/ (prod)
 * - Strict IPC validation — renderer has NO direct filesystem access
 * - Sandboxed renderer process
 */

const { app, BrowserWindow, ipcMain, shell } = require('electron')
const path = require('path')
const { spawn } = require('child_process')
const fs = require('fs')

const isDev = process.env.NODE_ENV === 'development' || !app.isPackaged
let mainWindow = null
let backendProcess = null

// ─── Start Python Backend ──────────────────────────────────────────────────
function startBackend() {
  const backendPath = isDev
    ? path.join(__dirname, '../../backend/main.py')
    : path.join(process.resourcesPath, 'backend/main.py')

  if (!fs.existsSync(backendPath)) {
    console.warn('[FCTT] Backend not found at:', backendPath)
    return
  }

  backendProcess = spawn('python3', [backendPath], {
    env: { ...process.env },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  backendProcess.stdout.on('data', (d) => console.log('[Backend]', d.toString().trim()))
  backendProcess.stderr.on('data', (d) => console.error('[Backend ERR]', d.toString().trim()))
  backendProcess.on('exit', (code) => console.log('[Backend] exited with code', code))

  console.log('[FCTT] Backend started PID:', backendProcess.pid)
}

// ─── Create Window ─────────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 960,
    minWidth: 1280,
    minHeight: 720,
    backgroundColor: '#060f18',
    titleBarStyle: 'hiddenInset',
    frame: process.platform !== 'darwin',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,       // ✅ Security: context isolation ON
      nodeIntegration: false,       // ✅ Security: no Node in renderer
      sandbox: true,                // ✅ Security: sandboxed renderer
      webSecurity: true,
    },
  })

  const url = isDev
    ? 'http://localhost:3000'
    : `file://${path.join(__dirname, '../dist/index.html')}`

  mainWindow.loadURL(url)

  if (isDev) mainWindow.webContents.openDevTools({ mode: 'detach' })

  mainWindow.on('closed', () => { mainWindow = null })
}

// ─── IPC Handlers (strictly validated) ────────────────────────────────────
ipcMain.handle('fctt:health', async () => {
  try {
    const res = await fetch('http://127.0.0.1:8765/api/health')
    return res.json()
  } catch {
    return { status: 'unreachable' }
  }
})

ipcMain.handle('fctt:open-external', async (_, url) => {
  // Only allow opening known safe URLs
  if (url.startsWith('http://127.0.0.1:8765/api/')) {
    shell.openExternal(url)
  }
})

ipcMain.handle('fctt:get-version', () => app.getVersion())

// ─── App Lifecycle ─────────────────────────────────────────────────────────
app.whenReady().then(() => {
  startBackend()
  // Wait briefly for backend to initialize
  setTimeout(createWindow, 1500)

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (backendProcess) {
    backendProcess.kill('SIGTERM')
    console.log('[FCTT] Backend terminated')
  }
  if (process.platform !== 'darwin') app.quit()
})

app.on('before-quit', () => {
  if (backendProcess) backendProcess.kill('SIGTERM')
})
