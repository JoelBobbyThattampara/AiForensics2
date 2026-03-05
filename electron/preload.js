/**
 * FCTT Electron Preload Script
 * Exposes only safe, validated APIs to the renderer via contextBridge.
 * The renderer CANNOT access Node.js or filesystem directly.
 */

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('fcttBridge', {
  health: () => ipcRenderer.invoke('fctt:health'),
  openExternal: (url) => ipcRenderer.invoke('fctt:open-external', url),
  getVersion: () => ipcRenderer.invoke('fctt:get-version'),
})
