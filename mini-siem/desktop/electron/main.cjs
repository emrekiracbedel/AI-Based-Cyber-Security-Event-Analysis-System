const { app, BrowserWindow } = require("electron");
const path = require("path");
const fs = require("fs");
const { spawn } = require("child_process");
const http = require("http");

const API_HOST = process.env.MINI_SIEM_HOST || "127.0.0.1";
const API_PORT = (process.env.MINI_SIEM_PORT || "8000").trim() || "8000";

let backendProc = null;

function backendExePath() {
  if (!app.isPackaged) return null;
  return path.join(process.resourcesPath, "backend", "MiniSIEM-Backend.exe");
}

function waitForHealth(port, attemptsLeft, done) {
  const url = `http://${API_HOST}:${port}/api/health`;
  const req = http.get(url, (res) => {
    res.resume();
    done(true);
  });
  req.on("error", () => {
    if (attemptsLeft <= 1) done(false);
    else setTimeout(() => waitForHealth(port, attemptsLeft - 1, done), 350);
  });
  req.setTimeout(2500, () => {
    try {
      req.destroy();
    } catch (_) {}
  });
}

function startBundledBackend() {
  return new Promise((resolve) => {
    const exe = backendExePath();
    if (!exe || !fs.existsSync(exe)) {
      resolve({ ok: false, reason: "no_bundle" });
      return;
    }
    const cwd = path.dirname(exe);
    backendProc = spawn(exe, [], {
      cwd,
      stdio: "ignore",
      windowsHide: true,
      env: {
        ...process.env,
        MINI_SIEM_PORT: API_PORT,
        MINI_SIEM_HOST: API_HOST,
      },
    });
    backendProc.on("error", () => {});
    backendProc.on("exit", () => {
      backendProc = null;
    });
    waitForHealth(API_PORT, 80, (ready) => {
      resolve({ ok: true, ready });
    });
  });
}

function stopBundledBackend() {
  if (!backendProc || backendProc.killed) return;
  try {
    if (process.platform === "win32") {
      spawn("taskkill", ["/pid", String(backendProc.pid), "/T", "/F"], {
        stdio: "ignore",
        windowsHide: true,
      });
    } else {
      backendProc.kill("SIGTERM");
    }
  } catch (_) {
    try {
      backendProc.kill();
    } catch (_) {}
  }
  backendProc = null;
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 960,
    minHeight: 640,
    title: "Mini-SIEM Desktop",
    backgroundColor: "#020617",
    webPreferences: {
      preload: path.join(__dirname, "preload.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      // Packaged app loads file:// — allow fetch/WS to local API on :8000
      webSecurity: !app.isPackaged,
    },
  });

  const dev = process.env.NODE_ENV === "development" || !app.isPackaged;
  if (dev) {
    const port = process.env.DEV_SERVER_PORT || "5173";
    win.loadURL(`http://127.0.0.1:${port}`);
  } else {
    win.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
}

app.whenReady().then(async () => {
  if (app.isPackaged) {
    const r = await startBundledBackend();
    if (!r.ready && r.ok) {
      console.warn("Mini-SIEM: API health check timed out (port " + API_PORT + ")");
    }
  }
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  stopBundledBackend();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
