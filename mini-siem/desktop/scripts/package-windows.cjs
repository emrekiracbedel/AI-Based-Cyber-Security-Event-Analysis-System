/**
 * Tam Windows paketi: PyInstaller (backend) + electron-builder (desktop).
 * Önkoşul: backend venv'te requirements + requirements-build yüklü, pyinstaller PATH'te.
 */
const { spawnSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const desktopRoot = path.resolve(__dirname, "..");
const miniSiemRoot = path.resolve(desktopRoot, "..");
const backendRoot = path.join(miniSiemRoot, "backend");
const backendExe = path.join(
  backendRoot,
  "dist",
  "MiniSIEM-Backend",
  "MiniSIEM-Backend.exe"
);

function run(cmd, args, cwd, shell = true) {
  const r = spawnSync(cmd, args, { cwd, shell, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

if (!fs.existsSync(backendRoot)) {
  console.error("Backend klasörü bulunamadı:", backendRoot);
  process.exit(1);
}

console.log("→ PyInstaller (backend)…");
run("pyinstaller", ["minisiem_backend.spec", "--noconfirm"], backendRoot);

if (!fs.existsSync(backendExe)) {
  console.error("Beklenen exe yok:", backendExe);
  process.exit(1);
}

console.log("→ electron-builder (desktop + gömülü backend)…");
run("npm", ["run", "build:win"], desktopRoot);

console.log("Tamam. Inno için: desktop\\release\\win-unpacked");
