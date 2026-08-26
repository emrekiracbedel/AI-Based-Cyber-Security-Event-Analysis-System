# Mini-SIEM

Electron desktop interface and FastAPI-based backend: Sigma-like rules, Isolation Forest anomaly, DDoS heuristics, optional LLM description.

---

## Requirements

| Component | Note |
|--------|-----|
| **Python 3.11+** | Backend |
| **Node.js (LTS)** | Desktop (`npm`) |
| **MongoDB** | Optional; `docker compose` or local `27017` |
| **Windows** | For full installation package and `host_network_agent` |

---

## Running the application with code (development)

Use two separate terminals. Close the **installed Mini-SIEM Desktop** if it's open — port `8000` conflicts.

### 1) API (backend)

```powershell
cd mini-siem\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-build.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Keep this window open. Check: in browser [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### 2) Desktop (frontend)

New PowerShell:

```powershell
cd mini-siem\desktop
npm install
npm run dev
```

The Electron window opens; The API connects to `http://127.0.0.1:8000` by default.

---

## Installed application (setup generated with Inno Setup)

1. Install with `MiniSIEM-Desktop-Setup-….exe`.
2. Launch from the **Mini-SIEM Desktop** shortcut.
3. The embedded API runs in the background on `127.0.0.1:8000`; you also don't need to run `uvicorn`.

To repackage (summary):

```powershell
cd mini-siem\backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-build.txt
deactivate
cd ..\desktop
npm install
npm run build:win:full
```

Then compile the `installer\MiniSIEM-Setup.iss` file with Inno Setup.

---

## Why might the Dashboard be empty?

- By default, **demo simulation is disabled** (`ENABLE_DEMO_SIMULATION=false`).
- Just browsing in the browser does not **automatically send data**.
- Data sources:
- **`POST /api/ingest/log`** — raw log line
- **`POST /api/ingest/flow`** — source/target IP flow counter
- **`backend/scripts/host_network_agent.py`** — actual TCP/UDP connections on this computer (runs separately)
- **`ENABLE_DEMO_SIMULATION=true`** — simulated traffic for testing (development only)

### Host agent (actual connections)

Separate terminal while API is running:

```powershell
cd mini-siem\backend
.\.venv\Scripts\Activate.ps1
python scripts/host_network_agent.py --api http://127.0.0.1:8000 --interval 2 --ping-every 30
```

Administrator PowerShell makes it easy to see sockets belonging to other user processes.

---

## MongoDB

In the project root:

```powershell
cd mini-siem
docker compose up -d
```

Default URI: `mongodb://127.0.0.1:27017`. API runs even when Mongo is down; persistent log/warning and **hydrate** on startup are limited.

---

## LLM (OpenAI / Gemini)

- **On the desktop:** API keys → Manage** keys are stored in `localStorage`; requests are sent with the headers `X-MiniSiem-Llm-OpenAI` / `X-MiniSiem-Llm-Gemini`.
- **On the server:** `OPENAI_API_KEY`, `GEMINI_API_KEY`, optional `LLM_PROVIDER=gemini`.

**Important:** The `http://127.0.0.1:8000/api/health` request you open directly in your browser **doesn't exist**; therefore, seeing `llm_configured: false` might be normal. The health line and LLM descriptions within the application are consistent with the headers.

---

## Environment variables (optional)

| Variable | Description |
|----------|-----------|
| `ENABLE_DEMO_SIMULATION` | `true` / `false` (default: off) |
| `MONGODB_URI` | E.g. `mongodb://127.0.0.1:27017` |
| `MONGODB_DB` | Default: `mini_siem` |
| `OPENAI_API_KEY` / `GEMINI_API_KEY` | Server-side LLM |
| `LLM_PROVIDER` | `openai` or `gemini` |
| `GEMINI_MODEL` / `LLM_MODEL` | Model names |

---

## Troubleshooting

| Problem | Solution |
|-------|--------|
| `WinError 10048` / port 8000 | Close the installed application or don't use `uvicorn`; or close the conflicting process. |
| `netstat -ano \| findstr :8000` | To see who is using the port. |
| PowerShell script not working | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |

---

## Folder structure (summary)

- `backend/` — FastAPI application (`app.main:app`)
- `desktop/` — Electron + Vite + React
- `installer/` — Inno Setup script
- `docker-compose.yml` — MongoDB
