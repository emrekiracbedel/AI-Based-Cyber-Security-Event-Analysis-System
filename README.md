# Mini-SIEM

Electron masaüstü arayüzü ve FastAPI tabanlı backend: Sigma benzeri kurallar, Isolation Forest anomali, DDoS heuristikleri, isteğe bağlı LLM açıklaması.

---

## Gereksinimler

| Bileşen | Not |
|--------|-----|
| **Python 3.11+** | Backend |
| **Node.js (LTS)** | Masaüstü (`npm`) |
| **MongoDB** | İsteğe bağlı; `docker compose` veya yerel `27017` |
| **Windows** | Tam kurulum paketi ve `host_network_agent` için |

---

## Uygulamayı kod ile çalıştırma (geliştirme)

İki ayrı terminal kullanın. **Kurulu Mini-SIEM Desktop** açıksa kapatın — `8000` portu çakışır.

### 1) API (backend)

```powershell
cd mini-siem\backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-build.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Bu pencere açık kalsın. Kontrol: tarayıcıda [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### 2) Masaüstü (frontend)

Yeni PowerShell:

```powershell
cd mini-siem\desktop
npm install
npm run dev
```

Electron penceresi açılır; API varsayılan olarak `http://127.0.0.1:8000` adresine bağlanır.

---

## Kurulu uygulama (Inno Setup ile üretilen setup)

1. `MiniSIEM-Desktop-Setup-….exe` ile kur.
2. **Mini-SIEM Desktop** kısayolundan başlat.
3. Gömülü API arka planda `127.0.0.1:8000` üzerinde kalkar; ayrıca `uvicorn` çalıştırman gerekmez.

Yeniden paketlemek için (özet):

```powershell
cd mini-siem\backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-build.txt
deactivate

cd ..\desktop
npm install
npm run build:win:full
```

Ardından Inno Setup ile `installer\MiniSIEM-Setup.iss` dosyasını derle.

---

## Dashboard neden boş olabilir?

- Varsayılan olarak **demo simülasyon kapalıdır** (`ENABLE_DEMO_SIMULATION=false`).
- Sadece tarayıcıda gezmek veriyi **otomatik göndermez**.
- Veri kaynakları:
  - **`POST /api/ingest/log`** — ham log satırı
  - **`POST /api/ingest/flow`** — kaynak/hedef IP akış sayacı
  - **`backend/scripts/host_network_agent.py`** — bu bilgisayardaki gerçek TCP/UDP bağlantıları (ayrı çalıştırılır)
  - **`ENABLE_DEMO_SIMULATION=true`** — test için sahte trafik (sadece geliştirme)

### Host ajanı (gerçek bağlantılar)

API çalışırken ayrı terminal:

```powershell
cd mini-siem\backend
.\.venv\Scripts\Activate.ps1
python scripts/host_network_agent.py --api http://127.0.0.1:8000 --interval 2 --ping-every 30
```

Yönetici PowerShell, diğer kullanıcı süreçlerine ait soketleri görmeyi kolaylaştırır.

---

## MongoDB

Proje kökünde:

```powershell
cd mini-siem
docker compose up -d
```

Varsayılan URI: `mongodb://127.0.0.1:27017`. Mongo kapalıyken API çalışır; kalıcı log/uyarı ve açılışta **hydrate** sınırlı kalır.

---

## LLM (OpenAI / Gemini)

- **Masaüstünde:** **API keys → Manage** ile anahtarlar `localStorage`’da tutulur; isteklerde `X-MiniSiem-Llm-OpenAI` / `X-MiniSiem-Llm-Gemini` başlıklarıyla gider.
- **Sunucuda:** `OPENAI_API_KEY`, `GEMINI_API_KEY`, isteğe bağlı `LLM_PROVIDER=gemini`.

**Önemli:** Tarayıcıda doğrudan açtığın `http://127.0.0.1:8000/api/health` isteğinde bu başlıklar **yoktur**; bu yüzden `llm_configured: false` görmen normal olabilir. Uygulama içindeki sağlık satırı ve LLM açıklamaları başlıklarla tutarlıdır.

---

## Ortam değişkenleri (seçmeli)

| Değişken | Açıklama |
|----------|-----------|
| `ENABLE_DEMO_SIMULATION` | `true` / `false` (varsayılan: kapalı) |
| `MONGODB_URI` | Örn. `mongodb://127.0.0.1:27017` |
| `MONGODB_DB` | Varsayılan: `mini_siem` |
| `OPENAI_API_KEY` / `GEMINI_API_KEY` | Sunucu tarafı LLM |
| `LLM_PROVIDER` | `openai` veya `gemini` |
| `GEMINI_MODEL` / `LLM_MODEL` | Model adları |

---

## Sorun giderme

| Sorun | Çözüm |
|-------|--------|
| `WinError 10048` / port 8000 | Kurulu uygulamayı kapat veya `uvicorn` kullanma; ya da çakışan süreci kapat. |
| `netstat -ano \| findstr :8000` | Portu kim kullanıyor görmek için. |
| PowerShell script çalışmıyor | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |

---

## Klasör yapısı (özet)

- `backend/` — FastAPI uygulaması (`app.main:app`)
- `desktop/` — Electron + Vite + React
- `installer/` — Inno Setup betiği
- `docker-compose.yml` — MongoDB
