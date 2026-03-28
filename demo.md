# DDoS Defense System — Division 3 Demo Script

## Quick Start

```powershell
# 1. Generate SSL certificate (first time only)
bash nginx/generate_cert.sh

# 2. Start all services
docker-compose down -v
docker-compose up --build

# 3. Seed database (new terminal)
docker-compose exec web python seed.py

# 4. Run tests
docker-compose exec web python tests/test_division3.py
```

## Access Points

| URL | Description |
|-----|-------------|
| https://localhost | Main dashboard (via nginx HTTPS) |
| http://localhost:5000 | Direct Flask (bypass nginx) |
| http://localhost:5001 | Sandbox agent |
| https://localhost/api/health | Health check |
| https://localhost/api/metrics | Live metrics JSON |

## Login Credentials

| User | Password | Role |
|------|----------|------|
| admin | Admin1234! | Admin — full access |
| operator | Operator1234! | Operator — view + block |

## Demo Steps

### Step 1 — Show the dashboard
- Login as admin
- Point out: WS indicator (⬤ Live), Start Sim button, ML Training bar

### Step 2 — Start the simulator
- Click ▶ Start Sim
- Live ticker starts updating (green = normal, red = attack)
- After ~60 seconds: ML bar fills up → turns green "🧠 Model Ready"

### Step 3 — Show ML detection
- Watch for rows with `ML_ANOMALY` attack type (green color)
- These are caught by ML only — no rule triggered them
- ML column shows anomaly score %

### Step 4 — Block an IP
- Click Block on any HIGH or CRITICAL alert
- All rows for that IP → 🔒 blocked instantly
- Blocked IPs counter increments
- That IP stops appearing in live ticker

### Step 5 — Export audit log
- Click "⬇ Export Audit Log (CSV)"
- CSV downloads with all block/unblock actions

### Step 6 — Show health/metrics
- Open https://localhost/api/health → {"status": "healthy"}
- Open https://localhost/api/metrics → full stats JSON

### Step 7 — Run tests
```powershell
docker-compose exec web python tests/test_division3.py
```
Expected: All tests pass ✅

## What Each Division Added

| Division | Feature |
|----------|---------|
| 1 | Flask app, DB models, auth, Docker, simulator |
| 2 | Detection engine, WebSocket alerts, live dashboard |
| 3 | ML anomaly detection, rate limiting, audit CSV, nginx HTTPS, tests, CI |
