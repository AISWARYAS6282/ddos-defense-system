# DDoS Defense System — Division 1

Secure foundation: authentication, database models, simulator, and sandboxed blocking agent.

---

## Quick Start

### 1. Clone & Configure
```bash
git clone <your-repo>
cd ddos-defense-system
cp .env.example .env
# Edit .env with your secrets
```

### 2. Run with Docker Compose
```bash
docker-compose up --build -d
docker-compose exec web flask db upgrade
docker-compose exec web python seed.py
```

### 3. Access
- Web UI: http://localhost:5000
- Login: admin / Admin1234! (or operator / Operator1234!)
- Sandbox Agent API: http://localhost:5001

---

## Local Development (without Docker)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export FLASK_APP=run.py
export FLASK_ENV=development
export DATABASE_URL=sqlite:///dev.db

flask db init
flask db migrate -m "initial"
flask db upgrade
python seed.py
python run.py
```

---

## Simulator

Emits JSON events to stdout based on fixed IP pools:

```bash
python simulator/simulator.py
# or with custom rate:
SIM_RATE=5 python simulator/simulator.py
```

---

## Sandbox Agent

Test the block API stub (no real iptables):

```bash
curl -X POST http://localhost:5001/apply_block \
  -H "Authorization: Bearer change-me-sandbox-token" \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.168.100.10", "action": "BLOCK"}'
```

---

## Branch Strategy

- `main` — stable, production-ready code only
- `dev` — integration branch
- `feature/<name>` — individual features
- `division/<n>` — division-level branches

---

## Project Structure

```
ddos-defense-system/
├── app/
│   ├── __init__.py          # App factory
│   ├── config.py            # Config classes
│   ├── extensions.py        # Flask extensions
│   ├── blueprints/
│   │   ├── auth/            # Login/logout
│   │   ├── dashboard/       # Main UI
│   │   └── api/             # REST API
│   ├── models/              # SQLAlchemy models
│   └── templates/           # Jinja2 HTML
├── simulator/
│   ├── simulator.py         # Event generator
│   └── ip_pools.json        # IP pool config
├── sandbox_agent/
│   ├── agent.py             # Flask stub agent
│   ├── Dockerfile
│   └── requirements.txt
├── migrations/              # Flask-Migrate
├── docker-compose.yml
├── Dockerfile
├── run.py
├── seed.py
└── requirements.txt
```

---

## Roles

| Role     | Permissions                          |
|----------|--------------------------------------|
| admin    | Full access, user management         |
| operator | View dashboard, trigger blocks       |

---

## Division Roadmap

- **Division 1** ✅ Foundation, auth, DB, simulator, sandbox stub
- Division 2 — Detection engine
- Division 3 — Real blocking via iptables
- Division 4 — Dashboard & alerting
- Division 5 — Hardening & reporting
