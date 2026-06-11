# DDoS Defense System

A full-stack, production-architecture DDoS detection and automated response platform.
Detects attacks in real time using a three-layer pipeline — rule engine, 
ML anomaly detection, and an XGBoost classifier trained on the CICIDS2017 dataset.

Built across three development divisions, evolving from a basic Flask scaffold 
to a containerized, ML-powered security system with a live dashboard.

---

## Architecture

```
                  ┌─────────────┐
   Browser ──────▶│  nginx HTTPS │
                  └──────┬──────┘
                         │
                  ┌──────▼──────┐       ┌──────────────────┐
                  │  Flask App  │──────▶│  Sandbox Agent   │
                  │  (web:5000) │       │  (block exec)    │
                  └──────┬──────┘       └──────────────────┘
                         │
                  ┌──────▼──────┐
                  │  PostgreSQL │
                  └─────────────┘
```

Three Docker services with isolated networks — the main app never directly 
executes IP blocks; it delegates to a sandboxed agent, enforcing least privilege.

---

## Detection Pipeline

### Layer 1 — Rule Engine
Sliding-window packet analysis across 60s and 300s intervals.
Detects: SYN Flood, UDP Flood, HTTP Flood, ICMP Flood, DNS Amplification.
Assigns severity (low / medium / high / critical) with confidence scores.

### Layer 2 — ML Anomaly Detection (Isolation Forest)
Trained on live normal traffic (auto-retrains at 100+ samples).
Catches novel attack patterns that rules miss.
Model persists to disk and reloads on restart.

### Layer 3 — XGBoost Classifier
Trained on the [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) 
intrusion detection dataset (~500K flows).
Zero data-leakage training: scaler and variance filter fit on train split only.

---

## Features

- **Live dashboard** — WebSocket-powered real-time alert feed
- **Auto-block** — IPs triggering 3+ alerts within 5 minutes are automatically blocked
- **Role-based access** — Admin (full control) and Operator (view + block) roles
- **Audit log** — All block/unblock actions exportable as CSV
- **Traffic simulator** — Synthetic attack/normal event generator for testing
- **Health & metrics API** — `/api/health` and `/api/metrics` endpoints
- **Rate limiting** — API endpoints protected via Flask-Limiter
- **HTTPS** — nginx with self-signed cert (swap for Let's Encrypt in production)
- **CI** — GitHub Actions pipeline runs tests on every push

---

## Quick Start (Docker)

```bash
git clone https://github.com/AISWARYAS6282/ddos-defense-system.git
cd ddos-defense-system

# Generate SSL cert (first time only)
bash nginx/generate_cert.sh

# Configure environment
cp .env.example .env

# Start all services
docker-compose up --build -d
docker-compose exec web flask db upgrade
docker-compose exec web python seed.py
```

Access at **https://localhost**

| User     | Password     | Role     |
|----------|--------------|----------|
| admin    | Admin1234!   | Admin    |
| operator | Operator1234!| Operator |

---

## Local Development (no Docker)

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

export FLASK_APP=run.py
export DATABASE_URL=sqlite:///dev.db

flask db init && flask db migrate -m "init" && flask db upgrade
python seed.py
python run.py
```

---

## Running Tests

```bash
docker-compose exec web pytest tests/
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, Flask-SocketIO, Flask-Login |
| Database | PostgreSQL (prod), SQLite (dev) |
| ML | scikit-learn (Isolation Forest), XGBoost, CICIDS2017 dataset |
| Infrastructure | Docker, Docker Compose, nginx, GitHub Actions CI |
| Security | Argon2 password hashing, JWT, Flask-Limiter, sandboxed block agent |

---

## Dataset

The XGBoost model is trained on the **CICIDS2017 Friday DDoS** dataset.
Due to file size (~500MB), the CSV is not included in this repo.
Download from: https://www.unb.ca/cic/datasets/ids-2017.html
Place as `data.csv` in the project root, then run `python train_model.py`.

---

## Disclaimer

This system is for educational purposes and authorized lab environments only.
The traffic simulator generates synthetic events — no real network packets are sent.
