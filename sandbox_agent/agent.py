#!/usr/bin/env python3
"""
DDoS Defense System — Sandbox Agent (STUB)
Division 1: Logs block/unblock requests. NO real iptables execution.
iptables will only be activated in Division 3 after full safety review.

Runs inside an isolated Docker container (non-privileged).
Exposes: POST /apply_block (authenticated with Bearer token)
"""

import logging
import os
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = app.logger

AGENT_TOKEN = os.environ.get("SANDBOX_AGENT_TOKEN", "stub-token")
DIVISION = "1-stub"


def _authorized(req) -> bool:
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth[len("Bearer "):] == AGENT_TOKEN


@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "mode": "stub",
        "division": DIVISION,
        "iptables_active": False,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/apply_block", methods=["POST"])
def apply_block():
    """
    Accepts block/unblock requests and LOGS them.
    No iptables calls until Division 3.
    """
    if not _authorized(request):
        logger.warning("Unauthorized request to /apply_block from %s", request.remote_addr)
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    ip = data.get("ip", "").strip()
    action = data.get("action", "BLOCK").upper()
    reason = data.get("reason", "")

    if not ip:
        return jsonify({"error": "ip field required"}), 400

    if action not in ("BLOCK", "UNBLOCK"):
        return jsonify({"error": "action must be BLOCK or UNBLOCK"}), 400

    # ── STUB: Log only, no iptables ──────────────────────────────────────────
    logger.info(
        "[STUB] %s request | ip=%s | reason=%s | from=%s",
        action, ip, reason or "(none)", request.remote_addr
    )
    # ─────────────────────────────────────────────────────────────────────────

    return jsonify({
        "status": "stubbed",
        "action": action,
        "ip": ip,
        "iptables_executed": False,
        "message": (
            f"[Division {DIVISION}] {action} for {ip} logged successfully. "
            "iptables enforcement not active until Division 3."
        ),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/list_rules")
def list_rules():
    """Returns empty rule set — stub only."""
    if not _authorized(request):
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify({
        "rules": [],
        "message": "iptables not active in Division 1 stub.",
        "iptables_active": False,
    })


if __name__ == "__main__":
    port = int(os.environ.get("AGENT_PORT", 5001))
    logger.info("Sandbox agent (STUB) starting on port %d", port)
    logger.info("iptables: DISABLED (Division 1 stub mode)")
    app.run(host="0.0.0.0", port=port)
