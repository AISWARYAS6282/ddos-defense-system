"""
app/blueprints/api/routes.py  —  Division 3  (COMPLETE + FIXED)
"""
import time
from flask import jsonify, request, current_app
from flask_login import login_required, current_user
import requests as http_requests
from . import api_bp
from ...extensions import db, socketio
from ...models.blocked_ip import BlockedIP
from ...models.response_log import ResponseLog
from ...models.simulator_config import SimulatorConfig
from ...models.attack import Attack
from ...security import limiter, is_valid_ip, sanitize_reason
from datetime import datetime

_start_time = time.time()


def _call_sandbox(action, ip):
    agent_url = current_app.config.get("SANDBOX_AGENT_URL", "http://sandbox_agent:5001")
    token     = current_app.config.get("SANDBOX_AGENT_TOKEN", "stub-token")
    try:
        resp = http_requests.post(
            f"{agent_url}/apply_block",
            json={"ip": ip, "action": action},
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return resp.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Health & Metrics ──────────────────────────────────────────────────────────

@api_bp.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    return jsonify({
        "status":         "healthy" if db_ok else "degraded",
        "database":       "up" if db_ok else "down",
        "uptime_seconds": round(time.time() - _start_time),
    }), (200 if db_ok else 503)


@api_bp.route("/metrics")
def metrics():
    from ...simulator_manager import simulator_manager
    try:
        from sqlalchemy import func
        top_ips = (
            db.session.query(Attack.source_ip, func.count(Attack.id).label("c"))
            .group_by(Attack.source_ip)
            .order_by(func.count(Attack.id).desc())
            .limit(5).all()
        )
        return jsonify({
            "uptime_seconds":    round(time.time() - _start_time),
            "simulator_running": simulator_manager.running,
            "attacks": {
                "total":   Attack.query.count(),
                "active":  Attack.query.filter_by(status="active").count(),
                "blocked": Attack.query.filter_by(status="blocked").count(),
                "ignored": Attack.query.filter_by(status="ignored").count(),
            },
            "blocked_ips": BlockedIP.query.filter_by(is_active=True).count(),
            "severity_breakdown": {
                s: Attack.query.filter_by(severity=s).count()
                for s in ("low", "medium", "high", "critical")
            },
            "top_attacker_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Status ────────────────────────────────────────────────────────────────────

@api_bp.route("/status")
def status():
    from ...simulator_manager import simulator_manager
    return jsonify({"status": "ok", "division": 3,
                    "simulator_running": simulator_manager.running})


# ── Simulator ─────────────────────────────────────────────────────────────────

@api_bp.route("/simulator/start", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def sim_start():
    from ...simulator_manager import simulator_manager
    started = simulator_manager.start(socketio, current_app._get_current_object())
    if not started:
        return jsonify({"running": True, "message": "Already running"})
    socketio.emit("sim_status", {"running": True, "started_by": current_user.username})
    return jsonify({"running": True, "message": "Simulator started"})


@api_bp.route("/simulator/stop", methods=["POST"])
@login_required
def sim_stop():
    from ...simulator_manager import simulator_manager
    simulator_manager.stop()
    socketio.emit("sim_status", {"running": False, "stopped_by": current_user.username})
    return jsonify({"running": False, "message": "Simulator stopped"})


@api_bp.route("/simulator/status")
@login_required
def sim_status():
    from ...simulator_manager import simulator_manager
    cfg = SimulatorConfig.query.first()
    return jsonify({
        "running":      simulator_manager.running,
        "attack_rate":  cfg.attack_rate  if cfg else 1.0,
        "attack_ratio": cfg.attack_ratio if cfg else 0.3,
    })


@api_bp.route("/simulator/config", methods=["GET", "POST"])
@login_required
def sim_config():
    cfg = SimulatorConfig.query.first()
    if request.method == "GET":
        return jsonify({
            "attack_rate":  cfg.attack_rate  if cfg else 1.0,
            "attack_ratio": cfg.attack_ratio if cfg else 0.3,
        })
    data = request.get_json() or {}
    if cfg:
        if "attack_rate"  in data:
            cfg.attack_rate  = max(0.1, min(float(data["attack_rate"]),  10.0))
        if "attack_ratio" in data:
            cfg.attack_ratio = max(0.0, min(float(data["attack_ratio"]), 1.0))
        db.session.commit()
    return jsonify({"success": True})


# ── Block / Unblock ───────────────────────────────────────────────────────────

@api_bp.route("/block", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def block_ip():
    data   = request.get_json() or {}
    ip     = data.get("ip", "").strip()
    reason = sanitize_reason(data.get("reason", "Manual block"))

    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    existing = BlockedIP.query.filter_by(ip_address=ip).first()
    if existing and existing.is_active:
        # Already blocked — just emit event so UI updates
        socketio.emit("ip_blocked", {
            "ip": ip, "reason": existing.reason,
            "blocked_by": existing.blocked_by,
            "timestamp": datetime.utcnow().isoformat(),
        })
        return jsonify({"success": True, "ip": ip, "note": "already blocked"})

    sandbox_resp = _call_sandbox("BLOCK", ip)

    if existing:
        existing.is_active  = True
        existing.reason     = reason
        existing.blocked_by = current_user.username
        existing.blocked_at = datetime.utcnow()
    else:
        db.session.add(BlockedIP(
            ip_address=ip, reason=reason,
            blocked_by=current_user.username
        ))

    Attack.query.filter_by(source_ip=ip, status="active").update({"status": "blocked"})

    db.session.add(ResponseLog(
        action="BLOCK", target_ip=ip,
        performed_by=current_user.username,
        status=sandbox_resp.get("status", "unknown"),
        message=sandbox_resp.get("message", ""),
        sandbox_response=sandbox_resp,
    ))
    db.session.commit()

    socketio.emit("ip_blocked", {
        "ip": ip, "reason": reason,
        "blocked_by": current_user.username,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return jsonify({"success": True, "ip": ip})


@api_bp.route("/unblock", methods=["POST"])
@login_required
def unblock_ip():
    data = request.get_json() or {}
    ip   = data.get("ip", "").strip()

    if not is_valid_ip(ip):
        return jsonify({"error": "Invalid IP address"}), 400

    block = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
    if not block:
        return jsonify({"error": "IP not currently blocked"}), 404

    sandbox_resp    = _call_sandbox("UNBLOCK", ip)
    block.is_active = False

    db.session.add(ResponseLog(
        action="UNBLOCK", target_ip=ip,
        performed_by=current_user.username,
        status=sandbox_resp.get("status", "unknown"),
        message=sandbox_resp.get("message", ""),
        sandbox_response=sandbox_resp,
    ))
    db.session.commit()

    socketio.emit("ip_unblocked", {
        "ip": ip, "unblocked_by": current_user.username,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return jsonify({"success": True, "ip": ip})


# ── Ignore ────────────────────────────────────────────────────────────────────

@api_bp.route("/ignore", methods=["POST"])
@login_required
def ignore_alert():
    data      = request.get_json() or {}
    attack_id = data.get("attack_id")
    if not attack_id:
        return jsonify({"error": "attack_id required"}), 400
    attack = Attack.query.get(attack_id)
    if not attack:
        return jsonify({"error": "Not found"}), 404
    if attack.status != "active":
        return jsonify({"error": f"Already {attack.status}"}), 409
    attack.status   = "ignored"
    attack.resolved = True
    db.session.commit()
    socketio.emit("alert_ignored", {
        "attack_id":  attack_id,
        "ip":         attack.source_ip,
        "ignored_by": current_user.username,
    })
    return jsonify({"success": True, "attack_id": attack_id})


# ── Stats ─────────────────────────────────────────────────────────────────────

@api_bp.route("/stats")
@login_required
def stats():
    from ...simulator_manager import simulator_manager
    return jsonify({
        "total_attacks":     Attack.query.count(),
        "active_alerts":     Attack.query.filter_by(status="active").count(),
        "blocked_alerts":    Attack.query.filter_by(status="blocked").count(),
        "ignored_alerts":    Attack.query.filter_by(status="ignored").count(),
        "blocked_ips":       BlockedIP.query.filter_by(is_active=True).count(),
        "simulator_running": simulator_manager.running,
    })


@api_bp.route("/attacks")
@login_required
def list_attacks():
    limit  = min(int(request.args.get("limit", 100)), 500)
    status = request.args.get("status")
    q = Attack.query.order_by(Attack.detected_at.desc())
    if status:
        q = q.filter_by(status=status)
    return jsonify([a.to_dict() for a in q.limit(limit).all()])


@api_bp.route("/blocked-ips")
@login_required
def list_blocked():
    ips = BlockedIP.query.filter_by(is_active=True).all()
    return jsonify([{
        "id":         b.id,
        "ip":         b.ip_address,
        "reason":     b.reason,
        "blocked_by": b.blocked_by,
        "blocked_at": b.blocked_at.isoformat(),
    } for b in ips])


# ── ML ────────────────────────────────────────────────────────────────────────

@api_bp.route("/ml/stats")
@login_required
def ml_stats():
    try:
        from ...ml.isolation_forest import anomaly_detector
        return jsonify(anomaly_detector.get_stats())
    except Exception as e:
        return jsonify({"error": str(e), "model_ready": False,
                        "training_samples": 0, "min_samples_needed": 100,
                        "total_anomalies": 0, "anomaly_rate": 0})


@api_bp.route("/ml/retrain", methods=["POST"])
@login_required
def ml_retrain():
    if not current_user.is_admin():
        return jsonify({"error": "Admin only"}), 403
    from ...ml.isolation_forest import anomaly_detector
    success = anomaly_detector.retrain()
    return jsonify({"success": success, "stats": anomaly_detector.get_stats()})


@api_bp.route("/ml/reset", methods=["POST"])
@login_required
def ml_reset():
    if not current_user.is_admin():
        return jsonify({"error": "Admin only"}), 403
    from ...ml.isolation_forest import anomaly_detector
    anomaly_detector.reset()
    return jsonify({"success": True})
