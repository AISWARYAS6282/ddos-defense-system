"""
app/blueprints/api/health.py  —  Division 3
/health and /metrics endpoints.
"""
import time
from flask import jsonify
from . import api_bp
from ...extensions import db
from ...models.attack import Attack
from ...models.blocked_ip import BlockedIP

_start_time = time.time()


@api_bp.route("/health")
def health():
    """Basic health check — returns 200 if app + DB are up."""
    try:
        db.session.execute(db.text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    status = "healthy" if db_ok else "degraded"
    code = 200 if db_ok else 503

    return jsonify({
        "status": status,
        "database": "up" if db_ok else "down",
        "uptime_seconds": round(time.time() - _start_time),
    }), code


@api_bp.route("/metrics")
def metrics():
    """Returns key system metrics."""
    from ...simulator_manager import simulator_manager

    try:
        total_attacks   = Attack.query.count()
        active_alerts   = Attack.query.filter_by(status="active").count()
        blocked_alerts  = Attack.query.filter_by(status="blocked").count()
        ignored_alerts  = Attack.query.filter_by(status="ignored").count()
        blocked_ips     = BlockedIP.query.filter_by(is_active=True).count()

        # Severity breakdown
        severity_counts = {}
        for sev in ("low", "medium", "high", "critical"):
            severity_counts[sev] = Attack.query.filter_by(severity=sev).count()

        # Top 5 attacker IPs
        from sqlalchemy import func
        top_ips = (
            db.session.query(Attack.source_ip, func.count(Attack.id).label("count"))
            .group_by(Attack.source_ip)
            .order_by(func.count(Attack.id).desc())
            .limit(5)
            .all()
        )

        return jsonify({
            "uptime_seconds":   round(time.time() - _start_time),
            "simulator_running": simulator_manager.running,
            "attacks": {
                "total":   total_attacks,
                "active":  active_alerts,
                "blocked": blocked_alerts,
                "ignored": ignored_alerts,
            },
            "blocked_ips": blocked_ips,
            "severity_breakdown": severity_counts,
            "top_attacker_ips": [
                {"ip": ip, "count": count} for ip, count in top_ips
            ],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
