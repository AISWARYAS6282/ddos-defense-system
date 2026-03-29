"""
app/blueprints/dashboard/routes.py  —  Division 3 (COMPLETE + FIXED)
"""
import csv
import io
from flask import render_template, redirect, url_for, flash, request, abort, Response
from flask_login import login_required, current_user
from . import dashboard_bp
from ...extensions import db
from ...models.user import User
from ...models.attack import Attack
from ...models.blocked_ip import BlockedIP
from ...models.response_log import ResponseLog
from ...models.simulator_config import SimulatorConfig


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


@dashboard_bp.route("/")
@login_required
def index():
    from ...simulator_manager import simulator_manager
    total_attacks  = Attack.query.count()
    active_alerts  = Attack.query.filter_by(status="active").count()
    total_blocked  = BlockedIP.query.filter_by(is_active=True).count()
    recent_attacks = Attack.query.order_by(Attack.detected_at.desc()).limit(50).all()
    sim_config     = SimulatorConfig.query.first()
    return render_template(
        "dashboard/index.html",
        total_attacks=total_attacks,
        active_alerts=active_alerts,
        total_blocked=total_blocked,
        recent_attacks=recent_attacks,
        sim_config=sim_config,
        sim_running=simulator_manager.running,
    )


@dashboard_bp.route("/blocked-ips")
@login_required
def blocked_ips():
    ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
    return render_template("dashboard/blocked_ips.html", ips=ips)


@dashboard_bp.route("/simulator", methods=["GET", "POST"])
@login_required
@admin_required
def simulator():
    config = SimulatorConfig.query.first()
    if request.method == "POST":
        config.attack_rate  = float(request.form.get("attack_rate", 1.0))
        config.attack_ratio = float(request.form.get("attack_ratio", 0.3))
        config.updated_by   = current_user.username
        db.session.commit()
        flash("Simulator config updated.", "success")
        return redirect(url_for("dashboard.simulator"))
    return render_template("dashboard/simulator.html", config=config)


@dashboard_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    return render_template("dashboard/users.html", users=all_users)


@dashboard_bp.errorhandler(403)
def forbidden(e):
    return render_template("dashboard/403.html"), 403


# ── Audit CSV Export ──────────────────────────────────────────────────────────

@dashboard_bp.route("/audit/export/csv")
@login_required
def export_audit_csv():
    if not current_user.is_admin():
        abort(403)
    logs = ResponseLog.query.order_by(ResponseLog.id.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Action", "Target IP", "Performed By",
                     "Status", "Message", "Timestamp"])
    for log in logs:
        # Handle both field names: performed_at and timestamp
        ts = getattr(log, "performed_at", None) or getattr(log, "timestamp", None)
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""
        writer.writerow([
            log.id, log.action, log.target_ip,
            log.performed_by, log.status,
            log.message or "", ts_str,
        ])
    output.seek(0)
    return Response(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"}
    )


@dashboard_bp.route("/audit/export/attacks/csv")
@login_required
def export_attacks_csv():
    attacks = Attack.query.order_by(Attack.detected_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Source IP", "Attack Type", "Severity",
                     "Confidence %", "Packet Count", "Status",
                     "Simulated", "Detected At"])
    for a in attacks:
        writer.writerow([
            a.id, a.source_ip, a.attack_type or "RATE_ANOMALY",
            a.severity, f"{int((a.confidence or 0) * 100)}%",
            a.packet_count or 0, a.status,
            "Yes" if a.is_simulated else "No",
            a.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        ])
    output.seek(0)
    return Response(
        output.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks_log.csv"}
    )
