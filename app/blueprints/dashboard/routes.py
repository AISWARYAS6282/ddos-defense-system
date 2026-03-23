from flask import render_template, redirect, url_for, flash, request, abort
from flask_login import login_required, current_user
from . import dashboard_bp
from ...extensions import db
from ...models.user import User
from ...models.attack import Attack
from ...models.blocked_ip import BlockedIP
from ...models.response_log import ResponseLog
from ...models.simulator_config import SimulatorConfig


def admin_required(f):
    """Decorator: restrict route to admin users only."""
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
    total_attacks = Attack.query.count()
    total_blocked = BlockedIP.query.filter_by(is_active=True).count()
    recent_attacks = Attack.query.order_by(Attack.detected_at.desc()).limit(10).all()
    recent_logs = ResponseLog.query.order_by(ResponseLog.timestamp.desc()).limit(10).all()
    sim_config = SimulatorConfig.query.first()
    return render_template(
        "dashboard/index.html",
        total_attacks=total_attacks,
        total_blocked=total_blocked,
        recent_attacks=recent_attacks,
        recent_logs=recent_logs,
        sim_config=sim_config,
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
        config.attack_rate = float(request.form.get("attack_rate", 1.0))
        config.attack_ratio = float(request.form.get("attack_ratio", 0.3))
        config.updated_by = current_user.username
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
