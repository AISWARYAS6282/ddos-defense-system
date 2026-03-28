"""
app/blueprints/dashboard/audit.py  —  Division 3
CSV export of response_logs audit trail.
"""
import csv
import io
from flask import Response, abort
from flask_login import login_required, current_user
from . import dashboard_bp
from ...models.response_log import ResponseLog
from ...models.attack import Attack


@dashboard_bp.route("/audit/export/csv")
@login_required
def export_audit_csv():
    """Download all response_logs as a CSV file."""
    if not current_user.is_admin():
        abort(403)

    logs = ResponseLog.query.order_by(ResponseLog.performed_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "ID", "Action", "Target IP", "Performed By",
        "Status", "Message", "Timestamp"
    ])

    for log in logs:
        writer.writerow([
            log.id,
            log.action,
            log.target_ip,
            log.performed_by,
            log.status,
            log.message or "",
            log.performed_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"}
    )


@dashboard_bp.route("/audit/export/attacks/csv")
@login_required
def export_attacks_csv():
    """Download all attacks as a CSV file."""
    attacks = Attack.query.order_by(Attack.detected_at.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID", "Source IP", "Attack Type", "Severity",
        "Confidence %", "Packet Count", "Status",
        "Simulated", "Detected At"
    ])

    for a in attacks:
        writer.writerow([
            a.id,
            a.source_ip,
            a.attack_type or "RATE_ANOMALY",
            a.severity,
            f"{int((a.confidence or 0) * 100)}%",
            a.packet_count or 0,
            a.status,
            "Yes" if a.is_simulated else "No",
            a.detected_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=attacks_log.csv"}
    )
