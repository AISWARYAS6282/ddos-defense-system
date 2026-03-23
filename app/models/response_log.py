from ..extensions import db
from datetime import datetime


class ResponseLog(db.Model):
    __tablename__ = "response_logs"

    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(64))                # BLOCK, UNBLOCK, ALERT
    target_ip = db.Column(db.String(45), index=True)
    performed_by = db.Column(db.String(64))          # username or 'system'
    status = db.Column(db.String(20))                # success, failed, stubbed
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sandbox_response = db.Column(db.JSON, nullable=True)

    def __repr__(self):
        return f"<ResponseLog {self.action} {self.target_ip} [{self.status}]>"
