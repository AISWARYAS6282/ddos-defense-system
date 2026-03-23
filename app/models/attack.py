from ..extensions import db
from datetime import datetime


class Attack(db.Model):
    __tablename__ = 'attacks'

    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    attack_type = db.Column(db.String(64))
    severity = db.Column(db.String(20))         # low/medium/high/critical
    confidence = db.Column(db.Float, default=0.0)   # 0.0 to 1.0
    packet_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='active')  # active/blocked/ignored
    detected_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_simulated = db.Column(db.Boolean, default=True)
    raw_event = db.Column(db.JSON)
    resolved = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            'id': self.id,
            'source_ip': self.source_ip,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'confidence': round(self.confidence * 100),
            'packet_count': self.packet_count,
            'status': self.status,
            'detected_at': self.detected_at.isoformat(),
            'is_simulated': self.is_simulated,
        }

    def __repr__(self):
        return f'<Attack {self.source_ip} {self.attack_type} [{self.severity}]>'

