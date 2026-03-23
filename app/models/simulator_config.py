from ..extensions import db
from datetime import datetime


class SimulatorConfig(db.Model):
    __tablename__ = "simulator_config"

    id = db.Column(db.Integer, primary_key=True)
    attack_rate = db.Column(db.Float, default=1.0)       # events per second
    attack_ratio = db.Column(db.Float, default=0.3)      # fraction that are attacks
    attack_types = db.Column(db.JSON, default=list)
    normal_ip_pool = db.Column(db.JSON, default=list)
    attacker_ip_pool = db.Column(db.JSON, default=list)
    is_running = db.Column(db.Boolean, default=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )
    updated_by = db.Column(db.String(64))

    def __repr__(self):
        return f"<SimulatorConfig rate={self.attack_rate} running={self.is_running}>"
