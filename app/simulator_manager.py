"""
app/simulator_manager.py  —  Division 3 (FIXED)
Clean background loop. ML scoring is optional — never crashes the loop.
"""
import json
import os
import random
import time
from datetime import datetime

_pool_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "simulator", "ip_pools.json"
)
try:
    with open(_pool_path) as f:
        _pools = json.load(f)
    NORMAL_IPS   = _pools["normal_ips"]
    ATTACKER_IPS = _pools["attacker_ips"]
    ATTACK_TYPES = _pools["attack_types"]
except Exception:
    NORMAL_IPS   = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]
    ATTACKER_IPS = ["192.168.100.10", "192.168.100.11", "192.168.100.12",
                    "203.0.113.5", "203.0.113.6"]
    ATTACK_TYPES = ["SYN_FLOOD", "UDP_FLOOD", "HTTP_FLOOD",
                    "ICMP_FLOOD", "DNS_AMPLIFICATION"]


def generate_event(blocked_ips: set, attack_ratio: float = 0.3) -> dict:
    is_attack = random.random() < attack_ratio
    pool      = ATTACKER_IPS if is_attack else NORMAL_IPS
    available = [ip for ip in pool if ip not in blocked_ips]
    if not available:
        available = NORMAL_IPS  # fall back to normal if all attackers blocked
    source_ip   = random.choice(available)
    attack_type = random.choice(ATTACK_TYPES) if is_attack else None
    severity     = None
    packet_count = random.randint(1, 100)
    if is_attack:
        severity = random.choices(
            ["low", "medium", "high", "critical"],
            weights=[30, 40, 25, 5]
        )[0]
        packet_count = {
            "low":      random.randint(200,   2000),
            "medium":   random.randint(2000,  10000),
            "high":     random.randint(10000, 50000),
            "critical": random.randint(50000, 200000),
        }[severity]
    return {
        "timestamp":      datetime.utcnow().isoformat() + "Z",
        "source_ip":      source_ip,
        "destination_ip": "10.10.10.1",
        "is_attack":      is_attack,
        "attack_type":    attack_type,
        "severity":       severity,
        "packet_count":   packet_count,
        "protocol":       random.choice(["TCP", "UDP", "ICMP"]) if is_attack else "TCP",
        "simulated":      True,
    }


def _try_ml_score(event: dict) -> dict:
    """Score with ML — returns safe default if ML not ready or errors."""
    try:
        from .ml.isolation_forest import anomaly_detector
        return anomaly_detector.score_event(event)
    except Exception:
        return {"anomaly_score": 0.0, "is_anomaly": False, "model_ready": False}


def _run_loop(socketio, app, manager):
    from .extensions import db
    from .models.blocked_ip import BlockedIP
    from .models.attack import Attack
    from .models.simulator_config import SimulatorConfig
    from .detector.engine import DetectionEngine

    engine = DetectionEngine()

    with app.app_context():
        cfg = SimulatorConfig.query.first()
        if cfg:
            cfg.is_running = True
            db.session.commit()

    while manager._running:
        interval = 1.0
        try:
            with app.app_context():
                cfg          = SimulatorConfig.query.first()
                rate         = cfg.attack_rate  if cfg else 1.0
                attack_ratio = cfg.attack_ratio if cfg else 0.3

                # Get currently blocked IPs
                blocked = {
                    b.ip_address
                    for b in BlockedIP.query.filter_by(is_active=True).all()
                }

                event = generate_event(blocked, attack_ratio)

                # ML scoring (never crashes loop)
                ml = _try_ml_score(event)

                # Emit to live ticker
                # Emit to live ticker
                # Emit to live ticker
                socketio.emit("sim_event", {
                    "ip":        event["source_ip"],
                    "is_attack": event["is_attack"],
                    "type":      event.get("attack_type"),
                    "packets":   event["packet_count"],
                    "timestamp": event["timestamp"],
                    "ml_anomaly": bool(ml["is_anomaly"]),
                    "ml_score":   float(ml["anomaly_score"]),
                    "ml_ready":   bool(ml["model_ready"]),
                })

                # Rule-based detection
                alerts = engine.process_event(event)

                for alert in alerts:
                    # Boost confidence if ML also flagged it
                    confidence = alert.confidence
                    if ml["model_ready"] and ml["is_anomaly"]:
                        confidence = min(confidence + ml["anomaly_score"] * 0.1, 0.99)

                    attack = Attack(
                        source_ip    = alert.source_ip,
                        attack_type  = alert.attack_type,
                        severity     = alert.severity,
                        confidence   = confidence,
                        packet_count = alert.packet_count,
                        status       = "active",
                        is_simulated = True,
                        raw_event    = event,
                    )
                    db.session.add(attack)
                    db.session.commit()

                    socketio.emit("alert", {
                        **alert.to_dict(),
                        "id":         attack.id,
                        "confidence": int(confidence * 100),
                        "ml_score":   float(ml["anomaly_score"]),
                        "ml_flagged": bool(ml["is_anomaly"]),
                    })

                interval = max(1.0 / rate, 0.05)

        except Exception as e:
            try:
                app.logger.error(f"[Simulator] {e}")
            except Exception:
                pass
            interval = 1.0

        try:
            import eventlet
            eventlet.sleep(interval)
        except ImportError:
            time.sleep(interval)

    # Cleanup
    try:
        with app.app_context():
            cfg = SimulatorConfig.query.first()
            if cfg:
                cfg.is_running = False
                db.session.commit()
    except Exception:
        pass


class SimulatorManager:
    def __init__(self):
        self._running  = False
        self._greenlet = None

    @property
    def running(self) -> bool:
        return self._running

    def start(self, socketio, app):
        if self._running:
            return False
        self._running = True
        try:
            import eventlet
            self._greenlet = eventlet.spawn(_run_loop, socketio, app, self)
        except ImportError:
            import threading
            t = threading.Thread(
                target=_run_loop, args=(socketio, app, self), daemon=True
            )
            t.start()
        return True

    def stop(self):
        self._running = False
        if self._greenlet is not None:
            try:
                self._greenlet.kill()
            except Exception:
                pass
            self._greenlet = None


simulator_manager = SimulatorManager()
