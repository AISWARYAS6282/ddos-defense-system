"""
app/simulator_manager.py  —  Division 3
Adds ML anomaly scoring to the detection pipeline.
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
    NORMAL_IPS   = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    ATTACKER_IPS = ["192.168.100.10", "192.168.100.11", "203.0.113.5"]
    ATTACK_TYPES = ["SYN_FLOOD", "UDP_FLOOD", "HTTP_FLOOD"]


def generate_event(blocked_ips: set, attack_ratio: float = 0.3) -> dict:
    is_attack = random.random() < attack_ratio
    pool      = ATTACKER_IPS if is_attack else NORMAL_IPS
    available = [ip for ip in pool if ip not in blocked_ips] or pool
    source_ip   = random.choice(available)
    attack_type = random.choice(ATTACK_TYPES) if is_attack else None
    severity     = None
    packet_count = random.randint(1, 100)
    if is_attack:
        severity = random.choices(
            ["low", "medium", "high", "critical"], weights=[30, 40, 25, 5]
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
        "bytes":          packet_count * random.randint(40, 1500),
        "protocol":       random.choice(["TCP", "UDP", "ICMP"]) if is_attack else "TCP",
        "simulated":      True,
    }


def _run_loop(socketio, app, manager):
    from .extensions import db
    from .models.blocked_ip import BlockedIP
    from .models.attack import Attack
    from .models.simulator_config import SimulatorConfig
    from .detector.engine import DetectionEngine
    from .ml.isolation_forest import anomaly_detector

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

                blocked = {
                    b.ip_address
                    for b in BlockedIP.query.filter_by(is_active=True).all()
                }

                event = generate_event(blocked, attack_ratio)

                # ── ML scoring ────────────────────────────────────────────
                ml_result = anomaly_detector.score_event(event)

                # Emit raw event + ML score to live ticker
                socketio.emit("sim_event", {
                    "ip":            event["source_ip"],
                    "is_attack":     event["is_attack"],
                    "type":          event.get("attack_type"),
                    "packets":       event["packet_count"],
                    "timestamp":     event["timestamp"],
                    "ml_anomaly":    ml_result["is_anomaly"],
                    "ml_score":      ml_result["anomaly_score"],
                    "ml_ready":      ml_result["model_ready"],
                })

                # ── Rule-based detection ──────────────────────────────────
                alerts = engine.process_event(event)

                for alert in alerts:
                    # Blend ML score into confidence
                    blended_confidence = alert.confidence
                    if ml_result["model_ready"] and ml_result["is_anomaly"]:
                        blended_confidence = min(
                            alert.confidence + ml_result["anomaly_score"] * 0.15,
                            0.99
                        )

                    attack = Attack(
                        source_ip    = alert.source_ip,
                        attack_type  = alert.attack_type,
                        severity     = alert.severity,
                        confidence   = blended_confidence,
                        packet_count = alert.packet_count,
                        status       = "active",
                        is_simulated = alert.is_simulated,
                        raw_event    = event,
                    )
                    db.session.add(attack)
                    db.session.commit()

                    socketio.emit("alert", {
                        **alert.to_dict(),
                        "id":              attack.id,
                        "confidence":      int(blended_confidence * 100),
                        "ml_score":        ml_result["anomaly_score"],
                        "ml_flagged":      ml_result["is_anomaly"],
                        "ml_model_ready":  ml_result["model_ready"],
                    })

                # Emit ML-only anomaly if no rule triggered but ML flagged it
                if not alerts and ml_result["model_ready"] and ml_result["is_anomaly"] \
                        and ml_result["anomaly_score"] > 0.7 and event.get("is_attack"):
                    attack = Attack(
                        source_ip    = event["source_ip"],
                        attack_type  = "ML_ANOMALY",
                        severity     = "medium",
                        confidence   = ml_result["anomaly_score"],
                        packet_count = event["packet_count"],
                        status       = "active",
                        is_simulated = True,
                        raw_event    = event,
                    )
                    db.session.add(attack)
                    db.session.commit()

                    socketio.emit("alert", {
                        "id":             attack.id,
                        "source_ip":      event["source_ip"],
                        "attack_type":    "ML_ANOMALY",
                        "severity":       "medium",
                        "confidence":     int(ml_result["anomaly_score"] * 100),
                        "packet_count":   event["packet_count"],
                        "status":         "active",
                        "detected_at":    datetime.utcnow().isoformat(),
                        "ml_score":       ml_result["anomaly_score"],
                        "ml_flagged":     True,
                        "ml_model_ready": True,
                    })

                interval = max(1.0 / rate, 0.05)

        except Exception as e:
            try:
                app.logger.error(f"[SimulatorManager] {e}")
            except Exception:
                pass
            interval = 1.0

        try:
            import eventlet
            eventlet.sleep(interval)
        except ImportError:
            time.sleep(interval)

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
