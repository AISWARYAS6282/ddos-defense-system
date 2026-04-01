"""
app/simulator_manager.py  —  FINAL with auto-block + geolocation
"""
import json
import os
import random
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

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
    NORMAL_IPS   = ["10.0.0.1","10.0.0.2","10.0.0.3","10.0.0.4","10.0.0.5"]
    ATTACKER_IPS = ["192.168.100.10","192.168.100.11","192.168.100.12",
                    "203.0.113.5","203.0.113.6"]
    ATTACK_TYPES = ["SYN_FLOOD","UDP_FLOOD","HTTP_FLOOD",
                    "ICMP_FLOOD","DNS_AMPLIFICATION"]


def generate_event(blocked_ips: set, attack_ratio: float = 0.3) -> dict:
    is_attack   = random.random() < attack_ratio
    pool        = ATTACKER_IPS if is_attack else NORMAL_IPS
    available   = [ip for ip in pool if ip not in blocked_ips] or NORMAL_IPS
    source_ip   = random.choice(available)
    attack_type = random.choice(ATTACK_TYPES) if is_attack else None
    packet_count = random.randint(1, 100)
    severity     = None
    if is_attack:
        severity = random.choices(
            ["low","medium","high","critical"], weights=[30,40,25,5]
        )[0]
        packet_count = {
            "low":      random.randint(200,   2000),
            "medium":   random.randint(2000,  10000),
            "high":     random.randint(10000, 50000),
            "critical": random.randint(50000, 200000),
        }[severity]
    return {
        "timestamp":    datetime.utcnow().isoformat() + "Z",
        "source_ip":    source_ip,
        "is_attack":    is_attack,
        "attack_type":  attack_type,
        "severity":     severity,
        "packet_count": packet_count,
        "protocol":     random.choice(["TCP","UDP","ICMP"]) if is_attack else "TCP",
        "simulated":    True,
    }


def _try_ml_score(event: dict) -> dict:
    try:
        from .ml.isolation_forest import anomaly_detector
        return anomaly_detector.score_event(event)
    except Exception:
        return {"anomaly_score": 0.0, "is_anomaly": False, "model_ready": False}


def _try_geo(ip: str) -> dict:
    try:
        from .geoip import lookup
        return lookup(ip)
    except Exception:
        return {"flag": "🌍", "country": "Unknown", "city": "Unknown"}


def _do_auto_block(ip: str, app, db, BlockedIP, Attack, ResponseLog,
                   socketio) -> bool:
    """Block an IP automatically. Returns True if blocked."""
    try:
        existing = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
        if existing:
            return False  # already blocked

        geo = _try_geo(ip)
        reason = f"Auto-blocked: 3+ alerts in 5 min ({geo['flag']} {geo['country']})"

        new_block = BlockedIP(
            ip_address=ip,
            reason=reason,
            blocked_by="system",
        )
        db.session.add(new_block)
        Attack.query.filter_by(source_ip=ip, status="active").update(
            {"status": "blocked"}
        )
        db.session.add(ResponseLog(
            action="AUTO_BLOCK",
            target_ip=ip,
            performed_by="system",
            status="success",
            message=reason,
            sandbox_response={"auto": True},
        ))
        db.session.commit()

        socketio.emit("ip_blocked", {
            "ip":         ip,
            "reason":     reason,
            "blocked_by": "🤖 Auto-block",
            "timestamp":  datetime.utcnow().isoformat(),
            "auto":       True,
        })
        logger.info(f"[AutoBlock] Blocked {ip} — {reason}")
        return True
    except Exception as e:
        logger.error(f"[AutoBlock] Failed for {ip}: {e}")
        db.session.rollback()
        return False


def _run_loop(socketio, app, manager):
    with app.app_context():
        from .extensions import db
        from .models.blocked_ip import BlockedIP
        from .models.attack import Attack
        from .models.simulator_config import SimulatorConfig
        from .models.response_log import ResponseLog
        from .detector.engine import DetectionEngine
        from .autoblock import record_alert, clear_ip

        engine = DetectionEngine()

        cfg = SimulatorConfig.query.first()
        if cfg:
            cfg.is_running = True
            db.session.commit()

        logger.info("[Simulator] Started.")

        while manager._running:
            try:
                cfg          = SimulatorConfig.query.first()
                rate         = cfg.attack_rate  if cfg else 1.0
                attack_ratio = cfg.attack_ratio if cfg else 0.3

                blocked = {
                    b.ip_address
                    for b in BlockedIP.query.filter_by(is_active=True).all()
                }

                event = generate_event(blocked, attack_ratio)
                ip    = event["source_ip"]

                # ML scoring
                ml = _try_ml_score(event)

                # Geolocation
                geo = _try_geo(ip)

                # Emit live ticker
                socketio.emit("sim_event", {
                    "ip":        ip,
                    "is_attack": event["is_attack"],
                    "type":      event.get("attack_type"),
                    "packets":   event["packet_count"],
                    "timestamp": event["timestamp"],
                    "ml_anomaly": bool(ml["is_anomaly"]),
                    "ml_score":   float(ml["anomaly_score"]),
                    "ml_ready":   bool(ml["model_ready"]),
                    "flag":       geo["flag"],
                    "country":    geo["country"],
                })

                # Detection
                alerts = engine.process_event(event)

                for alert in alerts:
                    confidence = alert.confidence
                    if ml["model_ready"] and ml["is_anomaly"]:
                        confidence = min(confidence + float(ml["anomaly_score"]) * 0.1, 0.99)

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
                        "flag":       geo["flag"],
                        "country":    geo["country"],
                        "city":       geo["city"],
                    })

                    # Auto-block check
                    should_block = record_alert(alert.source_ip)
                    if should_block:
                        auto_blocked = _do_auto_block(
                            alert.source_ip, app, db,
                            BlockedIP, Attack, ResponseLog, socketio
                        )
                        if auto_blocked:
                            clear_ip(alert.source_ip)
                            socketio.emit("auto_blocked", {
                                "ip":      alert.source_ip,
                                "reason":  "3+ alerts in 5 minutes",
                                "flag":    geo["flag"],
                                "country": geo["country"],
                            })

                interval = max(1.0 / rate, 0.05)

            except Exception as e:
                logger.error(f"[Simulator] {e}")
                try:
                    db.session.rollback()
                except Exception:
                    pass
                interval = 1.0

            try:
                import eventlet
                eventlet.sleep(interval)
            except Exception:
                time.sleep(interval)

        try:
            cfg = SimulatorConfig.query.first()
            if cfg:
                cfg.is_running = False
                db.session.commit()
        except Exception:
            pass
        logger.info("[Simulator] Stopped.")


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
