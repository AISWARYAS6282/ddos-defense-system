"""
app/simulator_manager.py  —  FINAL
Generates CICIDS2017-style traffic so XGBoost gives real predictions.
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


def generate_cicids_features(is_attack: bool) -> dict:
    """
    Generate realistic CICIDS2017-style flow features.
    Attack traffic matches DDoS patterns from the dataset.
    Normal traffic matches BENIGN patterns.
    """
    if is_attack:
        # DDoS pattern from CICIDS2017:
        # - Very high packet rate
        # - Large packet sizes (amplification)
        # - Very short inter-arrival times
        # - Almost no backward traffic (one-way flood)
        flow_duration     = random.randint(1, 100)
        fwd_packets       = random.randint(500, 5000)
        bwd_packets       = random.randint(0, 5)
        fwd_pkt_len_mean  = random.uniform(1400, 1480)
        bwd_pkt_len_mean  = 0.0
        flow_bytes_s      = random.uniform(1e7, 1e9)
        flow_packets_s    = random.uniform(1e4, 1e6)
        flow_iat_mean     = random.uniform(0.1, 5.0)
        syn_flag          = 1
        ack_flag          = 0
        down_up_ratio     = 0.0
        packet_count      = fwd_packets
    else:
        # BENIGN pattern:
        # - Normal packet rate
        # - Mixed packet sizes
        # - Normal inter-arrival times
        # - Two-way traffic
        flow_duration     = random.randint(1000, 100000)
        fwd_packets       = random.randint(5, 100)
        bwd_packets       = random.randint(5, 100)
        fwd_pkt_len_mean  = random.uniform(100, 800)
        bwd_pkt_len_mean  = random.uniform(100, 800)
        flow_bytes_s      = random.uniform(1000, 100000)
        flow_packets_s    = random.uniform(1, 100)
        flow_iat_mean     = random.uniform(100, 10000)
        syn_flag          = 0
        ack_flag          = 1
        down_up_ratio     = random.uniform(0.5, 2.0)
        packet_count      = fwd_packets + bwd_packets

    return {
        "flow_duration":    flow_duration,
        "fwd_packets":      fwd_packets,
        "bwd_packets":      bwd_packets,
        "fwd_pkt_len_mean": fwd_pkt_len_mean,
        "bwd_pkt_len_mean": bwd_pkt_len_mean,
        "flow_bytes_s":     flow_bytes_s,
        "flow_packets_s":   flow_packets_s,
        "flow_iat_mean":    flow_iat_mean,
        "syn_flag":         syn_flag,
        "ack_flag":         ack_flag,
        "down_up_ratio":    down_up_ratio,
        "packet_count":     packet_count,
    }


def generate_event(blocked_ips: set, attack_ratio: float = 0.3) -> dict:
    is_attack   = random.random() < attack_ratio
    pool        = ATTACKER_IPS if is_attack else NORMAL_IPS
    available   = [ip for ip in pool if ip not in blocked_ips] or NORMAL_IPS
    source_ip   = random.choice(available)
    attack_type = random.choice(ATTACK_TYPES) if is_attack else None

    # Generate CICIDS2017-style features
    cic = generate_cicids_features(is_attack)

    severity = None
    if is_attack:
        pps = cic["flow_packets_s"]
        if pps > 1e6:
            severity = "critical"
        elif pps > 1e5:
            severity = "high"
        elif pps > 1e4:
            severity = "medium"
        else:
            severity = "low"

    return {
        "timestamp":        datetime.utcnow().isoformat() + "Z",
        "source_ip":        source_ip,
        "is_attack":        is_attack,
        "attack_type":      attack_type,
        "severity":         severity,
        "packet_count":     int(cic["packet_count"]),
        "protocol":         random.choice(["TCP","UDP","ICMP"]) if is_attack else "TCP",
        "simulated":        True,
        # CICIDS2017 features for ML scoring
        "flow_duration":    cic["flow_duration"],
        "fwd_packets":      cic["fwd_packets"],
        "bwd_packets":      cic["bwd_packets"],
        "fwd_pkt_len_mean": cic["fwd_pkt_len_mean"],
        "bwd_pkt_len_mean": cic["bwd_pkt_len_mean"],
        "flow_bytes_s":     cic["flow_bytes_s"],
        "flow_packets_s":   cic["flow_packets_s"],
        "flow_iat_mean":    cic["flow_iat_mean"],
        "syn_flag":         cic["syn_flag"],
        "ack_flag":         cic["ack_flag"],
        "down_up_ratio":    cic["down_up_ratio"],
    }


def _try_ml_score(event: dict) -> dict:
    try:
        from .ml.isolation_forest import anomaly_detector
        return anomaly_detector.score_event(event)
    except Exception:
        return {"anomaly_score": 0.0, "is_anomaly": False,
                "model_ready": False, "model_type": "none",
                "prediction": "unknown"}


def _try_geo(ip: str) -> dict:
    try:
        from .geoip import lookup
        return lookup(ip)
    except Exception:
        return {"flag": "🌍", "country": "Unknown", "city": "Unknown"}


def _do_auto_block(ip, app, db, BlockedIP, Attack, ResponseLog, socketio, geo) -> bool:
    try:
        existing = BlockedIP.query.filter_by(ip_address=ip, is_active=True).first()
        if existing:
            return False
        reason = f"Auto-blocked: 3+ alerts in 5 min ({geo['flag']} {geo['country']})"
        db.session.add(BlockedIP(ip_address=ip, reason=reason, blocked_by="system"))
        Attack.query.filter_by(source_ip=ip, status="active").update({"status": "blocked"})
        db.session.add(ResponseLog(
            action="AUTO_BLOCK", target_ip=ip, performed_by="system",
            status="success", message=reason, sandbox_response={"auto": True},
        ))
        db.session.commit()
        socketio.emit("ip_blocked", {
            "ip": ip, "reason": reason,
            "blocked_by": "🤖 Auto-block",
            "timestamp": datetime.utcnow().isoformat(),
            "auto": True,
        })
        return True
    except Exception as e:
        logger.error(f"[AutoBlock] {e}")
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

                # ML scoring with real XGBoost
                ml  = _try_ml_score(event)
                geo = _try_geo(ip)

                # Emit live ticker
                socketio.emit("sim_event", {
                    "ip":        ip,
                    "is_attack": event["is_attack"],
                    "type":      event.get("attack_type"),
                    "packets":   event["packet_count"],
                    "timestamp": event["timestamp"],
                    "ml_anomaly": bool(ml.get("is_anomaly", False)),
                    "ml_score":   float(ml.get("anomaly_score", 0.0)),
                    "ml_ready":   bool(ml.get("model_ready", False)),
                    "flag":       geo.get("flag", "🌍"),
                    "country":    geo.get("country", "Unknown"),
                })

                # Rule-based detection
                alerts = engine.process_event(event)

                for alert in alerts:
                    # Blend ML confidence
                    confidence = alert.confidence
                    if ml.get("model_ready") and ml.get("is_anomaly"):
                        confidence = min(
                            confidence + float(ml.get("anomaly_score", 0)) * 0.1,
                            0.99
                        )

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
                        "ml_score":   float(ml.get("anomaly_score", 0.0)),
                        "ml_flagged": bool(ml.get("is_anomaly", False)),
                        "ml_prediction": str(ml.get("prediction", "unknown")),
                        "flag":       geo.get("flag", "🌍"),
                        "country":    geo.get("country", "Unknown"),
                        "city":       geo.get("city", "Unknown"),
                    })

                    # Auto-block check
                    if record_alert(alert.source_ip):
                        if _do_auto_block(alert.source_ip, app, db,
                                         BlockedIP, Attack, ResponseLog,
                                         socketio, geo):
                            clear_ip(alert.source_ip)

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
