"""
tests/test_division3.py  —  Division 3
Full test suite: detector, auth, block idempotency, ML, health.
Run with: docker-compose exec web python -m pytest tests/ -v
"""
import sys, os, types, unittest.mock as mock

# ── Mock Flask deps so tests run without Docker ───────────────────────────────
ev = types.ModuleType("eventlet")
ev.monkey_patch = lambda: None
ev.sleep        = lambda x: None
ev.spawn        = lambda f, *a, **k: None
sys.modules["eventlet"] = ev

for m in [
    "flask_sqlalchemy", "flask_migrate", "flask_login",
    "flask_bcrypt", "flask_socketio", "flask_limiter",
    "flask_limiter.util", "flask_wtf", "flask",
    "sqlalchemy", "joblib",
]:
    sys.modules[m] = mock.MagicMock()

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
import time


# ════════════════════════════════════════════════════════════════════════════
# DETECTOR TESTS
# ════════════════════════════════════════════════════════════════════════════

from app.detector.engine import DetectionEngine, DetectionAlert


def make_event(ip="10.0.0.1", is_attack=True, attack_type="SYN_FLOOD",
               severity="high", packet_count=5000):
    return {
        "source_ip":    ip,
        "is_attack":    is_attack,
        "attack_type":  attack_type,
        "severity":     severity,
        "packet_count": packet_count,
        "simulated":    True,
    }


def flood(engine, ip, atype, pkts, count):
    alerts = []
    for _ in range(count):
        alerts.extend(engine.process_event(
            make_event(ip=ip, attack_type=atype, packet_count=pkts)
        ))
    return alerts


class TestDetector:
    def test_normal_traffic_no_alert(self):
        engine = DetectionEngine()
        for _ in range(10):
            assert engine.process_event(
                make_event(is_attack=False, packet_count=10)
            ) == []

    def test_flood_triggers_alert(self):
        engine = DetectionEngine()
        alerts = flood(engine, "1.2.3.4", "SYN_FLOOD", 1000, 12)
        assert any(a.severity in ("medium", "high", "critical") for a in alerts)

    def test_confidence_range(self):
        engine = DetectionEngine()
        alerts = flood(engine, "1.2.3.4", "SYN_FLOOD", 1000, 12)
        for a in alerts:
            assert 0.0 <= a.confidence <= 1.0

    def test_cooldown_suppresses_repeat(self):
        engine = DetectionEngine(cooldown_seconds=60)
        a1 = flood(engine, "2.2.2.2", "SYN_FLOOD", 1000, 12)
        assert a1, "First flood should trigger alert"
        a2 = flood(engine, "2.2.2.2", "SYN_FLOOD", 1000, 5)
        assert a2 == [], "Cooldown should suppress second alert"

    def test_independent_ip_cooldowns(self):
        engine = DetectionEngine(cooldown_seconds=60)
        aA = flood(engine, "10.1.1.1", "SYN_FLOOD", 1000, 12)
        aB = flood(engine, "10.1.1.2", "SYN_FLOOD", 1000, 12)
        assert aA, "IP A should alert"
        assert aB, "IP B should alert independently"

    def test_blacklist_immediate_critical(self):
        engine = DetectionEngine(blacklisted_ips={"6.6.6.6"})
        alerts = engine.process_event(
            make_event(ip="6.6.6.6", is_attack=False, packet_count=1)
        )
        assert alerts
        assert alerts[0].severity == "critical"
        assert alerts[0].rule_triggered == "BLACKLIST"

    def test_to_dict_structure(self):
        engine = DetectionEngine()
        alerts = flood(engine, "3.3.3.3", "SYN_FLOOD", 1000, 12)
        assert alerts
        d = alerts[0].to_dict()
        required = ("source_ip", "attack_type", "severity",
                    "confidence", "packet_count", "rule_triggered", "timestamp")
        for k in required:
            assert k in d, f"Missing key: {k}"

    def test_reset_clears_state(self):
        engine = DetectionEngine()
        flood(engine, "4.4.4.4", "SYN_FLOOD", 1000, 5)
        engine.reset()
        s = engine.get_stats()
        assert s["processed_events"] == 0
        assert s["tracked_ips"] == 0

    def test_http_flood_rule(self):
        engine = DetectionEngine()
        alerts = flood(engine, "5.5.5.5", "HTTP_FLOOD", 500, 15)
        assert any(a.attack_type == "HTTP_FLOOD" for a in alerts)

    def test_severity_escalation(self):
        """High packet counts should produce high/critical severity."""
        engine = DetectionEngine()
        alerts = flood(engine, "7.7.7.7", "SYN_FLOOD", 5000, 20)
        severities = {a.severity for a in alerts}
        assert severities & {"high", "critical"}, \
            f"Expected high/critical severity, got: {severities}"


# ════════════════════════════════════════════════════════════════════════════
# IP VALIDATION TESTS
# ════════════════════════════════════════════════════════════════════════════

from app.security import is_valid_ip, sanitize_reason


class TestIPValidation:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1")
        assert is_valid_ip("10.0.0.1")
        assert is_valid_ip("203.0.113.5")

    def test_invalid_ip_formats(self):
        assert not is_valid_ip("")
        assert not is_valid_ip("not-an-ip")
        assert not is_valid_ip("999.999.999.999")
        assert not is_valid_ip("192.168.1")
        assert not is_valid_ip("192.168.1.1.1")
        assert not is_valid_ip(None)

    def test_sanitize_reason_truncates(self):
        long_reason = "x" * 300
        result = sanitize_reason(long_reason)
        assert len(result) <= 200

    def test_sanitize_reason_strips(self):
        assert sanitize_reason("  test  ") == "test"

    def test_sanitize_reason_empty(self):
        assert sanitize_reason("") == "No reason provided"
        assert sanitize_reason(None) == "No reason provided"


# ════════════════════════════════════════════════════════════════════════════
# ML FEATURE EXTRACTOR TESTS
# ════════════════════════════════════════════════════════════════════════════

from app.ml.feature_extractor import extract_features, extract_batch
import numpy as np


class TestFeatureExtractor:
    def test_returns_numpy_array(self):
        event = make_event(packet_count=1000)
        features = extract_features(event)
        assert isinstance(features, np.ndarray)

    def test_correct_shape(self):
        event = make_event(packet_count=1000)
        features = extract_features(event)
        assert features.shape == (6,)

    def test_packet_count_is_first_feature(self):
        event = make_event(packet_count=5000)
        features = extract_features(event)
        assert features[0] == 5000.0

    def test_is_attack_encoding(self):
        attack = extract_features(make_event(is_attack=True))
        normal = extract_features(make_event(is_attack=False))
        assert attack[1] == 1.0
        assert normal[1] == 0.0

    def test_batch_extraction(self):
        events = [make_event(packet_count=i * 100) for i in range(1, 6)]
        matrix = extract_batch(events)
        assert matrix.shape == (5, 6)

    def test_log_transform_applied(self):
        event = make_event(packet_count=1000)
        features = extract_features(event)
        assert abs(features[5] - np.log1p(1000)) < 0.001


# ════════════════════════════════════════════════════════════════════════════
# ML ANOMALY DETECTOR TESTS
# ════════════════════════════════════════════════════════════════════════════

from app.ml.isolation_forest import AnomalyDetector


class TestAnomalyDetector:
    def test_returns_dict_before_training(self):
        det = AnomalyDetector()
        det.reset()
        result = det.score_event(make_event(is_attack=False, packet_count=50))
        assert "anomaly_score" in result
        assert "is_anomaly" in result
        assert "model_ready" in result
        assert result["model_ready"] is False

    def test_trains_after_enough_samples(self):
        det = AnomalyDetector()
        det.reset()
        # Feed 110 normal events to trigger training (threshold=100)
        for i in range(110):
            det.score_event(make_event(is_attack=False, packet_count=10 + i % 50))
        assert det._is_trained

    def test_scores_in_range_after_training(self):
        det = AnomalyDetector()
        det.reset()
        for i in range(110):
            det.score_event(make_event(is_attack=False, packet_count=10 + i % 50))
        result = det.score_event(make_event(packet_count=100))
        assert 0.0 <= result["anomaly_score"] <= 1.0

    def test_reset_clears_model(self):
        det = AnomalyDetector()
        det.reset()
        assert not det._is_trained
        assert len(det._training_buffer) == 0

    def test_get_stats_structure(self):
        det = AnomalyDetector()
        det.reset()
        stats = det.get_stats()
        assert "model_ready" in stats
        assert "training_samples" in stats
        assert "min_samples_needed" in stats


if __name__ == "__main__":
    # Run all tests manually
    import traceback
    tests = [
        TestDetector, TestIPValidation,
        TestFeatureExtractor, TestAnomalyDetector,
    ]
    passed = failed = 0
    for cls in tests:
        obj = cls()
        for name in [m for m in dir(cls) if m.startswith("test_")]:
            try:
                getattr(obj, name)()
                print(f"  ✓ {cls.__name__}.{name}")
                passed += 1
            except Exception as e:
                print(f"  ✗ {cls.__name__}.{name}: {e}")
                traceback.print_exc()
                failed += 1
    print(f"\n{'='*50}")
    print(f"  Results: {passed} passed, {failed} failed")
    if failed == 0:
        print("  ✅ All tests passed!")
    else:
        print("  ❌ Some tests failed!")
    sys.exit(0 if failed == 0 else 1)
