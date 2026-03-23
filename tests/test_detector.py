import time, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Mock Flask deps so tests run without Docker
import types, unittest.mock as mock
ev = types.ModuleType('eventlet')
ev.monkey_patch = lambda: None
sys.modules['eventlet'] = ev
for m in ['flask_sqlalchemy','flask_migrate','flask_login',
          'flask_bcrypt','flask_socketio','flask','sqlalchemy']:
    sys.modules[m] = mock.MagicMock()

from app.detector.engine import DetectionEngine, DetectionAlert

def make_event(ip='10.0.0.1', is_attack=True, attack_type='SYN_FLOOD',
               severity='high', packet_count=5000):
    return {'source_ip': ip, 'is_attack': is_attack, 'attack_type': attack_type,
            'severity': severity, 'packet_count': packet_count, 'simulated': True}

def flood(engine, ip, atype, pkts, count):
    alerts = []
    for _ in range(count):
        alerts.extend(engine.process_event(
            make_event(ip=ip, attack_type=atype, packet_count=pkts)))
    return alerts

def test_normal_no_alert():
    engine = DetectionEngine()
    for _ in range(10):
        assert engine.process_event(make_event(
            is_attack=False, packet_count=10)) == []
    print('✓ T1: normal traffic no alert')

def test_flood_triggers():
    engine = DetectionEngine()
    alerts = flood(engine, '1.2.3.4', 'SYN_FLOOD', 1000, 12)
    assert any(a.severity in ('medium','high','critical') for a in alerts)
    print('✓ T2: flood triggers alert')

def test_confidence_range():
    engine = DetectionEngine()
    alerts = flood(engine, '1.2.3.4', 'SYN_FLOOD', 1000, 12)
    for a in alerts: assert 0.0 <= a.confidence <= 1.0
    print('✓ T3: confidence in [0,1]')

def test_cooldown():
    engine = DetectionEngine(cooldown_seconds=60)
    a1 = flood(engine, '2.2.2.2', 'SYN_FLOOD', 1000, 12)
    assert a1
    a2 = flood(engine, '2.2.2.2', 'SYN_FLOOD', 1000, 5)
    assert a2 == []
    print('✓ T4: cooldown suppresses repeat')

def test_blacklist():
    engine = DetectionEngine(blacklisted_ips={'6.6.6.6'})
    alerts = engine.process_event(make_event(ip='6.6.6.6',
        is_attack=False, packet_count=1))
    assert alerts and alerts[0].severity == 'critical'
    assert alerts[0].rule_triggered == 'BLACKLIST'
    print('✓ T5: blacklist → critical')

def test_to_dict():
    engine = DetectionEngine()
    alerts = flood(engine, '3.3.3.3', 'SYN_FLOOD', 1000, 12)
    d = alerts[0].to_dict()
    for k in ('source_ip','attack_type','severity','confidence',
              'packet_count','rule_triggered','timestamp'):
        assert k in d
    print('✓ T6: to_dict structure')

def test_reset():
    engine = DetectionEngine()
    flood(engine, '4.4.4.4', 'SYN_FLOOD', 1000, 5)
    engine.reset()
    s = engine.get_stats()
    assert s['processed_events'] == 0 and s['tracked_ips'] == 0
    print('✓ T7: reset clears state')

def test_independent_ips():
    engine = DetectionEngine(cooldown_seconds=60)
    aA = flood(engine, '10.1.1.1', 'SYN_FLOOD', 1000, 12)
    aB = flood(engine, '10.1.1.2', 'SYN_FLOOD', 1000, 12)
    assert aA and aB
    print('✓ T8: independent IPs')

if __name__ == '__main__':
    test_normal_no_alert()
    test_flood_triggers()
    test_confidence_range()
    test_cooldown()
    test_blacklist()
    test_to_dict()
    test_reset()
    test_independent_ips()
    print('\n✅ All 8 tests passed!')
