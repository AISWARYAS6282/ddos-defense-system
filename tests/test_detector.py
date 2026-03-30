"""
tests/test_detector.py  —  Standalone detector tests (no Flask imports)
Run: docker-compose exec web python tests/test_detector.py
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Only import the detector — no Flask needed
from app.detector.engine import DetectionEngine, DetectionAlert
from app.detector.rules import DDOS_RULES


def make_event(ip='10.0.0.1', is_attack=True,
               attack_type='SYN_FLOOD', packet_count=5000):
    return {
        'source_ip':    ip,
        'is_attack':    is_attack,
        'attack_type':  attack_type,
        'packet_count': packet_count,
        'simulated':    True,
    }


def flood(engine, ip, atype, pkts, count):
    alerts = []
    for _ in range(count):
        alerts.extend(engine.process_event(
            make_event(ip=ip, attack_type=atype, packet_count=pkts)
        ))
    return alerts


tests_passed = 0
tests_failed = 0


def test(name, fn):
    global tests_passed, tests_failed
    try:
        fn()
        print(f'  ✓ {name}')
        tests_passed += 1
    except Exception as e:
        print(f'  ✗ {name}: {e}')
        tests_failed += 1


# ── Tests ─────────────────────────────────────────────────────────────────────

def t1():
    e = DetectionEngine()
    for _ in range(10):
        assert e.process_event(make_event(is_attack=False, packet_count=10)) == []

def t2():
    e = DetectionEngine()
    alerts = flood(e, '1.2.3.4', 'SYN_FLOOD', 1000, 12)
    assert any(a.severity in ('medium', 'high', 'critical') for a in alerts)

def t3():
    e = DetectionEngine()
    alerts = flood(e, '1.2.3.4', 'SYN_FLOOD', 1000, 12)
    for a in alerts:
        assert 0.0 <= a.confidence <= 1.0

def t4():
    e = DetectionEngine(cooldown_seconds=60)
    a1 = flood(e, '2.2.2.2', 'SYN_FLOOD', 1000, 12)
    assert a1
    a2 = flood(e, '2.2.2.2', 'SYN_FLOOD', 1000, 5)
    assert a2 == []

def t5():
    e = DetectionEngine(blacklisted_ips={'6.6.6.6'})
    alerts = e.process_event(make_event(ip='6.6.6.6', is_attack=False, packet_count=1))
    assert alerts and alerts[0].severity == 'critical'
    assert alerts[0].rule_triggered == 'BLACKLIST'

def t6():
    e = DetectionEngine()
    alerts = flood(e, '3.3.3.3', 'SYN_FLOOD', 1000, 12)
    d = alerts[0].to_dict()
    for k in ('source_ip','attack_type','severity','confidence',
              'packet_count','rule_triggered','timestamp'):
        assert k in d

def t7():
    e = DetectionEngine()
    flood(e, '4.4.4.4', 'SYN_FLOOD', 1000, 5)
    e.reset()
    s = e.get_stats()
    assert s['processed_events'] == 0 and s['tracked_ips'] == 0

def t8():
    e = DetectionEngine(cooldown_seconds=60)
    aA = flood(e, '10.1.1.1', 'SYN_FLOOD', 1000, 12)
    aB = flood(e, '10.1.1.2', 'SYN_FLOOD', 1000, 12)
    assert aA and aB


print('\nRunning detector tests...\n')
test('T1: normal traffic no alert',         t1)
test('T2: flood triggers alert',            t2)
test('T3: confidence in [0,1]',             t3)
test('T4: cooldown suppresses repeat',      t4)
test('T5: blacklist → critical alert',      t5)
test('T6: to_dict has required fields',     t6)
test('T7: reset clears state',              t7)
test('T8: independent IP cooldowns',        t8)

print(f'\n{"="*40}')
print(f'  {tests_passed} passed, {tests_failed} failed')
if tests_failed == 0:
    print('  ✅ All detector tests passed!')
else:
    print('  ❌ Some tests failed!')
sys.exit(0 if tests_failed == 0 else 1)
