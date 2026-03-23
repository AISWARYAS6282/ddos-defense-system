import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Optional
from .rules import (
    DDOS_RULES, EVENT_COUNT_RULES, BLACKLISTED_IPS,
    SEVERITY_SCORES, SEVERITY_RANK, ALERT_COOLDOWN_SECONDS,
)


@dataclass
class DetectionAlert:
    source_ip: str
    attack_type: str
    severity: str
    confidence: float        # 0.0 to 1.0
    packet_count: int
    rule_triggered: str
    window_packets_60s: int
    window_packets_300s: int
    window_events_60s: int
    timestamp: float = field(default_factory=time.time)
    is_simulated: bool = True

    def to_dict(self) -> dict:
        return {
            'source_ip': self.source_ip,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'confidence': round(self.confidence * 100),
            'packet_count': self.packet_count,
            'rule_triggered': self.rule_triggered,
            'window_packets_60s': self.window_packets_60s,
            'window_packets_300s': self.window_packets_300s,
            'window_events_60s': self.window_events_60s,
            'timestamp': self.timestamp,
            'is_simulated': self.is_simulated,
        }


class IPWindow:
    """Sliding window tracker for a single IP address."""

    def __init__(self):
        self.events_60s: deque  = deque()   # (timestamp, packet_count)
        self.events_300s: deque = deque()

    def add_event(self, timestamp: float, packet_count: int):
        entry = (timestamp, packet_count)
        self.events_60s.append(entry)
        self.events_300s.append(entry)

    def prune(self, now: float):
        """Remove entries older than the window size."""
        cutoff_60  = now - 60
        cutoff_300 = now - 300
        while self.events_60s  and self.events_60s[0][0]  < cutoff_60:
            self.events_60s.popleft()
        while self.events_300s and self.events_300s[0][0] < cutoff_300:
            self.events_300s.popleft()

    def packet_sum_60s(self)  -> int: return sum(e[1] for e in self.events_60s)
    def packet_sum_300s(self) -> int: return sum(e[1] for e in self.events_300s)
    def event_count_60s(self) -> int: return len(self.events_60s)
    def event_count_300s(self) -> int: return len(self.events_300s)


class DetectionEngine:
    def __init__(self, cooldown_seconds=ALERT_COOLDOWN_SECONDS, blacklisted_ips=None):
        self.windows   = defaultdict(IPWindow)
        self.cooldowns = {}
        self.cooldown_seconds = cooldown_seconds
        self.blacklisted_ips = blacklisted_ips or set(BLACKLISTED_IPS)
        self._processed_count = 0
        self._alert_count = 0

    def process_event(self, event: dict) -> List[DetectionAlert]:
        ip = event.get('source_ip', '')
        if not ip: return []

        now = time.time()
        packet_count = int(event.get('packet_count', 1))
        attack_type  = event.get('attack_type') or 'GENERIC'
        is_simulated = event.get('simulated', True)

        # Update sliding window
        window = self.windows[ip]
        window.add_event(now, packet_count)
        window.prune(now)
        self._processed_count += 1

        pkts_60s   = window.packet_sum_60s()
        pkts_300s  = window.packet_sum_300s()
        events_60s = window.event_count_60s()

        alerts = []

        # Rule 1: Blacklist check (highest priority)
        if ip in self.blacklisted_ips:
            alert = self._make_alert(ip, attack_type, 'critical', 0.99,
                packet_count, 'BLACKLIST', pkts_60s, pkts_300s, events_60s, is_simulated)
            if alert: alerts.append(alert)
            return alerts

        # Rule 2: Packet flood (attack events only)
        if event.get('is_attack'):
            flood = self._check_flood(ip, attack_type, packet_count,
                pkts_60s, pkts_300s, events_60s, is_simulated)
            if flood: alerts.append(flood)

        # Rule 3: Event-rate anomaly (all traffic)
        rate = self._check_event_rate(ip, attack_type, packet_count,
            pkts_60s, pkts_300s, events_60s, is_simulated)
        if rate: alerts.append(rate)

        if alerts:
            self._alert_count += len(alerts)
            self.cooldowns[ip] = now

        return alerts

    def add_to_blacklist(self, ip): self.blacklisted_ips.add(ip)
    def remove_from_blacklist(self, ip): self.blacklisted_ips.discard(ip)
    def get_stats(self) -> dict:
        return {'processed_events': self._processed_count,
                'total_alerts': self._alert_count,
                'tracked_ips': len(self.windows),
                'blacklisted_ips': len(self.blacklisted_ips)}
    def reset(self):
        self.windows.clear(); self.cooldowns.clear()
        self._processed_count = 0; self._alert_count = 0

    def _in_cooldown(self, ip, now) -> bool:
        last = self.cooldowns.get(ip)
        return False if last is None else (now - last) < self.cooldown_seconds

    def _make_alert(self, ip, attack_type, severity, confidence,
                    packet_count, rule, pkts_60s, pkts_300s,
                    events_60s, is_simulated) -> Optional[DetectionAlert]:
        if self._in_cooldown(ip, time.time()): return None
        return DetectionAlert(
            source_ip=ip, attack_type=attack_type, severity=severity,
            confidence=confidence, packet_count=packet_count,
            rule_triggered=rule, window_packets_60s=pkts_60s,
            window_packets_300s=pkts_300s, window_events_60s=events_60s,
            timestamp=time.time(), is_simulated=is_simulated,
        )

    def _check_flood(self, ip, attack_type, packet_count,
                     pkts_60s, pkts_300s, events_60s, is_simulated):
        rule_set = DDOS_RULES.get(attack_type, DDOS_RULES['GENERIC'])
        sev_60  = self._classify(pkts_60s,  rule_set['window_60s'])
        sev_300 = self._classify(pkts_300s, rule_set['window_300s'])
        if sev_60 is None and sev_300 is None: return None
        severity = self._max_severity(sev_60, sev_300)
        confidence = self._compute_confidence(
            pkts_60s, pkts_300s, rule_set['window_60s'],
            rule_set['window_300s'], severity)
        return self._make_alert(ip, attack_type, severity, confidence,
            packet_count, f'FLOOD_{attack_type}',
            pkts_60s, pkts_300s, events_60s, is_simulated)

    def _check_event_rate(self, ip, attack_type, packet_count,
                          pkts_60s, pkts_300s, events_60s, is_simulated):
        t60  = EVENT_COUNT_RULES['window_60s']
        t300 = EVENT_COUNT_RULES['window_300s']
        events_300s = self.windows[ip].event_count_300s()
        sev_60  = self._classify(events_60s,  t60)
        sev_300 = self._classify(events_300s, t300)
        if sev_60 is None and sev_300 is None: return None
        severity   = self._max_severity(sev_60, sev_300)
        confidence = min(SEVERITY_SCORES.get(severity, 0.5) * 0.85, 0.95)
        return self._make_alert(ip, attack_type or 'RATE_ANOMALY', severity,
            confidence, packet_count, 'EVENT_RATE',
            pkts_60s, pkts_300s, events_60s, is_simulated)

    @staticmethod
    def _classify(value, thresholds) -> Optional[str]:
        if value >= thresholds.get('critical', float('inf')): return 'critical'
        if value >= thresholds.get('high',     float('inf')): return 'high'
        if value >= thresholds.get('medium',   float('inf')): return 'medium'
        if value >= thresholds.get('low',      float('inf')): return 'low'
        return None

    @staticmethod
    def _max_severity(a, b):
        rank = SEVERITY_RANK
        if a is None: return b
        if b is None: return a
        return a if rank.get(a, 0) >= rank.get(b, 0) else b

    @staticmethod
    def _compute_confidence(pkts_60s, pkts_300s, thresh_60, thresh_300, severity):
        base      = SEVERITY_SCORES.get(severity, 0.5)
        ratio_60  = min(pkts_60s  / max(thresh_60.get(severity,  1), 1), 2.0)
        ratio_300 = min(pkts_300s / max(thresh_300.get(severity, 1), 1), 2.0)
        boost     = ((ratio_60 + ratio_300) / 2 - 1.0) * 0.1
        return min(base + max(boost, 0), 0.99)
