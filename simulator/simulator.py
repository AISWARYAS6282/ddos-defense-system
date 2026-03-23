#!/usr/bin/env python3
"""
DDoS Defense System — Simulator
Division 1: Emits synthetic attack/normal traffic events to stdout as JSON.
No real network traffic is generated.

Usage:
    python simulator/simulator.py
    SIM_RATE=5 python simulator/simulator.py

To ingest events into the Flask app, pipe output to the API endpoint:
    python simulator/simulator.py | while read line; do
      curl -s -X POST http://localhost:5000/api/simulator/event \
        -H "Content-Type: application/json" -d "$line";
    done
"""

import json
import os
import random
import sys
import time
from datetime import datetime

# Load IP pools from JSON config
_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_dir, "ip_pools.json")) as _f:
    _pools = json.load(_f)

NORMAL_IPS = _pools["normal_ips"]
ATTACKER_IPS = _pools["attacker_ips"]
ATTACK_TYPES = _pools["attack_types"]

# Config via environment variables
RATE = float(os.environ.get("SIM_RATE", "1.0"))          # events per second
ATTACK_RATIO = float(os.environ.get("SIM_ATTACK_RATIO", "0.3"))  # 30% attacks


def generate_event() -> dict:
    """Generate a single synthetic traffic event."""
    is_attack = random.random() < ATTACK_RATIO
    source_ip = random.choice(ATTACKER_IPS if is_attack else NORMAL_IPS)
    attack_type = random.choice(ATTACK_TYPES) if is_attack else None

    severity = None
    packet_count = random.randint(1, 100)
    if is_attack:
        severity = random.choice(["low", "low", "medium", "medium", "high"])
        packet_count = {
            "low": random.randint(500, 2000),
            "medium": random.randint(2000, 20000),
            "high": random.randint(20000, 100000),
        }[severity]

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": source_ip,
        "destination_ip": "10.10.10.1",  # simulated target
        "is_attack": is_attack,
        "attack_type": attack_type,
        "severity": severity,
        "packet_count": packet_count,
        "bytes": packet_count * random.randint(40, 1500),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]) if is_attack else "TCP",
        "simulated": True,
    }


def main():
    print(
        f"[simulator] Starting — rate={RATE}/s attack_ratio={ATTACK_RATIO:.0%}",
        file=sys.stderr
    )
    print(
        f"[simulator] Normal IPs: {len(NORMAL_IPS)} | Attacker IPs: {len(ATTACKER_IPS)}",
        file=sys.stderr
    )
    print("[simulator] Ctrl+C to stop. Events piped to stdout as JSON.", file=sys.stderr)
    print("-" * 60, file=sys.stderr)

    interval = 1.0 / RATE
    try:
        while True:
            event = generate_event()
            print(json.dumps(event), flush=True)
            if event["is_attack"]:
                print(
                    f"[simulator] ⚠  ATTACK {event['attack_type']} from {event['source_ip']} "
                    f"[{event['severity']}] {event['packet_count']} pkts",
                    file=sys.stderr
                )
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[simulator] Stopped.", file=sys.stderr)


if __name__ == "__main__":
    main()
