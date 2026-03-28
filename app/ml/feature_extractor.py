"""
app/ml/feature_extractor.py  —  Division 3
Converts raw traffic events into numeric feature vectors for ML.
"""
import numpy as np

# Attack type → numeric encoding
ATTACK_TYPE_MAP = {
    None:                0,
    "SYN_FLOOD":         1,
    "UDP_FLOOD":         2,
    "HTTP_FLOOD":        3,
    "ICMP_FLOOD":        4,
    "DNS_AMPLIFICATION": 5,
    "GENERIC":           6,
    "RATE_ANOMALY":      7,
}

PROTOCOL_MAP = {
    "TCP":  0,
    "UDP":  1,
    "ICMP": 2,
    None:   0,
}

FEATURE_NAMES = [
    "packet_count",
    "is_attack",
    "attack_type_enc",
    "protocol_enc",
    "hour_of_day",
    "packets_log",
]


def extract_features(event: dict) -> np.ndarray:
    """
    Convert a raw event dict into a 1D numpy feature vector.

    Features:
        0: packet_count       (raw)
        1: is_attack          (0 or 1)
        2: attack_type_enc    (encoded integer)
        3: protocol_enc       (encoded integer)
        4: hour_of_day        (0-23)
        5: packets_log        (log1p of packet_count)
    """
    packet_count  = int(event.get("packet_count", 1))
    is_attack     = 1 if event.get("is_attack") else 0
    attack_type   = event.get("attack_type")
    protocol      = event.get("protocol")

    # Parse hour from timestamp if available
    hour = 0
    ts = event.get("timestamp", "")
    try:
        if "T" in ts:
            hour = int(ts.split("T")[1][:2])
    except Exception:
        hour = 0

    return np.array([
        packet_count,
        is_attack,
        ATTACK_TYPE_MAP.get(attack_type, 0),
        PROTOCOL_MAP.get(protocol, 0),
        hour,
        np.log1p(packet_count),
    ], dtype=np.float32)


def extract_batch(events: list) -> np.ndarray:
    """Convert a list of events into a 2D feature matrix."""
    return np.vstack([extract_features(e) for e in events])
