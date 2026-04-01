"""
app/autoblock.py  —  Auto-block IPs that trigger 3+ alerts in 5 minutes.
Called from simulator_manager after every alert is saved.
"""
import time
from collections import defaultdict
from threading import Lock

# In-memory tracker: ip → list of alert timestamps
_alert_times: dict = defaultdict(list)
_lock = Lock()

THRESHOLD_COUNT   = 3      # alerts within window
THRESHOLD_WINDOW  = 300    # 5 minutes in seconds


def record_alert(ip: str) -> bool:
    """
    Record an alert for this IP.
    Returns True if auto-block should be triggered.
    """
    now = time.time()
    with _lock:
        times = _alert_times[ip]
        # Remove old entries outside the window
        times[:] = [t for t in times if now - t < THRESHOLD_WINDOW]
        times.append(now)
        return len(times) >= THRESHOLD_COUNT


def clear_ip(ip: str):
    """Clear alert history for an IP (call after blocking)."""
    with _lock:
        _alert_times.pop(ip, None)


def get_stats() -> dict:
    """Return current tracking stats."""
    with _lock:
        return {
            "tracked_ips": len(_alert_times),
            "ip_counts": {
                ip: len(times)
                for ip, times in _alert_times.items()
            }
        }
