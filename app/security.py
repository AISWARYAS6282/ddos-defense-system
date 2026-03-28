"""
app/security.py  —  Division 3
Rate limiting, input validation, CSRF helpers.
"""
import re
import ipaddress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Rate Limiter ──────────────────────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],          # no global limit — set per-route
    storage_uri="memory://",    # in-memory (use redis:// in production)
)

# ── IP Validation ─────────────────────────────────────────────────────────────
_IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')


def is_valid_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address."""
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not _IP_RE.match(ip):
        return False
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """Return True if ip is a private/loopback address."""
    try:
        addr = ipaddress.IPv4Address(ip.strip())
        return addr.is_private or addr.is_loopback
    except ValueError:
        return False


def sanitize_reason(reason: str, max_len: int = 200) -> str:
    """Strip and truncate a reason string."""
    if not reason or not isinstance(reason, str):
        return "No reason provided"
    return reason.strip()[:max_len]