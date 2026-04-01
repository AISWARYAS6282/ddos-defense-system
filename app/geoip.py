"""
app/geoip.py  —  Free IP geolocation using ip-api.com
No API key needed. Rate limit: 45 requests/minute.
Results cached in memory to avoid hammering the API.
"""
import requests
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

# Country code → flag emoji
_FLAGS = {
    "AF":"🇦🇫","AL":"🇦🇱","DZ":"🇩🇿","AR":"🇦🇷","AU":"🇦🇺",
    "AT":"🇦🇹","BD":"🇧🇩","BE":"🇧🇪","BR":"🇧🇷","BG":"🇧🇬",
    "CA":"🇨🇦","CL":"🇨🇱","CN":"🇨🇳","CO":"🇨🇴","HR":"🇭🇷",
    "CZ":"🇨🇿","DK":"🇩🇰","EG":"🇪🇬","FI":"🇫🇮","FR":"🇫🇷",
    "DE":"🇩🇪","GH":"🇬🇭","GR":"🇬🇷","HK":"🇭🇰","HU":"🇭🇺",
    "IN":"🇮🇳","ID":"🇮🇩","IR":"🇮🇷","IQ":"🇮🇶","IE":"🇮🇪",
    "IL":"🇮🇱","IT":"🇮🇹","JP":"🇯🇵","JO":"🇯🇴","KZ":"🇰🇿",
    "KE":"🇰🇪","KR":"🇰🇷","KW":"🇰🇼","LB":"🇱🇧","MY":"🇲🇾",
    "MX":"🇲🇽","MA":"🇲🇦","NL":"🇳🇱","NZ":"🇳🇿","NG":"🇳🇬",
    "NO":"🇳🇴","PK":"🇵🇰","PE":"🇵🇪","PH":"🇵🇭","PL":"🇵🇱",
    "PT":"🇵🇹","RO":"🇷🇴","RU":"🇷🇺","SA":"🇸🇦","SG":"🇸🇬",
    "ZA":"🇿🇦","ES":"🇪🇸","SE":"🇸🇪","CH":"🇨🇭","TW":"🇹🇼",
    "TH":"🇹🇭","TR":"🇹🇷","UA":"🇺🇦","AE":"🇦🇪","GB":"🇬🇧",
    "US":"🇺🇸","VN":"🇻🇳","YE":"🇾🇪","ZW":"🇿🇼","PY":"🇵🇾",
}


@lru_cache(maxsize=512)
def lookup(ip: str) -> dict:
    """
    Look up geolocation for an IP address.
    Returns dict with country, city, flag, isp.
    Results are cached — same IP never looked up twice.
    """
    # Private/local IPs — return immediately
    if ip.startswith(("10.", "192.168.", "172.", "127.", "0.")):
        return {
            "country":     "Private Network",
            "country_code": "XX",
            "city":        "Local",
            "flag":        "🏠",
            "isp":         "Internal",
            "lat":         0.0,
            "lon":         0.0,
        }

    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,lat,lon",
            timeout=3,
        )
        data = resp.json()
        if data.get("status") == "success":
            code = data.get("countryCode", "")
            return {
                "country":      data.get("country", "Unknown"),
                "country_code": code,
                "city":         data.get("city", "Unknown"),
                "flag":         _FLAGS.get(code, "🌍"),
                "isp":          data.get("isp", "Unknown"),
                "lat":          data.get("lat", 0.0),
                "lon":          data.get("lon", 0.0),
            }
    except Exception as e:
        logger.debug(f"[GeoIP] lookup failed for {ip}: {e}")

    return {
        "country":      "Unknown",
        "country_code": "XX",
        "city":         "Unknown",
        "flag":         "🌍",
        "isp":          "Unknown",
        "lat":          0.0,
        "lon":          0.0,
    }
