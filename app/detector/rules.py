# Detection rules for the DDoS Defense System.

# DDoS / Flood rules — packet count thresholds per window
DDOS_RULES = {
    'SYN_FLOOD': {
        'window_60s':  {'low': 200,  'medium': 800,  'high': 2000,  'critical': 10000},
        'window_300s': {'low': 500,  'medium': 2000, 'high': 8000,  'critical': 40000},
    },
    'UDP_FLOOD': {
        'window_60s':  {'low': 300,  'medium': 1000, 'high': 3000,  'critical': 15000},
        'window_300s': {'low': 800,  'medium': 3000, 'high': 12000, 'critical': 60000},
    },
    'HTTP_FLOOD': {
        'window_60s':  {'low': 100,  'medium': 400,  'high': 1200,  'critical': 6000},
        'window_300s': {'low': 300,  'medium': 1200, 'high': 5000,  'critical': 25000},
    },
    'ICMP_FLOOD': {
        'window_60s':  {'low': 500,  'medium': 2000, 'high': 5000,  'critical': 20000},
        'window_300s': {'low': 1500, 'medium': 6000, 'high': 20000, 'critical': 80000},
    },
    'DNS_AMPLIFICATION': {
        'window_60s':  {'low': 50,   'medium': 200,  'high': 600,   'critical': 3000},
        'window_300s': {'low': 150,  'medium': 600,  'high': 2500,  'critical': 12000},
    },
    'GENERIC': {
        'window_60s':  {'low': 150,  'medium': 600,  'high': 1500,  'critical': 8000},
        'window_300s': {'low': 400,  'medium': 1500, 'high': 6000,  'critical': 30000},
    },
}

# Event count rules (how many events per window, not packet count)
EVENT_COUNT_RULES = {
    'window_60s':  {'low': 30,  'medium': 80,  'high': 200, 'critical': 500},
    'window_300s': {'low': 100, 'medium': 300, 'high': 700, 'critical': 2000},
}

# Blacklisted IPs — any traffic = immediate critical alert
BLACKLISTED_IPS = {'0.0.0.0', '255.255.255.255'}

# Base confidence score per severity level
SEVERITY_SCORES = {
    'low': 0.25, 'medium': 0.55, 'high': 0.80, 'critical': 0.97,
}

# Seconds before same IP can alert again
ALERT_COOLDOWN_SECONDS = 20

# For comparing severities
SEVERITY_RANK = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
