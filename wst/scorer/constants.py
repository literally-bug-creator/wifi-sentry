# Risk scoring constants
SCORE_OPEN_NETWORK = 7
SCORE_HANDSHAKE_CAPTURE = 6
SCORE_DUPLICATE_SSID = 3
SCORE_EVIL_TWIN_SIGNAL = 4
SCORE_MULTI_CHANNEL = 3
SCORE_SIMILAR_SSIDS = 3
SCORE_OPEN_WITH_ENCRYPTED = 3

# Risk thresholds
SIGNAL_DIFF_THRESHOLD = 20
SIMILAR_SSID_THRESHOLD = 3

# Similar SSID patterns for detection
SUSPICIOUS_SSID_PATTERNS = [
    "free_wifi",
    "freewifi",
    "free wifi",
    "guest",
    "public",
    "wifi",
    "internet",
    "hotspot",
    "access",
]
