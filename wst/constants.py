# Display constants
TABLE_WIDTH = 80
MAX_SSID_DISPLAY = 20
SIGNAL_BAR_SEGMENTS = 10

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

# Risk level thresholds and ratings
RISK_THRESHOLDS = {
    'safe': (0, 4, 1, 2),      # (min_score, max_score, min_rating, max_rating)
    'minor': (5, 8, 3, 4),
    'medium': (9, 13, 5, 6),
    'high': (14, 18, 7, 8),
    'critical': (19, float('inf'), 9, 10)
}

# Similar SSID patterns for detection
SUSPICIOUS_SSID_PATTERNS = [
    'free_wifi', 'freewifi', 'free wifi', 'guest', 'public',
    'wifi', 'internet', 'hotspot', 'access'
]

# Messages
MSG_SCANNING = "Scanning..."
MSG_NO_NETWORKS = "No networks found"
MSG_NETWORK_NOT_FOUND = "Network not found"
MSG_SCAN_INTERRUPTED = "Interrupted"
MSG_FATAL_ERROR = "Fatal error"
MSG_MUST_SPECIFY = "Must specify --ssid or --bssid"

# Risk level names
RISK_LEVELS = {
    'safe': "Safe / Low Risk",
    'minor': "Minor Risk", 
    'medium': "Medium Risk",
    'high': "High Risk",
    'critical': "Critical Danger"
}

# Risk indicators
RISK_INDICATORS = {
    'open': "Open network",
    'handshake': "Handshake capture possible",
    'duplicate': "Duplicate SSID",
    'evil_twin': "Evil twin signal",
    'multi_channel': "Multi-channel broadcast",
    'similar_ssids': "Similar SSIDs",
    'open_encrypted': "Open with encrypted duplicate"
}