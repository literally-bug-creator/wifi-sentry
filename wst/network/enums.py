from enum import Enum


class SecurityType(Enum):
    OPEN = "open"
    WEP = "wep"
    WPA = "wpa"
    WPA2 = "wpa2"
    WPA3 = "wpa3"
    WPA_WPA2 = "wpa_wpa2"


class ConnectionState(Enum):
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    FAILED = "failed"