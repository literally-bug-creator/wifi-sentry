from enum import Enum
from typing import Optional


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


class WiFiNetwork:
    def __init__(self, ssid: str, bssid: str, signal_strength: int, frequency: int, 
                 security_type: SecurityType, connection_state: ConnectionState = ConnectionState.DISCONNECTED,
                 channel: Optional[int] = None):
        self._ssid = ssid
        self._bssid = bssid
        self._signal_strength = signal_strength
        self._frequency = frequency
        self._security_type = security_type
        self._connection_state = connection_state
        self._channel = channel
    
    def get_ssid(self) -> str:
        return self._ssid
    
    def get_bssid(self) -> str:
        return self._bssid
    
    def get_signal_quality(self) -> int:
        if self._signal_strength >= -30:
            return 100
        elif self._signal_strength <= -90:
            return 0
        else:
            return int(2 * (self._signal_strength + 100))
    
    def get_frequency(self) -> int:
        return self._frequency
    
    def get_security_type(self) -> SecurityType:
        return self._security_type
    
    def get_connection_state(self) -> ConnectionState:
        return self._connection_state
    
    def get_channel(self) -> Optional[int]:
        return self._channel
    
    def is_secured(self) -> bool:
        return self._security_type != SecurityType.OPEN
    
    def is_connected(self) -> bool:
        return self._connection_state == ConnectionState.CONNECTED