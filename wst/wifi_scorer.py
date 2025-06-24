from typing import List, Tuple
from .wifi_network import WiFiNetwork, SecurityType
from .constants import (
    SCORE_OPEN_NETWORK, SCORE_HANDSHAKE_CAPTURE, SCORE_DUPLICATE_SSID,
    SCORE_EVIL_TWIN_SIGNAL, SCORE_MULTI_CHANNEL, SCORE_SIMILAR_SSIDS,
    SCORE_OPEN_WITH_ENCRYPTED, SIGNAL_DIFF_THRESHOLD, SIMILAR_SSID_THRESHOLD,
    SUSPICIOUS_SSID_PATTERNS, RISK_THRESHOLDS, RISK_LEVELS, RISK_INDICATORS
)


class WiFiScorer:
    def __init__(self, networks: List[WiFiNetwork]):
        self._networks = networks

    def _get_ssid_duplicates(self, ssid: str) -> List[WiFiNetwork]:
        return [n for n in self._networks if n.get_ssid() == ssid]

    def _has_duplicate_ssid(self, target: WiFiNetwork) -> bool:
        return len(self._get_ssid_duplicates(target.get_ssid())) > 1

    def _has_evil_twin_signal(self, target: WiFiNetwork) -> bool:
        duplicates = self._get_ssid_duplicates(target.get_ssid())
        if len(duplicates) < 2:
            return False
        
        signals = [n._signal_strength for n in duplicates]
        return (max(signals) - min(signals)) > SIGNAL_DIFF_THRESHOLD

    def _has_multi_channel(self, target: WiFiNetwork) -> bool:
        duplicates = self._get_ssid_duplicates(target.get_ssid())
        channels = {n.get_channel() for n in duplicates if n.get_channel()}
        return len(channels) > 1

    def _has_similar_ssids(self, target: WiFiNetwork) -> bool:
        target_ssid = target.get_ssid().lower()
        all_ssids = [n.get_ssid().lower() for n in self._networks]
        
        for pattern in SUSPICIOUS_SSID_PATTERNS:
            if pattern in target_ssid:
                matches = sum(1 for ssid in all_ssids if pattern in ssid)
                if matches >= SIMILAR_SSID_THRESHOLD:
                    return True
        return False

    def _has_open_with_encrypted_duplicate(self, target: WiFiNetwork) -> bool:
        if target.get_security_type() != SecurityType.OPEN:
            return False
        
        duplicates = self._get_ssid_duplicates(target.get_ssid())
        return any(n.is_secured() for n in duplicates if n != target)

    def _is_handshake_vulnerable(self, target: WiFiNetwork) -> bool:
        vulnerable_types = {SecurityType.WPA, SecurityType.WPA2, SecurityType.WPA_WPA2}
        return target.get_security_type() in vulnerable_types

    def calculate_score(self, target: WiFiNetwork) -> Tuple[int, List[str]]:
        score = 0
        reasons = []

        if target.get_security_type() == SecurityType.OPEN:
            score += SCORE_OPEN_NETWORK
            reasons.append(f"{RISK_INDICATORS['open']} (+{SCORE_OPEN_NETWORK})")

        if self._is_handshake_vulnerable(target):
            score += SCORE_HANDSHAKE_CAPTURE
            reasons.append(f"{RISK_INDICATORS['handshake']} (+{SCORE_HANDSHAKE_CAPTURE})")

        if self._has_duplicate_ssid(target):
            score += SCORE_DUPLICATE_SSID
            reasons.append(f"{RISK_INDICATORS['duplicate']} (+{SCORE_DUPLICATE_SSID})")

        if self._has_evil_twin_signal(target):
            score += SCORE_EVIL_TWIN_SIGNAL
            reasons.append(f"{RISK_INDICATORS['evil_twin']} (+{SCORE_EVIL_TWIN_SIGNAL})")

        if self._has_multi_channel(target):
            score += SCORE_MULTI_CHANNEL
            reasons.append(f"{RISK_INDICATORS['multi_channel']} (+{SCORE_MULTI_CHANNEL})")

        if self._has_similar_ssids(target):
            score += SCORE_SIMILAR_SSIDS
            reasons.append(f"{RISK_INDICATORS['similar_ssids']} (+{SCORE_SIMILAR_SSIDS})")

        if self._has_open_with_encrypted_duplicate(target):
            score += SCORE_OPEN_WITH_ENCRYPTED
            reasons.append(f"{RISK_INDICATORS['open_encrypted']} (+{SCORE_OPEN_WITH_ENCRYPTED})")

        return score, reasons

    def get_risk_level(self, score: int) -> Tuple[str, int]:
        for level, (min_score, max_score, min_rating, max_rating) in RISK_THRESHOLDS.items():
            if min_score <= score <= max_score:
                if level == 'safe':
                    rating = 1 if score <= 2 else 2
                elif level == 'minor':
                    rating = 3 if score <= 6 else 4
                elif level == 'medium':
                    rating = 5 if score <= 11 else 6
                elif level == 'high':
                    rating = 7 if score <= 16 else 8
                else:  # critical
                    rating = 9 if score <= 25 else 10
                
                return RISK_LEVELS[level], rating
        
        return RISK_LEVELS['critical'], 10