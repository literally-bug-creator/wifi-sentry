from ..network import SecurityType, WiFiNetwork
from .constants import (
    SIGNAL_DIFF_THRESHOLD,
    SIMILAR_SSID_THRESHOLD,
    SUSPICIOUS_SSID_PATTERNS,
)
from .enums import RiskIndicator, RiskLevel


class WiFiScorer:
    def __init__(self, networks: list[WiFiNetwork]):
        self._networks = networks

    def _get_ssid_duplicates(self, ssid: str) -> list[WiFiNetwork]:
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

    def calculate_score(self, target: WiFiNetwork) -> tuple[int, list[str]]:
        score = 0
        reasons = []

        if target.get_security_type() == SecurityType.OPEN:
            score += RiskIndicator.OPEN.score
            reasons.append(f"{RiskIndicator.OPEN.description} (+{RiskIndicator.OPEN.score})")

        if self._is_handshake_vulnerable(target):
            score += RiskIndicator.HANDSHAKE.score
            reasons.append(f"{RiskIndicator.HANDSHAKE.description} (+{RiskIndicator.HANDSHAKE.score})")

        if self._has_duplicate_ssid(target):
            score += RiskIndicator.DUPLICATE.score
            reasons.append(f"{RiskIndicator.DUPLICATE.description} (+{RiskIndicator.DUPLICATE.score})")

        if self._has_evil_twin_signal(target):
            score += RiskIndicator.EVIL_TWIN.score
            reasons.append(f"{RiskIndicator.EVIL_TWIN.description} (+{RiskIndicator.EVIL_TWIN.score})")

        if self._has_multi_channel(target):
            score += RiskIndicator.MULTI_CHANNEL.score
            reasons.append(f"{RiskIndicator.MULTI_CHANNEL.description} (+{RiskIndicator.MULTI_CHANNEL.score})")

        if self._has_similar_ssids(target):
            score += RiskIndicator.SIMILAR_SSIDS.score
            reasons.append(f"{RiskIndicator.SIMILAR_SSIDS.description} (+{RiskIndicator.SIMILAR_SSIDS.score})")

        if self._has_open_with_encrypted_duplicate(target):
            score += RiskIndicator.OPEN_ENCRYPTED.score
            reasons.append(f"{RiskIndicator.OPEN_ENCRYPTED.description} (+{RiskIndicator.OPEN_ENCRYPTED.score})")

        return score, reasons

    def get_risk_level(self, score: int) -> tuple[str, int]:
        risk_level = RiskLevel.from_score(score)
        rating = risk_level.get_rating(score)
        return risk_level.level_name, rating