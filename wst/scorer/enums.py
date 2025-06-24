from enum import Enum

from .constants import (
    SCORE_DUPLICATE_SSID,
    SCORE_EVIL_TWIN_SIGNAL,
    SCORE_HANDSHAKE_CAPTURE,
    SCORE_MULTI_CHANNEL,
    SCORE_OPEN_NETWORK,
    SCORE_OPEN_WITH_ENCRYPTED,
    SCORE_SIMILAR_SSIDS,
)


class RiskLevel(Enum):
    SAFE = ("Safe / Low Risk", 0, 4)
    MINOR = ("Minor Risk", 5, 8)
    MEDIUM = ("Medium Risk", 9, 13)
    HIGH = ("High Risk", 14, 18)
    CRITICAL = ("Critical Danger", 19, float("inf"))

    def __init__(self, name: str, min_score: int, max_score: float):
        self.level_name = name
        self.min_score = min_score
        self.max_score = max_score

    def get_rating(self, score: int) -> int:
        if self == RiskLevel.SAFE:
            return 1 if score <= 2 else 2
        elif self == RiskLevel.MINOR:
            return 3 if score <= 6 else 4
        elif self == RiskLevel.MEDIUM:
            return 5 if score <= 11 else 6
        elif self == RiskLevel.HIGH:
            return 7 if score <= 16 else 8
        else:  # CRITICAL
            return 9 if score <= 25 else 10

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        for level in cls:
            if level.min_score <= score <= level.max_score:
                return level
        return cls.CRITICAL


class RiskIndicator(Enum):
    OPEN = ("Open network", SCORE_OPEN_NETWORK)
    HANDSHAKE = ("Handshake capture possible", SCORE_HANDSHAKE_CAPTURE)
    DUPLICATE = ("Duplicate SSID", SCORE_DUPLICATE_SSID)
    EVIL_TWIN = ("Evil twin signal", SCORE_EVIL_TWIN_SIGNAL)
    MULTI_CHANNEL = ("Multi-channel broadcast", SCORE_MULTI_CHANNEL)
    SIMILAR_SSIDS = ("Similar SSIDs", SCORE_SIMILAR_SSIDS)
    OPEN_ENCRYPTED = ("Open with encrypted duplicate", SCORE_OPEN_WITH_ENCRYPTED)

    def __init__(self, description: str, score: int):
        self.description = description
        self.score = score
