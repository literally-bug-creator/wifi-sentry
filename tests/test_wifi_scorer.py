from wst.network import SecurityType, WiFiNetwork
from wst.scorer import WiFiScorer


def test_init_creates_scorer_with_networks():
    networks = [
        WiFiNetwork("Test1", "aa:bb:cc:dd:ee:f1", -50, 2437, SecurityType.WPA2),
        WiFiNetwork("Test2", "aa:bb:cc:dd:ee:f2", -60, 2437, SecurityType.OPEN),
    ]

    scorer = WiFiScorer(networks)

    assert scorer._networks == networks


def test_calculate_score_returns_zero_for_secure_single_network():
    network = WiFiNetwork("Secure", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA3)
    scorer = WiFiScorer([network])

    score, reasons = scorer.calculate_score(network)

    assert score == 0
    assert reasons == []


def test_calculate_score_adds_7_points_for_open_network():
    network = WiFiNetwork("OpenNet", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.OPEN)
    scorer = WiFiScorer([network])

    score, reasons = scorer.calculate_score(network)

    assert score == 7
    assert len(reasons) == 1
    assert "Open network (+7)" in reasons[0]


def test_calculate_score_adds_6_points_for_handshake_vulnerable():
    network = WiFiNetwork("WPA2Net", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)
    scorer = WiFiScorer([network])

    score, reasons = scorer.calculate_score(network)

    assert score == 6
    assert len(reasons) == 1
    assert "Handshake capture possible (+6)" in reasons[0]


def test_calculate_score_adds_3_points_for_duplicate_ssid():
    network1 = WiFiNetwork(
        "Duplicate", "aa:bb:cc:dd:ee:f1", -50, 2437, SecurityType.WPA3
    )
    network2 = WiFiNetwork(
        "Duplicate", "aa:bb:cc:dd:ee:f2", -60, 2437, SecurityType.WPA3
    )
    scorer = WiFiScorer([network1, network2])

    score, reasons = scorer.calculate_score(network1)

    assert score == 3
    assert any("Duplicate SSID (+3)" in reason for reason in reasons)


def test_calculate_score_adds_3_points_for_multi_channel():
    network1 = WiFiNetwork(
        "MultiCh", "aa:bb:cc:dd:ee:f1", -50, 2437, SecurityType.WPA3, channel=6
    )
    network2 = WiFiNetwork(
        "MultiCh", "aa:bb:cc:dd:ee:f2", -50, 2462, SecurityType.WPA3, channel=11
    )
    scorer = WiFiScorer([network1, network2])

    score, reasons = scorer.calculate_score(network1)

    assert score == 6
    assert any("Multi-channel broadcast (+3)" in reason for reason in reasons)


def test_calculate_score_adds_3_points_for_similar_ssids():
    networks = [
        WiFiNetwork("Free_WiFi", "aa:bb:cc:dd:ee:f1", -50, 2437, SecurityType.WPA3),
        WiFiNetwork("FreeWiFi", "aa:bb:cc:dd:ee:f2", -50, 2437, SecurityType.WPA3),
        WiFiNetwork("Free WiFi", "aa:bb:cc:dd:ee:f3", -50, 2437, SecurityType.WPA3),
    ]
    scorer = WiFiScorer(networks)

    score, reasons = scorer.calculate_score(networks[0])

    assert score == 3
    assert any("Similar SSIDs (+3)" in reason for reason in reasons)


def test_calculate_score_adds_3_points_for_open_with_encrypted_duplicate():
    network1 = WiFiNetwork("Mixed", "aa:bb:cc:dd:ee:f1", -50, 2437, SecurityType.OPEN)
    network2 = WiFiNetwork("Mixed", "aa:bb:cc:dd:ee:f2", -50, 2437, SecurityType.WPA2)
    scorer = WiFiScorer([network1, network2])

    score, reasons = scorer.calculate_score(network1)

    assert score == 13
    assert any("Open with encrypted duplicate (+3)" in reason for reason in reasons)


def test_calculate_score_adds_4_points_for_evil_twin_signal():
    network1 = WiFiNetwork(
        "EvilTwin", "aa:bb:cc:dd:ee:f1", -30, 2437, SecurityType.WPA3
    )
    network2 = WiFiNetwork(
        "EvilTwin", "aa:bb:cc:dd:ee:f2", -80, 2437, SecurityType.WPA3
    )
    scorer = WiFiScorer([network1, network2])

    score, reasons = scorer.calculate_score(network1)

    assert score == 7
    assert any("Evil twin signal (+4)" in reason for reason in reasons)


def test_calculate_score_combines_multiple_risks():
    network1 = WiFiNetwork("Complex", "aa:bb:cc:dd:ee:f1", -30, 2437, SecurityType.OPEN)
    network2 = WiFiNetwork("Complex", "aa:bb:cc:dd:ee:f2", -80, 2437, SecurityType.WPA2)
    scorer = WiFiScorer([network1, network2])

    score, reasons = scorer.calculate_score(network1)

    assert score == 17
    assert len(reasons) == 4


def test_get_risk_level_returns_safe_for_low_scores():
    scorer = WiFiScorer([])

    risk_level, rating = scorer.get_risk_level(2)

    assert risk_level == "Safe / Low Risk"
    assert rating == 1


def test_get_risk_level_returns_minor_for_medium_scores():
    scorer = WiFiScorer([])

    risk_level, rating = scorer.get_risk_level(7)

    assert risk_level == "Minor Risk"
    assert rating == 4


def test_get_risk_level_returns_medium_for_high_scores():
    scorer = WiFiScorer([])

    risk_level, rating = scorer.get_risk_level(11)

    assert risk_level == "Medium Risk"
    assert rating == 5


def test_get_risk_level_returns_high_for_very_high_scores():
    scorer = WiFiScorer([])

    risk_level, rating = scorer.get_risk_level(16)

    assert risk_level == "High Risk"
    assert rating == 7


def test_get_risk_level_returns_critical_for_extreme_scores():
    scorer = WiFiScorer([])

    risk_level, rating = scorer.get_risk_level(25)

    assert risk_level == "Critical Danger"
    assert rating == 9
