from wst.network import ConnectionState, SecurityType, WiFiNetwork


def test_get_ssid():
    # Arrange
    network = WiFiNetwork("TestNetwork", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.get_ssid()

    # Assert
    assert result == "TestNetwork"


def test_get_bssid():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.get_bssid()

    # Assert
    assert result == "aa:bb:cc:dd:ee:ff"


def test_get_frequency():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.get_frequency()

    # Assert
    assert result == 2437


def test_get_security_type():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.get_security_type()

    # Assert
    assert result == SecurityType.WPA2


def test_get_channel_returns_none_when_not_set():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.get_channel()

    # Assert
    assert result is None


def test_get_channel_returns_value_when_set():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2, channel=11)

    # Act
    result = network.get_channel()

    # Assert
    assert result == 11


def test_is_secured_returns_false_for_open_network():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.OPEN)

    # Act
    result = network.is_secured()

    # Assert
    assert result is False


def test_is_secured_returns_true_for_wpa_network():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.is_secured()

    # Assert
    assert result is True


def test_is_connected_returns_false_for_disconnected_network():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2)

    # Act
    result = network.is_connected()

    # Assert
    assert result is False


def test_is_connected_returns_true_for_connected_network():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -50, 2437, SecurityType.WPA2, ConnectionState.CONNECTED)

    # Act
    result = network.is_connected()

    # Assert
    assert result is True


def test_get_signal_quality_returns_0_for_weak_signal():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -90, 2437, SecurityType.OPEN)

    # Act
    result = network.get_signal_quality()

    # Assert
    assert result == 0


def test_get_signal_quality_calculates_intermediate_values():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -60, 2437, SecurityType.OPEN)

    # Act
    result = network.get_signal_quality()

    # Assert
    assert result == 80


def test_get_signal_quality_returns_100_for_strong_signal():
    # Arrange
    network = WiFiNetwork("Test", "aa:bb:cc:dd:ee:ff", -30, 2437, SecurityType.OPEN)

    # Act
    result = network.get_signal_quality()

    # Assert
    assert result == 100


def test_init_creates_network_with_required_fields():
    # Arrange
    ssid = "TestNetwork"
    bssid = "aa:bb:cc:dd:ee:ff"
    signal_strength = -50
    frequency = 2437
    security_type = SecurityType.WPA2

    # Act
    network = WiFiNetwork(ssid, bssid, signal_strength, frequency, security_type)

    # Assert
    assert network.get_ssid() == ssid
    assert network.get_bssid() == bssid
    assert network.get_frequency() == frequency
    assert network.get_security_type() == security_type
    assert network.get_connection_state() == ConnectionState.DISCONNECTED
    assert network.get_channel() is None


def test_init_creates_network_with_all_fields():
    # Arrange
    ssid = "TestNetwork"
    bssid = "aa:bb:cc:dd:ee:ff"
    signal_strength = -40
    frequency = 2412
    security_type = SecurityType.WPA3
    connection_state = ConnectionState.CONNECTED
    channel = 6

    # Act
    network = WiFiNetwork(ssid, bssid, signal_strength, frequency, security_type, connection_state, channel)

    # Assert
    assert network.get_ssid() == ssid
    assert network.get_bssid() == bssid
    assert network.get_frequency() == frequency
    assert network.get_security_type() == security_type
    assert network.get_connection_state() == connection_state
    assert network.get_channel() == channel
