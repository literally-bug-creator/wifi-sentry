from wifi_manager import WiFiManager
from wifi_network import SecurityType

def example_basic_scan():
    print("=== Basic WiFi Scan ===")

    wifi = WiFiManager()
    networks = wifi.scan_networks()

    for network in networks:
        print(f"{network.get_ssid()} - {network._signal_strength}dBm - {network.get_security_type().value}")

def example_network_details():
    print("\n=== Network Details ===")

    wifi = WiFiManager()
    networks = wifi.scan_networks()

    if networks:
        network = networks[0]  # strongest signal
        print(f"SSID: {network.get_ssid()}")
        print(f"BSSID: {network.get_bssid()}")
        print(f"Signal: {network._signal_strength}dBm ({network.get_signal_quality()}%)")
        print(f"Channel: {network.get_channel()}")
        print(f"Security: {network.get_security_type().value}")
        print(f"Connected: {network.is_connected()}")

def example_find_network():
    print("\n=== Find Specific Network ===")

    wifi = WiFiManager()
    network = wifi.find_network("MyNetwork")

    if network:
        print(f"Found: {network.get_ssid()} with {network.get_signal_quality()}% quality")
    else:
        print("Network not found")

def example_connected_network():
    print("\n=== Current Connection ===")

    wifi = WiFiManager()
    connected = wifi.get_connected_network()

    if connected:
        print(f"Connected to: {connected.get_ssid()}")
        print(f"Signal: {connected._signal_strength}dBm")
    else:
        print("Not connected to any network")

def example_filter_networks():
    print("\n=== Filter Networks ===")

    wifi = WiFiManager()
    networks = wifi.scan_networks()

    # Only open networks
    open_networks = [n for n in networks if n.get_security_type() == SecurityType.OPEN]
    print(f"Open networks: {len(open_networks)}")

    # Strong signal networks
    strong_networks = [n for n in networks if n._signal_strength > -50]
    print(f"Strong networks: {len(strong_networks)}")

def main():
    try:
        wifi = WiFiManager()

        if not wifi.is_wifi_enabled():
            print("Enabling WiFi...")
            wifi.enable_wifi(True)

        example_basic_scan()
        example_network_details()
        example_find_network()
        example_connected_network()
        example_filter_networks()

    except RuntimeError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("Interrupted by user")

if __name__ == "__main__":
    main()
