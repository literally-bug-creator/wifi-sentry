import time
from functools import wraps
from typing import List, Optional
from jeepney import DBusAddress, new_method_call
from jeepney.io.blocking import open_dbus_connection
from wifi_network import WiFiNetwork, SecurityType, ConnectionState


def handle_dbus_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            if "ServiceUnknown" in str(e):
                raise RuntimeError("NetworkManager is not running")
            elif "AccessDenied" in str(e):
                raise RuntimeError("Access denied - try running with sudo")
            else:
                raise RuntimeError(f"D-Bus error: {e}")
    return wrapper


class WiFiManager:
    # NetworkManager constants
    NM_SERVICE = 'org.freedesktop.NetworkManager'
    NM_PATH = '/org/freedesktop/NetworkManager'
    NM_DEVICE_TYPE_WIFI = 2
    
    # D-Bus interfaces
    NM_INTERFACE = 'org.freedesktop.NetworkManager'
    DEVICE_INTERFACE = 'org.freedesktop.NetworkManager.Device'
    WIRELESS_INTERFACE = 'org.freedesktop.NetworkManager.Device.Wireless'
    AP_INTERFACE = 'org.freedesktop.NetworkManager.AccessPoint'
    CONNECTION_INTERFACE = 'org.freedesktop.NetworkManager.Connection.Active'
    PROPERTIES_INTERFACE = 'org.freedesktop.DBus.Properties'
    
    # Security flags
    WPA3_FLAG = 0x400
    WEP_FLAG = 0x1
    
    # Connection states
    STATE_ACTIVATING = 1
    STATE_ACTIVATED = 2
    
    # Frequency ranges
    FREQ_2_4_MIN = 2412
    FREQ_2_4_MAX = 2484
    FREQ_2_4_CH14 = 2484
    FREQ_5_MIN = 5170
    FREQ_5_MAX = 5825
    
    # Signal conversion
    SIGNAL_OFFSET = -100
    SCAN_WAIT_TIME = 2

    @handle_dbus_errors
    def __init__(self):
        self.connection = open_dbus_connection(bus='SYSTEM')
        self.nm_address = DBusAddress(self.NM_PATH, bus_name=self.NM_SERVICE, interface=self.NM_INTERFACE)
        self.wireless_device = None
        self._find_wireless_device()

    def _get_property(self, address, property_name):
        msg = new_method_call(
            DBusAddress(address.object_path, bus_name=address.bus_name, interface=self.PROPERTIES_INTERFACE),
            'Get',
            'ss',
            (address.interface, property_name)
        )
        reply = self.connection.send_and_get_reply(msg)
        value = reply.body[0]
        # Handle D-Bus variant types - extract actual value from tuple
        if isinstance(value, tuple) and len(value) == 2:
            return value[1]  # (type, value) -> value
        return value

    def _set_property(self, address, property_name, signature, value):
        msg = new_method_call(
            DBusAddress(address.object_path, bus_name=address.bus_name, interface=self.PROPERTIES_INTERFACE),
            'Set',
            'ssv',
            (address.interface, property_name, (signature, value))
        )
        self.connection.send_and_get_reply(msg)

    @handle_dbus_errors
    def _find_wireless_device(self):
        msg = new_method_call(self.nm_address, 'GetDevices')
        reply = self.connection.send_and_get_reply(msg)
        devices = reply.body[0]

        for device_path in devices:
            device_address = DBusAddress(device_path, bus_name=self.NM_SERVICE, interface=self.DEVICE_INTERFACE)
            device_type = self._get_property(device_address, 'DeviceType')

            if device_type == self.NM_DEVICE_TYPE_WIFI:
                self.wireless_device = device_path
                return

        if not self.wireless_device:
            raise RuntimeError("No wireless device found")

    @handle_dbus_errors
    def scan_networks(self) -> List[WiFiNetwork]:
        if not self.wireless_device:
            raise RuntimeError("No wireless device available")

        wireless_address = DBusAddress(self.wireless_device, bus_name=self.NM_SERVICE, interface=self.WIRELESS_INTERFACE)
        
        # Request scan
        msg = new_method_call(wireless_address, 'RequestScan', 'a{sv}', ({},))
        self.connection.send_and_get_reply(msg)
        
        time.sleep(self.SCAN_WAIT_TIME)

        # Get access points
        msg = new_method_call(wireless_address, 'GetAccessPoints')
        reply = self.connection.send_and_get_reply(msg)
        access_points = reply.body[0]

        networks = []
        seen_ssids = set()

        for ap_path in access_points:
            network = self._create_network_from_ap(ap_path)
            if network and network.get_ssid() not in seen_ssids:
                networks.append(network)
                seen_ssids.add(network.get_ssid())

        networks.sort(key=lambda x: x._signal_strength, reverse=True)
        return networks

    def _create_network_from_ap(self, ap_path: str) -> Optional[WiFiNetwork]:
        try:
            ap_address = DBusAddress(ap_path, bus_name=self.NM_SERVICE, interface=self.AP_INTERFACE)

            ssid_bytes = self._get_property(ap_address, 'Ssid')
            ssid = bytes(ssid_bytes).decode('utf-8', errors='ignore').strip()

            if not ssid:
                return None

            bssid = self._get_property(ap_address, 'HwAddress')
            strength = self._get_property(ap_address, 'Strength')
            frequency = self._get_property(ap_address, 'Frequency')
            flags = self._get_property(ap_address, 'Flags')
            wpa_flags = self._get_property(ap_address, 'WpaFlags')
            rsn_flags = self._get_property(ap_address, 'RsnFlags')

            signal_dbm = self.SIGNAL_OFFSET + strength
            security_type = self._get_security_type(flags, wpa_flags, rsn_flags)
            channel = self._frequency_to_channel(frequency)
            connection_state = self._get_connection_state(ap_path)

            return WiFiNetwork(
                ssid=ssid,
                bssid=bssid,
                signal_strength=signal_dbm,
                frequency=frequency,
                security_type=security_type,
                connection_state=connection_state,
                channel=channel
            )

        except Exception:
            return None

    def _get_security_type(self, flags: int, wpa_flags: int, rsn_flags: int) -> SecurityType:
        if rsn_flags & self.WPA3_FLAG:
            return SecurityType.WPA3

        if rsn_flags > 0:
            if wpa_flags > 0:
                return SecurityType.WPA_WPA2
            return SecurityType.WPA2

        if wpa_flags > 0:
            return SecurityType.WPA

        if flags & self.WEP_FLAG:
            return SecurityType.WEP

        return SecurityType.OPEN

    def _frequency_to_channel(self, frequency: int) -> int:
        if self.FREQ_2_4_MIN <= frequency <= self.FREQ_2_4_MAX:
            if frequency == self.FREQ_2_4_CH14:
                return 14
            return (frequency - self.FREQ_2_4_MIN) // 5 + 1
        elif self.FREQ_5_MIN <= frequency <= self.FREQ_5_MAX:
            return (frequency - 5000) // 5
        else:
            return 0

    def _get_connection_state(self, ap_path: str) -> ConnectionState:
        try:
            active_connections = self._get_property(self.nm_address, 'ActiveConnections')

            for conn_path in active_connections:
                conn_address = DBusAddress(conn_path, bus_name=self.NM_SERVICE, interface=self.CONNECTION_INTERFACE)
                devices = self._get_property(conn_address, 'Devices')

                if self.wireless_device in devices:
                    state = self._get_property(conn_address, 'State')

                    if state == self.STATE_ACTIVATED:
                        return ConnectionState.CONNECTED
                    elif state == self.STATE_ACTIVATING:
                        return ConnectionState.CONNECTING
                    else:
                        return ConnectionState.FAILED

            return ConnectionState.DISCONNECTED

        except Exception:
            return ConnectionState.DISCONNECTED

    def get_connected_network(self) -> Optional[WiFiNetwork]:
        networks = self.scan_networks()
        for network in networks:
            if network.is_connected():
                return network
        return None

    def find_network(self, ssid: str) -> Optional[WiFiNetwork]:
        networks = self.scan_networks()
        for network in networks:
            if network.get_ssid() == ssid:
                return network
        return None

    @handle_dbus_errors
    def is_wifi_enabled(self) -> bool:
        return bool(self._get_property(self.nm_address, 'WirelessEnabled'))

    @handle_dbus_errors
    def enable_wifi(self, enable: bool = True) -> bool:
        self._set_property(self.nm_address, 'WirelessEnabled', 'b', enable)
        return True