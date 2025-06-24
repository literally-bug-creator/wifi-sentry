import dbus
import time
from functools import wraps
from typing import List, Optional
from wifi_network import WiFiNetwork, SecurityType, ConnectionState


def handle_dbus_errors(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except dbus.DBusException as e:
            if "ServiceUnknown" in str(e):
                raise RuntimeError("NetworkManager is not running")
            elif "AccessDenied" in str(e):
                raise RuntimeError("Access denied - try running with sudo")
            else:
                raise RuntimeError(f"D-Bus error: {e}")
        except Exception as e:
            raise RuntimeError(f"Unexpected error: {e}")
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
        self.system_bus = dbus.SystemBus()
        self.nm_proxy = self._get_nm_proxy()
        self.nm_interface = self._get_nm_interface()
        self.device_interface = None
        self.wireless_device = None
        self._find_wireless_device()

    def _get_nm_proxy(self):
        return self.system_bus.get_object(self.NM_SERVICE, self.NM_PATH)

    def _get_nm_interface(self):
        return dbus.Interface(self.nm_proxy, self.NM_INTERFACE)

    def _get_device_proxy(self, device_path):
        return self.system_bus.get_object(self.NM_SERVICE, device_path)

    def _get_device_properties(self, device_proxy):
        return dbus.Interface(device_proxy, self.PROPERTIES_INTERFACE)

    def _get_wireless_interface(self, device_proxy):
        return dbus.Interface(device_proxy, self.WIRELESS_INTERFACE)

    def _get_ap_proxy(self, ap_path):
        return self.system_bus.get_object(self.NM_SERVICE, ap_path)

    def _get_ap_properties(self, ap_proxy):
        return dbus.Interface(ap_proxy, self.PROPERTIES_INTERFACE)

    def _get_connection_proxy(self, conn_path):
        return self.system_bus.get_object(self.NM_SERVICE, conn_path)

    def _get_connection_properties(self, conn_proxy):
        return dbus.Interface(conn_proxy, self.PROPERTIES_INTERFACE)

    def _get_nm_properties(self):
        return dbus.Interface(self.nm_proxy, self.PROPERTIES_INTERFACE)

    @handle_dbus_errors
    def _find_wireless_device(self):
        devices = self.nm_interface.GetDevices()
        for device_path in devices:
            device_proxy = self._get_device_proxy(device_path)
            device_props = self._get_device_properties(device_proxy)
            device_type = device_props.Get(self.DEVICE_INTERFACE, 'DeviceType')

            if device_type == self.NM_DEVICE_TYPE_WIFI:
                self.wireless_device = device_path
                self.device_interface = self._get_wireless_interface(device_proxy)
                return

        if not self.wireless_device:
            raise RuntimeError("No wireless device found")

    @handle_dbus_errors
    def scan_networks(self) -> List[WiFiNetwork]:
        if not self.device_interface:
            raise RuntimeError("No wireless device available")

        self.device_interface.RequestScan({})
        time.sleep(self.SCAN_WAIT_TIME)

        access_points = self.device_interface.GetAccessPoints()
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
            ap_proxy = self._get_ap_proxy(ap_path)
            ap_props = self._get_ap_properties(ap_proxy)

            ssid_bytes = ap_props.Get(self.AP_INTERFACE, 'Ssid')
            ssid = bytes(ssid_bytes).decode('utf-8', errors='ignore').strip()

            if not ssid:
                return None

            bssid = ap_props.Get(self.AP_INTERFACE, 'HwAddress')
            strength = int(ap_props.Get(self.AP_INTERFACE, 'Strength'))
            frequency = int(ap_props.Get(self.AP_INTERFACE, 'Frequency'))
            flags = int(ap_props.Get(self.AP_INTERFACE, 'Flags'))
            wpa_flags = int(ap_props.Get(self.AP_INTERFACE, 'WpaFlags'))
            rsn_flags = int(ap_props.Get(self.AP_INTERFACE, 'RsnFlags'))

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
            nm_props = self._get_nm_properties()
            active_connections = nm_props.Get(self.NM_INTERFACE, 'ActiveConnections')

            for conn_path in active_connections:
                conn_proxy = self._get_connection_proxy(conn_path)
                conn_props = self._get_connection_properties(conn_proxy)

                devices = conn_props.Get(self.CONNECTION_INTERFACE, 'Devices')

                if self.wireless_device in devices:
                    state = conn_props.Get(self.CONNECTION_INTERFACE, 'State')

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
        nm_props = self._get_nm_properties()
        return bool(nm_props.Get(self.NM_INTERFACE, 'WirelessEnabled'))

    @handle_dbus_errors
    def enable_wifi(self, enable: bool = True) -> bool:
        nm_props = self._get_nm_properties()
        nm_props.Set(self.NM_INTERFACE, 'WirelessEnabled', dbus.Boolean(enable))
        return True