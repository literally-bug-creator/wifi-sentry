import asyncio

from jeepney import DBusAddress, new_method_call
from jeepney.io.asyncio import open_dbus_router

from ..network import SecurityType, WiFiNetwork
from .constants import (
    AP_INTERFACE,
    DEVICE_INTERFACE,
    NM_INTERFACE,
    NM_PATH,
    NM_SERVICE,
    PROPERTIES_INTERFACE,
    SIGNAL_OFFSET,
    WIFI_DEVICE_TYPE,
    WIRELESS_INTERFACE,
)


class WiFiScanner:
    def __init__(self):
        self._wireless_device: str | None = None

    async def _call_method(
        self,
        router,
        address: DBusAddress,
        method: str,
        signature: str = "",
        args: tuple = (),
    ):
        msg = new_method_call(address, method, signature, args)
        reply = await router.send_and_get_reply(msg)
        return reply.body

    async def _get_property(
        self, router, object_path: str, interface: str, property_name: str
    ):
        address = DBusAddress(
            object_path, bus_name=NM_SERVICE, interface=PROPERTIES_INTERFACE
        )
        body = await self._call_method(
            router, address, "Get", "ss", (interface, property_name)
        )
        value = body[0]
        return value[1] if isinstance(value, tuple) and len(value) == 2 else value

    async def _find_wireless_device(self, router):
        if self._wireless_device:
            return self._wireless_device

        address = DBusAddress(NM_PATH, bus_name=NM_SERVICE, interface=NM_INTERFACE)
        devices = (await self._call_method(router, address, "GetDevices"))[0]

        for device_path in devices:
            device_type = await self._get_property(
                router, device_path, DEVICE_INTERFACE, "DeviceType"
            )
            if device_type == WIFI_DEVICE_TYPE:
                self._wireless_device = device_path
                return device_path

        raise RuntimeError("No wireless device found")

    async def _request_scan(self, router):
        device_path = await self._find_wireless_device(router)
        address = DBusAddress(
            device_path, bus_name=NM_SERVICE, interface=WIRELESS_INTERFACE
        )
        await self._call_method(router, address, "RequestScan", "a{sv}", ({},))
        await asyncio.sleep(2)

    async def _get_access_points(self, router) -> list[str]:
        device_path = await self._find_wireless_device(router)
        address = DBusAddress(
            device_path, bus_name=NM_SERVICE, interface=WIRELESS_INTERFACE
        )
        return (await self._call_method(router, address, "GetAccessPoints"))[0]

    async def _create_network(self, router, ap_path: str) -> WiFiNetwork | None:
        ssid_bytes = await self._get_property(router, ap_path, AP_INTERFACE, "Ssid")
        ssid = bytes(ssid_bytes).decode("utf-8", errors="ignore").strip()

        if not ssid:
            return None

        bssid = str(
            await self._get_property(router, ap_path, AP_INTERFACE, "HwAddress") # type: ignore
        )
        strength = int(
            await self._get_property(router, ap_path, AP_INTERFACE, "Strength") # type: ignore
        )
        frequency = int(
            await self._get_property(router, ap_path, AP_INTERFACE, "Frequency") # type: ignore
        )
        flags = int(await self._get_property(router, ap_path, AP_INTERFACE, "Flags"))  # type: ignore
        wpa_flags = int(
            await self._get_property(router, ap_path, AP_INTERFACE, "WpaFlags") # type: ignore
        )
        rsn_flags = int(
            await self._get_property(router, ap_path, AP_INTERFACE, "RsnFlags") # type: ignore
        )

        return WiFiNetwork(
            ssid=ssid,
            bssid=bssid,
            signal_strength=SIGNAL_OFFSET + strength,
            frequency=frequency,
            security_type=self._get_security_type(flags, wpa_flags, rsn_flags),
            channel=self._frequency_to_channel(frequency),
        )

    def _get_security_type(
        self, flags: int, wpa_flags: int, rsn_flags: int
    ) -> SecurityType:
        if rsn_flags & 0x400:
            return SecurityType.WPA3
        if rsn_flags > 0:
            return SecurityType.WPA_WPA2 if wpa_flags > 0 else SecurityType.WPA2
        if wpa_flags > 0:
            return SecurityType.WPA
        if flags & 0x1:
            return SecurityType.WEP
        return SecurityType.OPEN

    def _frequency_to_channel(self, frequency: int) -> int:
        if 2412 <= frequency <= 2484:
            return 14 if frequency == 2484 else (frequency - 2412) // 5 + 1
        if 5170 <= frequency <= 5825:
            return (frequency - 5000) // 5
        return 0

    async def scan(self) -> list[WiFiNetwork]:
        async with open_dbus_router(bus="SYSTEM") as router:
            await self._request_scan(router)
            access_points = await self._get_access_points(router)

            networks = []
            seen_ssids = set()

            for ap_path in access_points:
                network = await self._create_network(router, ap_path)
                if network and network.get_ssid() not in seen_ssids:
                    networks.append(network)
                    seen_ssids.add(network.get_ssid())

            return sorted(networks, key=lambda n: n._signal_strength, reverse=True)
