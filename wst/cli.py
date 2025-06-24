import argparse
import asyncio
import sys

from .constants import (
    MAX_SSID_DISPLAY,
    MSG_FATAL_ERROR,
    MSG_MUST_SPECIFY,
    MSG_NETWORK_NOT_FOUND,
    MSG_NO_NETWORKS,
    MSG_SCAN_INTERRUPTED,
    MSG_SCANNING,
    SIGNAL_BAR_SEGMENTS,
)
from .network import WiFiNetwork
from .scanner import WiFiScanner
from .scorer import WiFiScorer


def format_table_row(network: WiFiNetwork, index: int) -> str:
    ssid = network.get_ssid()[:MAX_SSID_DISPLAY]
    bssid = network.get_bssid()
    quality = network.get_signal_quality()
    security = network.get_security_type().value
    channel = network.get_channel() or 0
    frequency = network.get_frequency()

    quality_bar = "█" * (quality // SIGNAL_BAR_SEGMENTS) + "░" * (SIGNAL_BAR_SEGMENTS - quality // SIGNAL_BAR_SEGMENTS)
    security_icon = "🔒" if network.is_secured() else "🔓"

    return (f"{index:2d} │ {ssid:<20} │ {bssid:<17} │ {quality_bar} {quality:3d}% │ "
            f"{security_icon} {security:<10} │ {channel:2d} │ {frequency:4d}")


def print_table(networks: list[WiFiNetwork]):
    if not networks:
        print(MSG_NO_NETWORKS)
        return

    print(f"Found {len(networks)} networks")
    print("┌────┬──────────────────────┬───────────────────┬──────────────────┬──────────────┬────┬──────┐")
    print("│ №  │ SSID                 │ BSSID             │ Signal           │ Security     │ CH │ Freq │")
    print("├────┼──────────────────────┼───────────────────┼──────────────────┼──────────────┼────┼──────┤")

    for i, network in enumerate(networks, 1):
        print(format_table_row(network, i))

    print("└────┴──────────────────────┴───────────────────┴──────────────────┴──────────────┴────┴──────┘")


def print_score(network: WiFiNetwork, score: int, reasons: list[str], risk_level: str, rating: int):
    print(f"Target: {network.get_ssid()}")
    print(f"BSSID: {network.get_bssid()}")
    print(f"Security: {network.get_security_type().value}")
    print()

    if reasons:
        print("Risk factors:")
        for reason in reasons:
            print(f"  • {reason}")
        print()

    print(f"Score: {score} | Rating: {rating}/10 | Level: {risk_level}")

    if rating >= 7:
        print("⚠️  HIGH RISK")
    elif rating >= 5:
        print("⚡ MEDIUM RISK")
    else:
        print("✅ LOW RISK")


async def find_network(networks: list[WiFiNetwork], ssid: str | None, bssid: str | None) -> WiFiNetwork | None:
    if ssid and bssid:
        return next((n for n in networks if n.get_ssid() == ssid and n.get_bssid() == bssid), None)
    elif ssid:
        return next((n for n in networks if n.get_ssid() == ssid), None)
    elif bssid:
        return next((n for n in networks if n.get_bssid() == bssid), None)
    return None


async def cmd_scan():
    try:
        scanner = WiFiScanner()
        print(MSG_SCANNING)
        networks = await scanner.scan()
        print_table(networks)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


async def cmd_score(ssid: str | None, bssid: str | None):
    if not ssid and not bssid:
        print(MSG_MUST_SPECIFY)
        sys.exit(1)

    try:
        scanner = WiFiScanner()
        print(MSG_SCANNING)
        networks = await scanner.scan()

        target = await find_network(networks, ssid, bssid)
        if not target:
            print(MSG_NETWORK_NOT_FOUND)
            sys.exit(1)

        scorer = WiFiScorer(networks)
        score, reasons = scorer.calculate_score(target)
        risk_level, rating = scorer.get_risk_level(score)

        print_score(target, score, reasons, risk_level, rating)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(prog='wst', description='WiFi network scanner and analyzer')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    subparsers.add_parser('scan', help='Scan networks')

    score_parser = subparsers.add_parser('score', help='Analyze network risk')
    score_parser.add_argument('--ssid', help='Network SSID')
    score_parser.add_argument('--bssid', help='Network BSSID')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    try:
        if args.command == 'scan':
            asyncio.run(cmd_scan())
        elif args.command == 'score':
            asyncio.run(cmd_score(args.ssid, args.bssid))
    except KeyboardInterrupt:
        print(MSG_SCAN_INTERRUPTED)
    except Exception as e:
        print(f"{MSG_FATAL_ERROR}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
