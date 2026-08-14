#!/usr/bin/env python3

import argparse
from collections import defaultdict
from scapy.all import PcapNgReader, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt


def mac_normalize(mac):
    return mac.lower() if mac else None


def get_ssid(pkt):
    """Extract SSID from a Beacon or Probe Response."""
    if not pkt.haslayer(Dot11Elt):
        return None

    elt = pkt[Dot11Elt]

    while elt:
        if elt.ID == 0:  # SSID element
            try:
                return elt.info.decode("utf-8", errors="replace")
            except Exception:
                return ""

        elt = elt.payload.getlayer(Dot11Elt)

    return None


def get_information_elements(pkt):
    """Return 802.11 information elements."""
    elements = []

    if not pkt.haslayer(Dot11Elt):
        return elements

    elt = pkt[Dot11Elt]

    while isinstance(elt, Dot11Elt):
        elements.append((elt.ID, bytes(elt.info)))
        elt = elt.payload.getlayer(Dot11Elt)

    return elements


def classify_encryption(pkt):
    """
    Best-effort classification of the network's encryption/authentication.

    0   = Open
    48  = RSN information element (WPA2/WPA3)
    221 = Vendor-specific information element (often WPA1)
    """

    elements = get_information_elements(pkt)

    has_rsn = any(eid == 48 for eid, _ in elements)
    has_wpa_vendor = any(
        eid == 221 and b"WP" in data
        for eid, data in elements
    )

    if has_rsn:

        # Parse RSN AKM suite where possible.
        for eid, data in elements:

            if eid != 48 or len(data) < 8:
                continue

            try:
                # RSN:
                # Version              2 bytes
                # Group cipher         4 bytes
                # Pairwise count       2 bytes
                # Pairwise suites      variable
                # AKM count            2 bytes
                # AKM suites           variable

                pos = 0

                version = int.from_bytes(
                    data[pos:pos + 2],
                    "little"
                )
                pos += 2

                if version != 1:
                    continue

                # Group cipher suite
                pos += 4

                pairwise_count = int.from_bytes(
                    data[pos:pos + 2],
                    "little"
                )

                pos += 2 + (pairwise_count * 4)

                if pos + 2 > len(data):
                    break

                akm_count = int.from_bytes(
                    data[pos:pos + 2],
                    "little"
                )
                pos += 2

                akms = []

                for _ in range(akm_count):

                    if pos + 4 > len(data):
                        break

                    suite = data[pos:pos + 4]
                    pos += 4

                    # OUI 00:0f:ac = IEEE 802.11
                    if suite[:3] == b"\x00\x0f\xac":
                        akms.append(suite[3])

                # Common IEEE 802.11 AKM types:
                #
                # 1 = 802.1X
                # 2 = PSK
                # 8 = SAE (WPA3-Personal)
                # 9 = FT-SAE

                if 8 in akms or 9 in akms:
                    return "WPA3"

                if 2 in akms:
                    return "WPA2-PSK"

                if 1 in akms:
                    return "WPA2-Enterprise"

                return "WPA2/RSN"

            except Exception:
                pass

        return "WPA2/RSN"

    if has_wpa_vendor:
        return "WPA"

    # Privacy bit in the Beacon capability field indicates WEP
    if pkt.haslayer(Dot11Beacon):
        try:
            capability = pkt[Dot11Beacon].cap

            if capability & 0x0010:
                return "WEP"

        except Exception:
            pass

    if pkt.haslayer(Dot11ProbeResp):
        try:
            capability = pkt[Dot11ProbeResp].cap

            if capability & 0x0010:
                return "WEP"

        except Exception:
            pass

    return "Open"


def get_bssid(pkt):
    """
    Determine the BSSID from an 802.11 packet.

    For infrastructure networks:

      ToDS=0, FromDS=0 -> addr3
      ToDS=1, FromDS=0 -> addr1
      ToDS=0, FromDS=1 -> addr2
    """

    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]

    # Management frames
    if dot11.type == 0:

        # Beacons / probe responses have BSSID in addr3
        return mac_normalize(dot11.addr3)

    # Data frames
    if dot11.type == 2:

        to_ds = dot11.FCfield & 0x1
        from_ds = dot11.FCfield & 0x2

        if not to_ds and not from_ds:
            return mac_normalize(dot11.addr3)

        if to_ds and not from_ds:
            return mac_normalize(dot11.addr1)

        if not to_ds and from_ds:
            return mac_normalize(dot11.addr2)

        # WDS frame
        return None

    return None


def get_client_for_packet(pkt, bssid):
    """Determine the likely client MAC associated with a packet."""

    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]

    # Data frames
    if dot11.type == 2:

        to_ds = dot11.FCfield & 0x1
        from_ds = dot11.FCfield & 0x2

        if to_ds and not from_ds:
            # Client -> AP
            return mac_normalize(dot11.addr2)

        if from_ds and not to_ds:
            # AP -> Client
            return mac_normalize(dot11.addr1)

    # Management frames
    if dot11.type == 0:

        subtype = dot11.subtype

        # Association request / reassociation request
        if subtype in (0, 2):
            return mac_normalize(dot11.addr2)

        # Association response / reassociation response
        if subtype in (1, 3):
            return mac_normalize(dot11.addr1)

        # Authentication
        if subtype == 11:

            if mac_normalize(dot11.addr1) == bssid:
                return mac_normalize(dot11.addr2)

            if mac_normalize(dot11.addr2) == bssid:
                return mac_normalize(dot11.addr1)

    return None


def format_table(networks, limit=None):
    """Print network information as an ASCII table."""

    rows = []

    for _, data in networks.items():

        ssid = data["ssid"] or "<hidden>"
        encryption = data["encryption"]
        aps = len(data["bssids"])
        clients = len(data["clients"])

        rows.append(
            (
                ssid,
                encryption,
                aps,
                clients
            )
        )

    # Sort by number of APs, then clients.
    rows.sort(
        key=lambda x: (x[2], x[3]),
        reverse=True
    )

    if limit:
        rows = rows[:limit]

    headers = [
        "SSID",
        "Encryption/authorization",
        "# access points",
        "# clients",
    ]

    widths = [
        max(
            len(headers[0]),
            *(len(str(r[0])) for r in rows)
        ) if rows else len(headers[0]),

        max(
            len(headers[1]),
            *(len(str(r[1])) for r in rows)
        ) if rows else len(headers[1]),

        max(
            len(headers[2]),
            *(len(str(r[2])) for r in rows)
        ) if rows else len(headers[2]),

        max(
            len(headers[3]),
            *(len(str(r[3])) for r in rows)
        ) if rows else len(headers[3]),
    ]

    separator = (
        "+-"
        + "-+-".join("-" * w for w in widths)
        + "-+"
    )

    print(separator)

    print(
        "| "
        + " | ".join(
            headers[i].ljust(widths[i])
            for i in range(len(headers))
        )
        + " |"
    )

    print(separator)

    for row in rows:

        print(
            "| "
            + " | ".join(
                str(row[i]).ljust(widths[i])
                for i in range(len(row))
            )
            + " |"
        )

    print(separator)


def analyze_pcap(filename, limit=None):
    """
    Analyze a Kismet PCAP-NG capture.
    """

    networks = {}

    # Map BSSID -> observed client MAC addresses
    clients_by_bssid = defaultdict(set)

    packet_count = 0

    print(f"Reading: {filename}")

    with PcapNgReader(filename) as pcap:

        for pkt in pcap:

            packet_count += 1

            if not pkt.haslayer(Dot11):
                continue

            dot11 = pkt[Dot11]

            bssid = get_bssid(pkt)

            if not bssid:
                continue

            if bssid == "ff:ff:ff:ff:ff:ff":
                continue

            #
            # Discover networks from Beacons / Probe Responses
            #

            if dot11.type == 0 and dot11.subtype in (8, 5):

                ssid = get_ssid(pkt)

                if bssid not in networks:

                    networks[bssid] = {
                        "ssid": ssid,
                        "encryption": classify_encryption(pkt),
                        "bssids": {bssid},
                        "clients": set(),
                    }

                else:

                    if networks[bssid]["ssid"] in (None, "") and ssid:
                        networks[bssid]["ssid"] = ssid

            #
            # We may encounter data packets before seeing a beacon.
            #

            if bssid not in networks:

                networks[bssid] = {
                    "ssid": None,
                    "encryption": "Unknown",
                    "bssids": {bssid},
                    "clients": set(),
                }

            #
            # Determine associated client
            #

            client = get_client_for_packet(
                pkt,
                bssid
            )

            if client and client != bssid:

                # Ignore broadcast/multicast addresses
                if not client.startswith(
                    (
                        "ff:",
                        "01:00:5e:"
                    )
                ):
                    clients_by_bssid[bssid].add(client)

    #
    # Transfer client sets into network records.
    #

    for bssid, clients in clients_by_bssid.items():

        if bssid in networks:
            networks[bssid]["clients"].update(clients)

    #
    # Group multiple BSSIDs broadcasting the same
    # SSID + encryption combination.
    #

    grouped = {}

    for bssid, data in networks.items():

        ssid = data["ssid"] or "<hidden>"
        encryption = data["encryption"]

        key = (
            ssid,
            encryption
        )

        if key not in grouped:

            grouped[key] = {
                "ssid": ssid,
                "encryption": encryption,
                "bssids": set(),
                "clients": set(),
            }

        grouped[key]["bssids"].update(
            data["bssids"]
        )

        grouped[key]["clients"].update(
            data["clients"]
        )

    print()
    print(f"Packets analyzed: {packet_count:,}")
    print(f"Networks/BSSIDs found: {len(networks):,}")
    print()

    format_table(
        grouped,
        limit=limit
    )


def main():

    parser = argparse.ArgumentParser(
        description=(
            "Analyze a Kismet PCAP-NG wireless capture "
            "and display discovered wireless networks."
        )
    )

    parser.add_argument(
        "pcap",
        metavar="PCAPNG",
        help="Kismet PCAP-NG file to analyze"
    )

    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        metavar="N",
        help="Show only the top N networks"
    )

    args = parser.parse_args()

    analyze_pcap(
        args.pcap,
        args.limit
    )


if __name__ == "__main__":
    main()