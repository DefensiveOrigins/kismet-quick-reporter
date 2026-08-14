#!/usr/bin/env python3

import argparse
import html
import os
import sys
from collections import defaultdict
from pathlib import Path

from scapy.all import PcapNgReader, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11Elt
from tqdm import tqdm


def mac_normalize(mac):
    return mac.lower() if mac else None


def get_ssid(pkt):
    """Extract SSID from a Beacon or Probe Response."""
    if not pkt.haslayer(Dot11Elt):
        return None

    elt = pkt[Dot11Elt]

    while elt:
        if elt.ID == 0:
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
    """Best-effort classification of encryption/authentication."""
    elements = get_information_elements(pkt)

    has_rsn = any(eid == 48 for eid, _ in elements)
    has_wpa_vendor = any(
        eid == 221 and (b"\x00\x50\xf2\x01" in data or b"WPA" in data)
        for eid, data in elements
    )

    if has_rsn:
        for eid, data in elements:
            if eid != 48 or len(data) < 8:
                continue

            try:
                pos = 0

                version = int.from_bytes(data[pos:pos + 2], "little")
                pos += 2

                if version != 1:
                    continue

                if pos + 4 > len(data):
                    continue
                pos += 4

                if pos + 2 > len(data):
                    continue

                pairwise_count = int.from_bytes(
                    data[pos:pos + 2], "little"
                )
                pos += 2 + (pairwise_count * 4)

                if pos + 2 > len(data):
                    continue

                akm_count = int.from_bytes(
                    data[pos:pos + 2], "little"
                )
                pos += 2

                akms = []

                for _ in range(akm_count):
                    if pos + 4 > len(data):
                        break

                    suite = data[pos:pos + 4]
                    pos += 4

                    if suite[:3] == b"\x00\x0f\xac":
                        akms.append(suite[3])

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
    """Determine the BSSID from an 802.11 packet."""
    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]

    if dot11.type == 0:
        return mac_normalize(dot11.addr3)

    if dot11.type == 2:
        to_ds = bool(dot11.FCfield & 0x1)
        from_ds = bool(dot11.FCfield & 0x2)

        if not to_ds and not from_ds:
            return mac_normalize(dot11.addr3)

        if to_ds and not from_ds:
            return mac_normalize(dot11.addr1)

        if not to_ds and from_ds:
            return mac_normalize(dot11.addr2)

        return None

    return None


def get_client_for_packet(pkt, bssid):
    """Determine the likely client MAC associated with a packet."""
    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]

    if dot11.type == 2:
        to_ds = bool(dot11.FCfield & 0x1)
        from_ds = bool(dot11.FCfield & 0x2)

        if to_ds and not from_ds:
            return mac_normalize(dot11.addr2)

        if from_ds and not to_ds:
            return mac_normalize(dot11.addr1)

    if dot11.type == 0:
        subtype = dot11.subtype

        if subtype in (0, 2):
            return mac_normalize(dot11.addr2)

        if subtype in (1, 3):
            return mac_normalize(dot11.addr1)

        if subtype == 11:
            if mac_normalize(dot11.addr1) == bssid:
                return mac_normalize(dot11.addr2)

            if mac_normalize(dot11.addr2) == bssid:
                return mac_normalize(dot11.addr1)

    return None


def is_ignored_client(mac):
    """Return True for broadcast or multicast MAC addresses."""
    if not mac:
        return True

    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x01)
    except (ValueError, IndexError):
        return True


def count_packets(filename):
    """
    Stage 1: scan/import the capture and count packets.

    This first pass allows the analysis progress bar to have an exact total
    without loading a large PCAP into memory.
    """
    packet_count = 0
    file_size = os.path.getsize(filename)

    with open(filename, "rb") as fh:
        with PcapNgReader(fh) as pcap:
            with tqdm(
                total=file_size,
                desc="1/3 Importing capture",
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                dynamic_ncols=True,
            ) as progress:
                last_position = 0

                for _ in pcap:
                    packet_count += 1

                    try:
                        position = fh.tell()
                    except (OSError, ValueError):
                        position = last_position

                    if position > last_position:
                        progress.update(position - last_position)
                        last_position = position

                if last_position < file_size:
                    progress.update(file_size - last_position)

    return packet_count


def analyze_packets(filename, packet_count):
    """Stage 2: analyze 802.11 packets and collect BSSID/client data."""
    networks = {}
    clients_by_bssid = defaultdict(set)

    with PcapNgReader(str(filename)) as pcap:
        with tqdm(
            total=packet_count,
            desc="2/3 Analyzing packets",
            unit="pkt",
            dynamic_ncols=True,
        ) as progress:
            for pkt in pcap:
                progress.update(1)

                if not pkt.haslayer(Dot11):
                    continue

                dot11 = pkt[Dot11]
                bssid = get_bssid(pkt)

                if not bssid or bssid == "ff:ff:ff:ff:ff:ff":
                    continue

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

                        if networks[bssid]["encryption"] == "Unknown":
                            networks[bssid]["encryption"] = classify_encryption(pkt)

                if bssid not in networks:
                    networks[bssid] = {
                        "ssid": None,
                        "encryption": "Unknown",
                        "bssids": {bssid},
                        "clients": set(),
                    }

                client = get_client_for_packet(pkt, bssid)

                if (
                    client
                    and client != bssid
                    and not is_ignored_client(client)
                ):
                    clients_by_bssid[bssid].add(client)

    return networks, clients_by_bssid


def calculate_results(networks, clients_by_bssid):
    """Stage 3: attach clients and group BSSIDs by SSID/encryption."""
    grouped = {}

    total_work = len(clients_by_bssid) + len(networks)

    with tqdm(
        total=total_work,
        desc="3/3 Calculating results",
        unit="item",
        dynamic_ncols=True,
    ) as progress:
        for bssid, clients in clients_by_bssid.items():
            if bssid in networks:
                networks[bssid]["clients"].update(clients)

            progress.update(1)

        for bssid, data in networks.items():
            ssid = data["ssid"] or "<hidden>"
            encryption = data["encryption"]
            key = (ssid, encryption)

            if key not in grouped:
                grouped[key] = {
                    "ssid": ssid,
                    "encryption": encryption,
                    "bssids": set(),
                    "clients": set(),
                }

            grouped[key]["bssids"].update(data["bssids"])
            grouped[key]["clients"].update(data["clients"])

            progress.update(1)

    return grouped


def build_rows(networks, limit=None):
    """Convert grouped network data into sorted result rows."""
    rows = []

    for data in networks.values():
        rows.append(
            (
                data["ssid"] or "<hidden>",
                data["encryption"],
                len(data["bssids"]),
                len(data["clients"]),
            )
        )

    rows.sort(key=lambda row: (row[2], row[3]), reverse=True)

    if limit is not None:
        rows = rows[:limit]

    return rows


def format_table(rows):
    """Return an ASCII table as a string."""
    headers = [
        "SSID",
        "Encryption/authorization",
        "# access points",
        "# clients",
    ]

    widths = []

    for index, header in enumerate(headers):
        value_width = max(
            (len(str(row[index])) for row in rows),
            default=0,
        )
        widths.append(max(len(header), value_width))

    separator = "+-" + "-+-".join("-" * width for width in widths) + "-+"

    output = [
        separator,
        "| "
        + " | ".join(
            headers[i].ljust(widths[i])
            for i in range(len(headers))
        )
        + " |",
        separator,
    ]

    for row in rows:
        output.append(
            "| "
            + " | ".join(
                str(row[i]).ljust(widths[i])
                for i in range(len(row))
            )
            + " |"
        )

    output.append(separator)

    return "\n".join(output)


def write_html(filename, source_pcap, packet_count, bssid_count, rows):
    """Write a standalone HTML results report."""
    report_title = "Kismet Wireless Capture Summary"

    table_rows = []

    for ssid, encryption, aps, clients in rows:
        table_rows.append(
            "        <tr>\n"
            f"          <td>{html.escape(str(ssid))}</td>\n"
            f"          <td>{html.escape(str(encryption))}</td>\n"
            f"          <td class=\"number\">{aps}</td>\n"
            f"          <td class=\"number\">{clients}</td>\n"
            "        </tr>"
        )

    table_body = "\n".join(table_rows)

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(report_title)}</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}

    body {{
      margin: 0;
      padding: 2rem;
      background: Canvas;
      color: CanvasText;
    }}

    main {{
      max-width: 1100px;
      margin: 0 auto;
    }}

    h1 {{
      margin-bottom: 0.25rem;
    }}

    .summary {{
      display: flex;
      gap: 1rem;
      flex-wrap: wrap;
      margin: 1.5rem 0;
    }}

    .summary div {{
      border: 1px solid color-mix(in srgb, CanvasText 20%, transparent);
      border-radius: 0.5rem;
      padding: 0.75rem 1rem;
      min-width: 160px;
    }}

    .summary strong {{
      display: block;
      font-size: 1.35rem;
      margin-top: 0.25rem;
    }}

    .table-wrap {{
      overflow-x: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
    }}

    th, td {{
      padding: 0.65rem 0.8rem;
      border-bottom: 1px solid color-mix(in srgb, CanvasText 18%, transparent);
      text-align: left;
      white-space: nowrap;
    }}

    th {{
      position: sticky;
      top: 0;
      background: Canvas;
    }}

    .number {{
      text-align: right;
    }}

    .source {{
      color: color-mix(in srgb, CanvasText 70%, transparent);
      overflow-wrap: anywhere;
    }}
  </style>
</head>
<body>
  <main>
    <h1>{html.escape(report_title)}</h1>
    <div class="source">Source: {html.escape(str(source_pcap))}</div>

    <section class="summary">
      <div>
        Packets analyzed
        <strong>{packet_count:,}</strong>
      </div>
      <div>
        BSSIDs found
        <strong>{bssid_count:,}</strong>
      </div>
      <div>
        Result rows
        <strong>{len(rows):,}</strong>
      </div>
    </section>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>SSID</th>
            <th>Encryption/authorization</th>
            <th class="number"># access points</th>
            <th class="number"># clients</th>
          </tr>
        </thead>
        <tbody>
{table_body}
        </tbody>
      </table>
    </div>
  </main>
</body>
</html>
"""

    Path(filename).write_text(document, encoding="utf-8")


def analyze_pcap(filename, limit=None, html_output=None):
    """Analyze a Kismet PCAP-NG capture."""
    input_path = Path(filename)

    if not input_path.is_file():
        raise FileNotFoundError(f"Input file does not exist: {filename}")

    print(f"Reading: {input_path}", file=sys.stderr)

    packet_count = count_packets(input_path)
    networks, clients_by_bssid = analyze_packets(input_path, packet_count)
    grouped = calculate_results(networks, clients_by_bssid)
    rows = build_rows(grouped, limit=limit)

    if html_output:
        write_html(
            filename=html_output,
            source_pcap=input_path,
            packet_count=packet_count,
            bssid_count=len(networks),
            rows=rows,
        )

        print(
            f"HTML report written to: {Path(html_output).resolve()}",
            file=sys.stderr,
        )
    else:
        print()
        print(f"Packets analyzed: {packet_count:,}")
        print(f"Networks/BSSIDs found: {len(networks):,}")
        print()
        print(format_table(rows))


def positive_int(value):
    """argparse type for a positive integer."""
    parsed = int(value)

    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")

    return parsed


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Analyze a Kismet PCAP-NG wireless capture and summarize "
            "SSIDs, encryption, access points, and observed clients."
        )
    )

    parser.add_argument(
        "pcap",
        metavar="PCAPNG",
        help="Kismet PCAP-NG file to analyze",
    )

    parser.add_argument(
        "-n",
        "--limit",
        type=positive_int,
        default=None,
        metavar="N",
        help="Show only the top N result rows",
    )

    parser.add_argument(
        "--html",
        metavar="FILE",
        help=(
            "Write a standalone HTML report instead of printing the "
            "results table to stdout"
        ),
    )

    args = parser.parse_args()

    try:
        analyze_pcap(
            filename=args.pcap,
            limit=args.limit,
            html_output=args.html,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()