# Kismet Quick Reporter

Kismet Quick Reporter is a small Python utility that analyzes a Kismet-generated PCAP-NG wireless capture and produces a quick summary of observed wireless networks.

It identifies SSIDs, attempts to classify wireless encryption/authentication, counts observed access points, and estimates the number of associated clients. Results can be printed directly to the terminal or written as a standalone HTML report.

## Features

* Reads Kismet `.pcapng` captures
* Identifies observed SSIDs
* Groups multiple BSSIDs belonging to the same SSID
* Best-effort classification of Open, WEP, WPA, WPA2-PSK, WPA2-Enterprise, and WPA3
* Counts observed access points
* Counts observed wireless clients
* Sorts results by the number of observed access points and clients
* Optional result limit
* Optional standalone HTML report
* Progress bars for importing/scanning, analyzing packets, and calculating/grouping results

## Requirements

* Python 3
* Scapy
* tqdm

Install dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## Usage

```bash
python3 KismetQuickReporter.py PCAPNG
```

Example:

```bash
python3 KismetQuickReporter.py capture.pcapng
```

### Limit Results

Use `-n` or `--limit` to show only the top N result rows:

```bash
python3 KismetQuickReporter.py capture.pcapng --limit 20
```

or:

```bash
python3 KismetQuickReporter.py capture.pcapng -n 20
```

### HTML Output

Use `--html` to write the results to a standalone HTML file instead of printing the table to stdout:

```bash
python3 KismetQuickReporter.py capture.pcapng --html report.html
```

You can combine HTML output with the result limit:

```bash
python3 KismetQuickReporter.py capture.pcapng --limit 20 --html report.html
```

## Example Terminal Output

```text
Reading: capture.pcapng

1/3 Importing capture:    100%|████████████████████| 136M/136M
2/3 Analyzing packets:    100%|████████████████████| 582341/582341
3/3 Calculating results:  100%|████████████████████| 428/428

Packets analyzed: 582,341
Networks/BSSIDs found: 214

+----------------------+--------------------------+-----------------+-----------+
| SSID                 | Encryption/authorization | # access points | # clients |
+----------------------+--------------------------+-----------------+-----------+
| ExampleWireless      | WPA2-PSK                 | 8               | 37        |
| ExampleEnterprise    | WPA2-Enterprise          | 5               | 22        |
| Guest                | Open                     | 3               | 14        |
+----------------------+--------------------------+-----------------+-----------+
```

## Command-Line Options

```text
usage: KismetQuickReporter.py [-h] [-n N] [--html FILE] PCAPNG
```

* `PCAPNG` - Kismet PCAP-NG file to analyze.
* `-n N`, `--limit N` - Show only the top N result rows.
* `--html FILE` - Write a standalone HTML report instead of printing the results table to stdout.
* `-h`, `--help` - Display command-line help.

## How It Works

Kismet Quick Reporter processes the capture in three stages.

### 1. Importing the Capture

The first pass scans the PCAP-NG file and determines the number of packets in the capture. This provides an accurate packet total for the analysis progress bar without loading the entire capture into memory.

### 2. Analyzing Packets

The second pass analyzes 802.11 frames.

The script uses beacon and probe-response frames to identify wireless networks and SSIDs. It also examines 802.11 addressing information to associate observed client MAC addresses with BSSIDs.

Encryption/authentication classification is derived from available 802.11 information elements and should be considered a best-effort summary.

### 3. Calculating Results

Observed BSSIDs and clients are grouped by SSID and encryption type. The final results are then sorted by the number of access points and clients observed.

## Large Capture Files

The program is designed to process captures without loading the entire PCAP-NG file into memory.

For an accurate progress indicator, the capture is read once during the import/counting stage and again during packet analysis. As a result, very large captures can take some time to process.

Processing speed depends heavily on capture size, packet count, storage speed, CPU performance, and Scapy packet-decoding performance.

## Notes and Limitations

* Client counts are based on MAC addresses observed in relevant 802.11 frames.
* MAC randomization may cause a single physical client to appear as multiple clients.
* A client may be counted under more than one network if it is observed communicating with multiple BSSIDs.
* Hidden SSIDs may remain listed as `<hidden>` if the SSID cannot be recovered from observed management frames.
* Encryption/authentication detection is best effort and depends on the information elements present in the capture.
* WPA2/WPA3 transition networks and less common authentication suites may be summarized rather than identified with complete precision.
* Captures without native 802.11 frames may not provide useful results.

## Repository Files

```text
KismetQuickReporter.py
requirements.txt
README.md
```

## License

Add the license appropriate for your project here.
::: 
