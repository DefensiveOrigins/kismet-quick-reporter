def main():
    parser = argparse.ArgumentParser(
        description="Analyze a Kismet PCAP-NG wireless capture."
    )

    parser.add_argument(
        "pcap",
        help="Kismet PCAP-NG file to analyze"
    )

    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=None,
        help="Show only the top N networks"
    )

    args = parser.parse_args()

    analyze_pcap(args.pcap, args.limit)


if __name__ == "__main__":
    main()