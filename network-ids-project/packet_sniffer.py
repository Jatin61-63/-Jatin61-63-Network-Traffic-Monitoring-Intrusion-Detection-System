"""Authorized packet metadata collector. Does not store packet payloads."""
import argparse, json
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import sniff, IP, TCP, UDP, ICMP, rdpcap
from ml_model import TrafficAnomalyModel

BASE_DIR = Path(__file__).resolve().parent
OUT = BASE_DIR / "data" / "traffic_logs.jsonl"

def packet_to_record(pkt, detector, source):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    protocol, src_port, dst_port, flags = "OTHER", 0, 0, ""
    if TCP in pkt:
        protocol, src_port, dst_port, flags = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport), str(pkt[TCP].flags)
    elif UDP in pkt:
        protocol, src_port, dst_port = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
    elif ICMP in pkt:
        protocol = "ICMP"
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "src_ip": ip.src, "dst_ip": ip.dst, "protocol": protocol,
        "src_port": src_port, "dst_port": dst_port, "packet_size": int(len(pkt)),
        "duration": 0.0, "flags": flags, "source": source
    }
    prediction = detector.predict(record)
    record.update({"label": prediction["label"], "confidence": prediction["confidence"],
                   "anomaly_score": prediction["anomaly_score"]})
    return record

def main():
    parser = argparse.ArgumentParser(description="Collect metadata from an authorized network interface or PCAP file.")
    parser.add_argument("--authorized", action="store_true", help="Confirm you have permission to monitor this traffic.")
    parser.add_argument("--interface", help="Interface name, e.g. Ethernet or wlan0 (live mode)")
    parser.add_argument("--pcap", help="Read an existing PCAP file (offline mode)")
    parser.add_argument("--count", type=int, default=100, help="Maximum packets to inspect in live mode")
    args = parser.parse_args()
    if not args.authorized:
        parser.error("Use --authorized only after confirming you own/administer the network or have explicit permission.")
    if bool(args.interface) == bool(args.pcap):
        parser.error("Choose exactly one: --interface for live capture OR --pcap for offline analysis.")
    detector = TrafficAnomalyModel().load()
    OUT.parent.mkdir(exist_ok=True)
    def handle(pkt):
        rec = packet_to_record(pkt, detector, "live-interface")
        if rec:
            with OUT.open("a", encoding="utf-8") as f: f.write(json.dumps(rec) + "\n")
            print(f'{rec["timestamp"]} {rec["src_ip"]} -> {rec["dst_ip"]} {rec["protocol"]} {rec["label"]}')
    if args.pcap:
        for pkt in rdpcap(args.pcap):
            handle(pkt)
        print(f"Offline metadata appended to {OUT}")
    else:
        print("Live capture started. Press Ctrl+C to stop.")
        sniff(iface=args.interface, prn=handle, store=False, count=max(1, args.count))
if __name__ == "__main__":
    main()
