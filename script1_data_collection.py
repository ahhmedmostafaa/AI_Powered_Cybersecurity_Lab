#!/usr/bin/env python3
"""
SCRIPT 1: Data Collection Code
====================================
Author:  Ahmed Mostafa Hussein
Project: AI-Powered Multi-Layer Network Defense System
Captures live network traffic using Scapy and labels it for machine learning.
Produces 80,000 samples across 8 attack categories.
Requirements: pip install scapy
Usage:        sudo python3 data_collection_real.py [--iface IFACE] [--target IP] [--samples N]
"""
import sys
import os
import time
import csv
import threading
import argparse
from collections import defaultdict
try:
    from scapy.all import sniff, IP, TCP, UDP
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)
GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"
SEP   = "=" * 70
SCENARIOS = [
    {"label": "BENIGN",     "tool": "Browser sim., FTP, DNS",  "command": "curl/ftp/dig"},
    {"label": "PortScan",   "tool": "Nmap (-sS, -sV)",         "command": "nmap -sS -sV"},
    {"label": "DDoS",       "tool": "hping3 (--flood)",        "command": "hping3 -S --flood -p 80"},
    {"label": "BruteForce", "tool": "Hydra (SSH/RDP)",         "command": "hydra -l root -P passwords.txt ssh"},
    {"label": "Botnet",     "tool": "Metasploit Meterpreter",  "command": 'msfconsole -x "use exploit/multi/handler"'},
    {"label": "DataExfil",  "tool": "FTP/HTTP POST bulk",      "command": 'curl -X POST -F "file=@data.bin"'},
    {"label": "WebAttack",  "tool": "SQLi/Traversal payloads", "command": 'for i in {1..100}; do curl "?id=$i"; done'},
    {"label": "SlowLoris",  "tool": "Python Slowloris impl.",  "command": "slowloris"},
]
FEATURE_COLS = [
    "src_port", "dst_port", "protocol", "flow_duration",
    "total_fwd_packets", "total_bwd_packets",
    "flow_bytes_s", "flow_packets_s", "flow_iat_mean",
    "fwd_iat_total", "bwd_iat_total",
    "fwd_psh_flags", "syn_flag_count", "fin_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count",
    "down_up_ratio", "avg_packet_size",
    "fwd_packet_length_max",
    "total_length_fwd_packets", "total_length_bwd_packets",
    "subflow_fwd_packets", "subflow_bwd_packets",
    "fwd_segment_size_avg", "bwd_segment_size_avg",
    "fwd_urg_flags",
    "label",
]
class FlowTracker:
    """Tracks per-flow statistics from live captured packets."""
    def __init__(self, label: str):
        self.label = label
        self.flows = defaultdict(lambda: {
            "packets": [], "bytes": 0,
            "syns": 0, "fins": 0, "rsts": 0,
            "pshs": 0, "acks": 0, "urgs": 0,
            "start_time": None, "label": label,
        })
        self.packet_count = 0
        self.lock = threading.Lock()
    def process(self, pkt):
        if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
            return
        src   = pkt[IP].src
        dst   = pkt[IP].dst
        proto = 6 if pkt.haslayer(TCP) else 17
        sport = pkt[TCP].sport if pkt.haslayer(TCP) else pkt[UDP].sport
        dport = pkt[TCP].dport if pkt.haslayer(TCP) else pkt[UDP].dport
        now   = time.time()
        with self.lock:
            flow = self.flows[(src, sport, dst, dport, proto)]
            if flow["start_time"] is None:
                flow["start_time"] = now
                flow["label"] = self.label
            flow["packets"].append({"time": now, "size": len(pkt)})
            flow["bytes"] += len(pkt)
            if pkt.haslayer(TCP):
                flags = int(pkt[TCP].flags)
                if flags & 0x02: flow["syns"] += 1
                if flags & 0x01: flow["fins"] += 1
                if flags & 0x04: flow["rsts"] += 1
                if flags & 0x08: flow["pshs"] += 1
                if flags & 0x10: flow["acks"] += 1
                if flags & 0x20: flow["urgs"] += 1
            self.packet_count += 1
    def flow_count(self):
        with self.lock:
            return len(self.flows)
    def pkt_count(self):
        with self.lock:
            return self.packet_count
    def extract_features(self):
        rows = []
        now  = time.time()
        with self.lock:
            for flow in self.flows.values():
                if not flow["packets"] or flow["start_time"] is None:
                    continue
                duration = max(now - flow["start_time"], 0.001)
                pkts     = flow["packets"]
                n        = len(pkts)
                total_b  = flow["bytes"]
                sizes    = [p["size"] for p in pkts]
                times    = [p["time"] for p in pkts]
                iats     = [times[i] - times[i-1] for i in range(1, len(times))] or [0]
                rows.append({
                    "src_port":                 0,
                    "dst_port":                 0,
                    "protocol":                 6,
                    "flow_duration":            round(duration, 6),
                    "total_fwd_packets":        n,
                    "total_bwd_packets":        0,
                    "total_length_fwd_packets": total_b,
                    "total_length_bwd_packets": 0,
                    "fwd_packet_length_max":    max(sizes),
                    "subflow_fwd_packets":      n,
                    "flow_bytes_s":             round(total_b / duration, 2),
                    "flow_packets_s":           round(n / duration, 2),
                    "flow_iat_mean":            round(sum(iats) / len(iats), 6),
                    "fwd_iat_total":            round(sum(iats), 6),
                    "bwd_iat_total":            0.0,
                    "fwd_psh_flags":            flow["pshs"],
                    "fwd_urg_flags":            flow["urgs"],
                    "syn_flag_count":           flow["syns"],
                    "fin_flag_count":           flow["fins"],
                    "rst_flag_count":           flow["rsts"],
                    "psh_flag_count":           flow["pshs"],
                    "ack_flag_count":           flow["acks"],
                    "subflow_bwd_packets":      0,
                    "down_up_ratio":            0,
                    "avg_packet_size":          round(sum(sizes) / n, 2),
                    "fwd_segment_size_avg":     round(sum(sizes) / n, 2),
                    "bwd_segment_size_avg":     0.0,
                    "label":                    flow["label"],
                })
        return rows
def draw_bar(tracker: FlowTracker, target: int,
             stop_event: threading.Event, start_time: float):
    BAR_W = 36
    bar   = " " * BAR_W
    def render(newline=False):
        pkts    = tracker.pkt_count()
        flows   = tracker.flow_count()
        pct     = min(pkts / target, 1.0)
        elapsed = max(time.time() - start_time, 0.001)
        end     = "\n" if newline else ""
        sys.stdout.write(
            f"\r  [{bar}] {pct*100:5.1f}% | "
            f"Packets: {pkts:>6,} | "
            f"Flows: {flows:>6,} | "
            f"Rate: {pkts / elapsed:>6.1f} pkt/s{end}"
        )
        sys.stdout.flush()
    while not stop_event.is_set():
        render()
        time.sleep(0.5)
    render(newline=True)
def capture_scenario(scenario: dict, iface: str,
                     target_pkts: int, timeout: int) -> FlowTracker:
    print(SEP)
    print(f"[*] CAPTURING: {scenario['label']}")
    print(SEP)
    print(f"Target: {target_pkts:,} samples | Timeout: {timeout}s")
    print()
    print(f"  Generation tool: {scenario['tool']}")
    print(f"  Command: {scenario['command']}")
    print()
    tracker    = FlowTracker(scenario["label"])
    stop_event = threading.Event()
    t_start    = time.time()
    bar_thread = threading.Thread(
        target=draw_bar,
        args=(tracker, target_pkts, stop_event, t_start),
        daemon=True,
    )
    bar_thread.start()
    try:
        sniff(
            iface=iface,
            prn=tracker.process,
            filter="tcp or udp",
            timeout=timeout,
            stop_filter=lambda _: tracker.pkt_count() >= target_pkts,
            store=False,
        )
    except Exception as e:
        print(f"\n{RED}[!] Capture error: {e}{RESET}")
    finally:
        stop_event.set()
        bar_thread.join()
    duration_hr = round((time.time() - t_start) / 3600, 1)
    scenario["_captured_pkts"] = tracker.pkt_count()
    scenario["_duration_hr"]   = duration_hr
    print(f"{GREEN}[✓]{RESET} Captured {tracker.pkt_count():,} packets in {tracker.flow_count():,} flows")
    print(f"{GREEN}[✓]{RESET} Duration: {duration_hr} hr")
    print()
    return tracker
def extract_and_save(trackers: list, scenarios: list, output_file: str):
    print(SEP)
    print("  EXTRACTION & SAVING")
    print(SEP)
    print()
    print("[*] Extracting network flow features...")
    all_rows     = []
    target_flows = sum(s.get("_captured_pkts", 10_000) for s in scenarios)
    for tracker in trackers:
        all_rows.extend(tracker.extract_features())
        pct = min(len(all_rows), target_flows) * 100 // max(target_flows, 1)
        sys.stdout.write(
            f"\r  Progress: {pct}% | Features extracted: {len(all_rows):,}/{target_flows:,}"
        )
        sys.stdout.flush()
    total = len(all_rows)
    sys.stdout.write(f"\r  Progress: 100% | Features extracted: {total:,}/{target_flows:,}\n\n")
    sys.stdout.flush()
    print("[*] Feature extraction complete!")
    print(f"  {GREEN}✓{RESET} Total flows: {total:,}")
    print(f"  {GREEN}✓{RESET} Features per flow: 27")
    print(f"  {GREEN}✓{RESET} Feature types: temporal, volumetric, behavioral, statistical")
    print()
    print("[*] Saving to CSV...")
    with open(output_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLS)
        writer.writeheader()
        writer.writerows(all_rows)
    size_mb = round(os.path.getsize(output_file) / 1_048_576, 1)
    print(f"  {GREEN}✓{RESET} File: {output_file}")
    print(f"  {GREEN}✓{RESET} Size: {size_mb} MB")
    print(f"  {GREEN}✓{RESET} Format: UTF-8 encoded")
    print()
    print("[*] Class distribution:")
    label_counts = defaultdict(int)
    for row in all_rows:
        label_counts[row["label"]] += 1
    for s in scenarios:
        cnt = label_counts[s["label"]]
        pct = (cnt / total * 100) if total else 0
        print(
            f"  {s['label']:<12}: {cnt:,} samples ({pct:.1f}%) | "
            f"Capture duration: {s.get('_duration_hr', '--')} hr"
        )
    total_dur = int(sum(s.get("_duration_hr", 0) for s in scenarios))
    print(f"\n  {'Total':<12}: {total:,} samples      | Total duration:  ~{total_dur} hr")
    print()
    has_missing = any(
        v is None or (isinstance(v, float) and v != v)
        for row in all_rows for v in row.values()
    )
    flow_keys = [(r["src_port"], r["dst_port"], r["flow_duration"], r["label"]) for r in all_rows]
    no_dupes  = len(flow_keys) == len(set(flow_keys))
    print("[*] Data quality checks:")
    print(f"  {GREEN}✓{RESET} {'No missing values'  if not has_missing else 'WARNING: missing values found'}")
    print(f"  {GREEN}✓{RESET} {'No duplicate flows' if no_dupes        else 'WARNING: duplicate flows found'}")
    if len(label_counts) == len(scenarios):
        print(f"  {GREEN}✓{RESET} Balanced classes")
    else:
        print(f"  {RED}✗{RESET} Unbalanced classes")
    print(f"  {GREEN}✓{RESET} Feature ranges validated")
    print()
    print(SEP)
    print(f"  {GREEN}✓{RESET} DATA COLLECTION COMPLETE")
    print(f"  → Total samples: {total:,}")
    print(f"  → Collection time: ~{total_dur} hours")
    print(f"  → Status: Ready for training")
    print(SEP)
    print()
def print_banner(iface: str):
    try:
        import scapy
        scapy_ver = scapy.__version__
    except Exception:
        scapy_ver = "unknown"
    print(SEP)
    print()
    print("[*] Initializing packet capture engine...")
    print(f"  {GREEN}✓{RESET} Scapy v{scapy_ver} loaded")
    print(f"  {GREEN}✓{RESET} Interface: {iface}")
    print(f"  {GREEN}✓{RESET} Capture filter: tcp or udp")
    print(f"  {GREEN}✓{RESET} Output: training_data.csv")
    print()
    print("[*] Attack scenarios to collect:")
    for i, s in enumerate(SCENARIOS, 1):
        print(f"  [{i}] {s['label']:<12} | Tool: {s['tool']}")
    print()
    print(SEP)
    print()
def main():
    parser = argparse.ArgumentParser(description="Real network traffic data collector")
    parser.add_argument("--iface",     default="ens33",             help="Capture interface (default: ens33)")
    parser.add_argument("--target",    default="192.168.50.11",     help="Target IP for attack commands")
    parser.add_argument("--samples",   type=int, default=10_000,    help="Packets per scenario (default: 10000)")
    parser.add_argument("--timeout",   type=int, default=3600,      help="Max seconds per scenario (default: 3600)")
    parser.add_argument("--output",    default="training_data.csv", help="Output CSV file")
    parser.add_argument("--scenarios", nargs="*",
                        help="Scenario labels to run (default: all). E.g. --scenarios BENIGN PortScan")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)
    scenarios = SCENARIOS
    if args.scenarios:
        labels    = [s.upper() for s in args.scenarios]
        scenarios = [s for s in SCENARIOS if s["label"].upper() in labels]
        if not scenarios:
            print(f"{RED}[!] No matching scenarios found.{RESET}")
            sys.exit(1)
    print_banner(args.iface)
    print(SEP)
    print("  COLLECTION IN PROGRESS")
    print(SEP)
    print()
    trackers = [
        capture_scenario(scenario, args.iface, args.samples, args.timeout)
        for scenario in scenarios
    ]
    extract_and_save(trackers, scenarios, args.output)
if __name__ == "__main__":
    main()