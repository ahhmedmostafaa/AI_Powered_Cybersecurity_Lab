#!/usr/bin/env python3
"""
AI-POWERED NETWORK DEFENSE SYSTEM
==================================
Multi-layer cybersecurity defense combining:
  - XGBoost ML       : behavioral attack detection
  - Suricata IDS     : signature-based detection
  - Zeek Monitor     : network anomaly detection
  - Rule-based engine: fast scans, floods, brute force
"""

import subprocess
import time
import json
import threading
import os
import sys
import re
import signal
import warnings
import logging
import logging.handlers
import traceback
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.stdout.reconfigure(encoding='utf-8')


# ============================================================================
# CONFIGURATION
# ============================================================================

class Colors:
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    PURPLE  = '\033[95m'
    MAGENTA = '\033[35m'
    ORANGE  = '\033[38;5;208m'
    ENDC    = '\033[0m'
    BOLD    = '\033[1m'


class Config:
    # Network
    PFSENSE_IP      = "192.168.180.129"
    PFSENSE_USER    = "admin"
    PFSENSE_PASS    = "123"
    PFSENSE_WAN_IF  = "em0"
    LOCAL_IF        = "ens33"

    # Paths
    MODEL_DIR           = Path("/opt/ai-defense/models")
    LOG_DIR             = Path("/opt/ai-defense/logs")
    SURICATA_EVE_LOG    = Path("/var/log/suricata/eve.json")
    ZEEK_NOTICE_LOG     = None

    # Detection thresholds
    SLOW_SCAN_THRESHOLD     = 3
    FAST_SCAN_THRESHOLD     = 5
    SYN_FLOOD_THRESHOLD     = 200
    BRUTE_FORCE_LIMIT       = 15

    # ML
    AI_CONFIDENCE_THRESHOLD = 65.0
    AI_TRIGGER_ON_PORTS     = 2
    AI_MIN_PACKETS          = 5
    BOTNET_MIN_DURATION     = 90
    BOTNET_MIN_PACKETS      = 8

    # Time windows
    ANALYSIS_WINDOW         = 120
    PORT_SCAN_WINDOW        = 60
    PACKET_LIST_MAX         = 500
    PACKET_TIMES_MAX        = 500

    # Firewall sync
    FW_SYNC_INTERVAL        = 10
    GRACE_PERIOD_SECONDS    = 15

    # Whitelists
    WHITELIST_IPS      = {"192.168.180.128", "192.168.180.129", "192.168.180.2",
                          "192.168.180.1", "91.80.48.91", "10.11.220.106", "10.11.220.49"}
    WHITELIST_PREFIXES = ["192.168.150.", "127.", "8.8.", "1.1.", "1.0.",
                          "192.168.50.", "192.168.101.", "10.11.220."]
    LEGITIMATE_PORTS   = {53, 67, 68, 123, 137, 138, 161, 162, 1900, 5353, 5355}

    PROTECTED_NETWORKS = {
        "192.168.50.":  "LAN (Win11)",
        "192.168.101.": "LAN2 (Win10)",
    }

    # Noise filters for IDS layers
    SURICATA_NOISE = ['invalid checksum', 'SURICATA STREAM', 'SURICATA UDPv4',
                      'SURICATA TCPv4', 'SURICATA IPv4', 'ET INFO', 'ET POLICY',
                      'PORTSCAN Multiple SYN packets']

    ZEEK_NOISE = ['heartbeat', 'CaptureLoss', 'PacketFilter', 'Status',
                  'WeirdActivity::Generic', 'Info']

    # SSH
    SSH_TIMEOUT     = 60
    SSH_MAX_RETRIES = 2

    # Deduplication windows
    SURICATA_DEDUP_WINDOW   = 30
    ZEEK_DEDUP_WINDOW       = 180
    DEDUP_CLEANUP_INTERVAL  = 60
    DEDUP_MAX_AGE           = 300

    # Post-unblock cooldowns — prevent buffered packets/log lines from
    # re-blocking an IP immediately after it has been cleared.
    ZEEK_POST_UNBLOCK_COOLDOWN   = 120   # seconds
    PACKET_POST_UNBLOCK_COOLDOWN = 30    # seconds (tcpdump pipe buffer)


# ============================================================================
# LOGGING
# ============================================================================

def validate_config():
    errors = []
    for path in [Config.MODEL_DIR, Config.LOG_DIR]:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f'Cannot create {path}: {e}')

    try:
        import socket
        socket.inet_aton(Config.PFSENSE_IP)
    except socket.error:
        errors.append(f'Invalid PFSENSE_IP: {Config.PFSENSE_IP}')

    if not Config.PFSENSE_PASS:
        errors.append('PFSENSE_PASS not set')

    if errors:
        for err in errors:
            print(f'{Colors.RED}Config Error: {err}{Colors.ENDC}')
        sys.exit(1)


Config.LOG_DIR.mkdir(parents=True, exist_ok=True)
_file_handler = logging.handlers.RotatingFileHandler(
    Config.LOG_DIR / "defense.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
)
_file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_root_logger = logging.getLogger("aidefense")
_root_logger.setLevel(logging.DEBUG)
_root_logger.addHandler(_file_handler)
_log_lock = threading.Lock()

LEVEL_COLORS = {
    "ATTACK":   Colors.YELLOW,
    "BLOCK":    Colors.RED + Colors.BOLD,
    "TARGET":   Colors.CYAN,
    "SYSTEM":   Colors.GREEN,
    "AI":       Colors.MAGENTA + Colors.BOLD,
    "SURICATA": Colors.ORANGE + Colors.BOLD,
    "ZEEK":     Colors.BLUE + Colors.BOLD,
    "FIREWALL": Colors.GREEN,
    "WARNING":  Colors.YELLOW,
    "ERROR":    Colors.RED,
}


def log(msg: str, level: str = "INFO") -> None:
    """Thread-safe logging with colored console output."""
    try:
        ts = datetime.now().strftime("%H:%M:%S")
        color = LEVEL_COLORS.get(level, Colors.ENDC)
        with _log_lock:
            if level not in ["DEBUG", "INFO"]:
                sys.stdout.write(f"\r\033[K[{ts}] [{color}{level}{Colors.ENDC}] {msg}\n")
                sys.stdout.flush()
        _root_logger.info("[%s] %s", level, msg)
    except Exception as e:
        sys.stderr.write(f"Logging error: {e}\n")


# ============================================================================
# ZEEK LOG DISCOVERY
# ============================================================================

_zeek_discovery_attempted = False


def discover_zeek_log():
    """Locate Zeek notice.log, trying common paths then zeekctl config."""
    global _zeek_discovery_attempted
    if _zeek_discovery_attempted:
        return None
    _zeek_discovery_attempted = True

    common_paths = [
        Path("/opt/zeek/logs/current/notice.log"),
        Path("/usr/local/zeek/logs/current/notice.log"),
        Path("/opt/zeek/spool/zeek/notice.log"),
        Path("/var/log/zeek/current/notice.log"),
    ]
    for path in common_paths:
        if path.exists():
            return path

    try:
        result = subprocess.run(['/opt/zeek/bin/zeekctl', 'config'],
                                capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if 'logdir' in line.lower() and '=' in line:
                    log_dir = line.split('=')[1].strip()
                    if log_dir:
                        notice_path = Path(log_dir) / "current" / "notice.log"
                        if notice_path.exists():
                            return notice_path
    except Exception as e:
        log(f"Error discovering Zeek log via zeekctl: {e}", "WARNING")

    try:
        result = subprocess.run(
            ['find', '/opt/zeek', '/usr/local/zeek', '-name', 'notice.log', '-type', 'f'],
            capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            found_path = Path(result.stdout.strip().split('\n')[0])
            if found_path.exists():
                return found_path
    except Exception as e:
        log(f"Error finding Zeek log: {e}", "WARNING")

    return None


# ============================================================================
# SSH UTILITIES
# ============================================================================

# Semaphore limits concurrent SSH connections to avoid pfSense overload.
_ssh_semaphore = threading.Semaphore(2)


def ssh_with_retry(cmd, max_retries=None):
    """Execute SSH command, retrying on timeout."""
    if max_retries is None:
        max_retries = Config.SSH_MAX_RETRIES

    last_error = None
    with _ssh_semaphore:
        for attempt in range(max_retries):
            try:
                return subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=Config.SSH_TIMEOUT, shell=True)
            except subprocess.TimeoutExpired as e:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(1)
                else:
                    log(f'SSH timeout after {max_retries} attempts', 'ERROR')
            except Exception as e:
                last_error = e
                log(f'SSH error on attempt {attempt+1}: {e}', 'ERROR')
                if attempt < max_retries - 1:
                    time.sleep(1)

    raise last_error if last_error else Exception("SSH failed with unknown error")


# ============================================================================
# STATE MANAGEMENT
# ============================================================================

start_time    = time.time()
bridge_proc   = None
suricata_proc = None

blocked_ips_lock = threading.Lock()
blocked_ips = set()

grace_ips_lock = threading.Lock()
grace_ips = {}

# Zeek cooldown: prevents stale log entries from re-blocking a cleared IP.
zeek_cooldown_lock = threading.Lock()
zeek_cooldown_ips = {}   # ip -> unblock timestamp

# Packet cooldown: prevents tcpdump-buffered packets from re-triggering
# fast-scan rules immediately after an IP is cleared.
packet_cooldown_lock = threading.Lock()
packet_cooldown_ips = {}  # ip -> unblock timestamp

stats_lock = threading.Lock()
stats = {
    "blocked": 0, "slow": 0, "fast": 0, "flood": 0, "ddos": 0,
    "brute": 0, "ai_detections": 0, "ai_prevented_fp": 0,
    "web_attacks": 0, "botnet": 0, "exfiltration": 0,
    "suricata_detections": 0, "suricata_suppressed": 0, "suricata_deduped": 0,
    "zeek_detections": 0, "zeek_suppressed": 0, "zeek_deduped": 0,
    "multi_source": 0,
}

port_scan_windows_lock = threading.Lock()
port_scan_windows = defaultdict(lambda: defaultdict(list))

suricata_alert_seen = {}
suricata_dedup_lock = threading.Lock()
suricata_last_cleanup = time.time()

zeek_alert_seen = {}
zeek_dedup_lock = threading.Lock()
zeek_last_cleanup = time.time()


def suricata_is_duplicate(src_ip, signature):
    """Return True if this Suricata alert was already seen within the dedup window."""
    global suricata_last_cleanup
    key = (src_ip, signature)
    now = time.time()

    with suricata_dedup_lock:
        if now - suricata_last_cleanup > Config.DEDUP_CLEANUP_INTERVAL:
            old_keys = [k for k, v in suricata_alert_seen.items()
                        if now - v > Config.DEDUP_MAX_AGE]
            for k in old_keys:
                del suricata_alert_seen[k]
            suricata_last_cleanup = now
            if old_keys:
                log(f"Cleaned {len(old_keys)} old Suricata alerts", "SYSTEM")

        last_seen = suricata_alert_seen.get(key, 0)
        if now - last_seen < Config.SURICATA_DEDUP_WINDOW:
            return True

        suricata_alert_seen[key] = now
        return False


def zeek_is_duplicate(src_ip, notice_type):
    """Return True if this Zeek notice was already seen within the dedup window."""
    global zeek_last_cleanup
    key = (src_ip, notice_type)
    now = time.time()

    with zeek_dedup_lock:
        if now - zeek_last_cleanup > Config.DEDUP_CLEANUP_INTERVAL:
            old_keys = [k for k, v in zeek_alert_seen.items()
                        if now - v > Config.DEDUP_MAX_AGE]
            for k in old_keys:
                del zeek_alert_seen[k]
            zeek_last_cleanup = now
            if old_keys:
                log(f"Cleaned {len(old_keys)} old Zeek alerts", "SYSTEM")

        last_seen = zeek_alert_seen.get(key, 0)
        if now - last_seen < Config.ZEEK_DEDUP_WINDOW:
            return True

        zeek_alert_seen[key] = now
        return False


def zeek_in_cooldown(src_ip):
    """Return True if this IP is within the post-unblock Zeek cooldown period."""
    now = time.time()
    with zeek_cooldown_lock:
        return (now - zeek_cooldown_ips.get(src_ip, 0)) < Config.ZEEK_POST_UNBLOCK_COOLDOWN


def zeek_set_cooldown(src_ip):
    """Record the unblock time for this IP."""
    with zeek_cooldown_lock:
        zeek_cooldown_ips[src_ip] = time.time()


def zeek_cleanup_cooldowns():
    now = time.time()
    with zeek_cooldown_lock:
        expired = [ip for ip, ts in zeek_cooldown_ips.items()
                   if now - ts > Config.ZEEK_POST_UNBLOCK_COOLDOWN * 2]
        for ip in expired:
            del zeek_cooldown_ips[ip]


def packet_in_cooldown(src_ip):
    """Return True if this IP is within the post-unblock packet cooldown period."""
    now = time.time()
    with packet_cooldown_lock:
        return (now - packet_cooldown_ips.get(src_ip, 0)) < Config.PACKET_POST_UNBLOCK_COOLDOWN


def packet_set_cooldown(src_ip):
    """Record the unblock time for this IP at the packet level."""
    with packet_cooldown_lock:
        packet_cooldown_ips[src_ip] = time.time()


def packet_cleanup_cooldowns():
    now = time.time()
    with packet_cooldown_lock:
        expired = [ip for ip, ts in packet_cooldown_ips.items()
                   if now - ts > Config.PACKET_POST_UNBLOCK_COOLDOWN * 2]
        for ip in expired:
            del packet_cooldown_ips[ip]


threat_tracker_lock = threading.Lock()


def _new_tracker():
    """Initialize a fresh threat tracker for an IP."""
    return {
        "sus_ports":              set(),
        "all_ports":              set(),
        "scan_ports":             set(),
        "syn":                    0,
        "packets":                0,
        "bytes":                  0,
        "first":                  time.time(),
        "last":                   time.time(),
        "blocked":                False,
        "packet_times":           deque(maxlen=Config.PACKET_TIMES_MAX),
        "targets":                set(),
        "packet_list":            deque(maxlen=Config.PACKET_LIST_MAX),
        "ai_analyzed":            False,
        "port_packets":           defaultdict(int),
        "http_check_done":        False,
        "slowloris_check_done":   False,
        "first_seen":             time.time(),
        "detection_sources":      set(),
        "last_port_scan_cleanup": time.time(),
    }


threat_tracker = defaultdict(_new_tracker)

flood_tracker_lock = threading.Lock()
flood_tracker = defaultdict(lambda: {"syn": 0, "first": time.time(), "blocked": False})

AI_ENABLED       = False
SURICATA_ENABLED = False
ZEEK_ENABLED     = False
model = scaler = label_encoder = feature_names = None


# ============================================================================
# STARTUP
# ============================================================================

print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.ENDC}")
print(f"{Colors.BOLD}🛡️  AI POWERED CYBERSECURITY LAB{Colors.ENDC}")
print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.ENDC}")

try:
    validate_config()
except Exception as e:
    print(f"{Colors.RED}✗ Configuration: Failed - {e}{Colors.ENDC}")
    sys.exit(1)

try:
    model         = joblib.load(Config.MODEL_DIR / "xgboost_model_comprehensive.pkl")
    scaler        = joblib.load(Config.MODEL_DIR / "scaler_comprehensive.pkl")
    label_encoder = joblib.load(Config.MODEL_DIR / "label_encoder_comprehensive.pkl")
    with open(Config.MODEL_DIR / "feature_names_comprehensive.json") as f:
        feature_names = json.load(f)
    AI_ENABLED = True
    print(f"{Colors.GREEN}✓ XGBoost MODEL: Loaded{Colors.ENDC}")
except Exception as e:
    log(f"XGBoost ML loading failed: {e}", "WARNING")
    print(f"{Colors.YELLOW}⚠ XGBoost MODEL: Offline{Colors.ENDC}")

try:
    result = subprocess.run(['suricata', '--build-info'], capture_output=True, timeout=2)
    SURICATA_ENABLED = result.returncode == 0
    print(f"{Colors.GREEN}✓ Suricata IDS: Ready{Colors.ENDC}" if SURICATA_ENABLED
          else f"{Colors.YELLOW}⚠ Suricata IDS: Not installed{Colors.ENDC}")
except Exception:
    print(f"{Colors.YELLOW}⚠ Suricata IDS: Not installed{Colors.ENDC}")

try:
    result = subprocess.run(['/opt/zeek/bin/zeek', '--version'], capture_output=True, timeout=2)
    if result.returncode == 0:
        discovered_log = discover_zeek_log()
        if discovered_log:
            Config.ZEEK_NOTICE_LOG = discovered_log
            ZEEK_ENABLED = True
            print(f"{Colors.GREEN}✓ Zeek Monitor: Ready{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}⚠ Zeek: Installed but notice.log not found{Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}⚠ Zeek Monitor: Not installed{Colors.ENDC}")
except Exception:
    print(f"{Colors.YELLOW}⚠ Zeek Monitor: Not installed{Colors.ENDC}")

print(f"{Colors.BOLD}{Colors.BLUE}{'='*70}{Colors.ENDC}\n")


# ============================================================================
# MACHINE LEARNING
# ============================================================================

def extract_ml_features(tracker):
    """Extract network flow features for XGBoost classification."""
    duration      = max(time.time() - tracker["first"], 0.001)
    total_packets = max(tracker["packets"], 1)
    total_bytes   = max(tracker["bytes"], 1)

    times = list(tracker["packet_times"])
    if len(times) >= 2:
        intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
        large = [x for x in intervals if x > 10]
        if len(large) >= 2:
            avg_interval = float(np.mean(large))
        else:
            avg_interval = float(np.mean(intervals)) if intervals else duration / max(total_packets - 1, 1)
    else:
        avg_interval = duration / max(total_packets - 1, 1)

    packet_sizes = [p["size"] for p in tracker["packet_list"]]
    max_pkt_size = max(packet_sizes) if packet_sizes else 60

    features = {
        "src_port":                  0,
        "dst_port":                  next(iter(tracker["all_ports"]), 0),
        "protocol":                  6,
        "flow_duration":             duration,
        "total_fwd_packets":         total_packets,
        "total_bwd_packets":         0,
        "total_length_fwd_packets":  total_bytes,
        "total_length_bwd_packets":  0,
        "fwd_packet_length_max":     max_pkt_size,
        "bwd_packet_length_max":     0,
        "flow_bytes_s":              total_bytes / duration,
        "flow_packets_s":            total_packets / duration,
        "flow_iat_mean":             avg_interval,
        "fwd_iat_total":             duration,
        "bwd_iat_total":             0,
        "fwd_psh_flags":             0,
        "bwd_psh_flags":             0,
        "fwd_urg_flags":             0,
        "bwd_urg_flags":             0,
        "syn_flag_count":            tracker["syn"],
        "fin_flag_count":            0,
        "rst_flag_count":            0,
        "psh_flag_count":            0,
        "ack_flag_count":            0,
        "urg_flag_count":            0,
        "down_up_ratio":             0,
        "avg_packet_size":           total_bytes / total_packets,
        "fwd_segment_size_avg":      total_bytes / total_packets,
        "bwd_segment_size_avg":      0,
        "subflow_fwd_packets":       total_packets,
        "subflow_bwd_packets":       0,
    }
    return features, avg_interval


def ai_classify_threat(ip, tracker, is_botnet_pattern=False):
    """Classify traffic using the XGBoost model; returns (attack_type, confidence)."""
    if not AI_ENABLED:
        return None, 0.0

    try:
        features, avg_interval = extract_ml_features(tracker)
        df       = pd.DataFrame([features])[feature_names]
        X_scaled = scaler.transform(df)

        pred        = model.predict(X_scaled)[0]
        probs       = model.predict_proba(X_scaled)[0]
        attack_type = label_encoder.inverse_transform([pred])[0]
        confidence  = float(probs[pred]) * 100

        top3_idx = np.argsort(probs)[-3:][::-1]
        top3_cls = label_encoder.inverse_transform(top3_idx)
        top3_prob = probs[top3_idx] * 100
        duration  = time.time() - tracker["first"]

        # Reclassify slow periodic PortScan as Botnet beacon if timing matches.
        if is_botnet_pattern and attack_type == "PortScan":
            times     = list(tracker["packet_times"])
            intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
            large     = [x for x in intervals if x > 10]
            if len(large) >= 2:
                avg = float(np.mean(large))
                std = float(np.std(large))
                if 30 <= avg <= 120 and std < 20:
                    attack_type = "Botnet"
                    confidence  = 99.0
                    log(f"🧠 AI [{ip}] → {attack_type} ({confidence:.1f}%) [beacon {avg:.1f}s]", "AI")
                    log(f"   ports={len(tracker['sus_ports'])} pkts={tracker['packets']} "
                        f"bytes={tracker['bytes']:,} dur={duration:.0f}s itvl={avg_interval:.1f}s", "AI")
                    tracker["detection_sources"].add("ML")
                    return attack_type, confidence

        display_confidence = 99.0 if attack_type == "PortScan" else confidence
        log(f"🧠 AI [{ip}] → {attack_type} ({display_confidence:.1f}%)", "AI")
        log(f"   ports={len(tracker['sus_ports'])} pkts={tracker['packets']} "
            f"bytes={tracker['bytes']:,} dur={duration:.0f}s itvl={avg_interval:.1f}s", "AI")
        if top3_cls[0] != "PortScan":
            log(f"   Top3: {top3_cls[0]}({top3_prob[0]:.1f}%) "
                f"{top3_cls[1]}({top3_prob[1]:.1f}%) "
                f"{top3_cls[2]}({top3_prob[2]:.1f}%)", "AI")

        tracker["detection_sources"].add("ML")

        if attack_type == "BENIGN" and confidence > 90:
            with stats_lock:
                stats["ai_prevented_fp"] += 1

        return (attack_type, confidence) if attack_type != "BENIGN" else ("BENIGN", confidence)

    except Exception as exc:
        log(f"AI error for {ip}: {exc}", "ERROR")
        log(traceback.format_exc(), "DEBUG")
        return None, 0.0


# ============================================================================
# HELPERS
# ============================================================================

def is_valid_ip(ip):
    if not ip:
        return False
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False


def is_whitelisted(ip):
    if not is_valid_ip(ip):
        return True
    if ip in Config.WHITELIST_IPS:
        return True
    return any(ip.startswith(pre) for pre in Config.WHITELIST_PREFIXES)


def get_target_name(dst_ip):
    if not dst_ip:
        return "Unknown"
    for prefix, name in Config.PROTECTED_NETWORKS.items():
        if dst_ip.startswith(prefix):
            return f"{dst_ip} ({name})"
    return dst_ip


# ============================================================================
# FIREWALL BLOCKING
# ============================================================================

def block_ip(ip, reason, conf=0.0, method="Rule"):
    """Block an IP via pfSense pfctl and update internal state."""
    if not is_valid_ip(ip):
        log(f"Invalid IP format, skipping: {ip}", "WARNING")
        return

    with blocked_ips_lock:
        if ip in blocked_ips or is_whitelisted(ip):
            return
        blocked_ips.add(ip)

    with stats_lock:
        stats["blocked"] += 1

        if "AI" in method or "XGBoost" in method or "ML" in method:
            stats["ai_detections"] += 1
        elif "Zeek" in method:
            stats["zeek_detections"] += 1
        elif "Suricata" in method:
            stats["suricata_detections"] += 1

        with threat_tracker_lock:
            if ip in threat_tracker and len(threat_tracker[ip]["detection_sources"]) > 1:
                stats["multi_source"] += 1
                sources = ', '.join(threat_tracker[ip]["detection_sources"])
                log(f"🎯 Multi-layer: {sources}", "SYSTEM")

        reason_lower = reason.lower()
        if "scan" in reason_lower or "portscan" in reason_lower:
            stats["fast"] += 1
        elif "flood" in reason_lower:
            stats["flood"] += 1
        elif "brute" in reason_lower:
            stats["brute"] += 1
        elif "ddos" in reason_lower:
            stats["ddos"] += 1
        elif "slowloris" in reason_lower or "web" in reason_lower:
            stats["web_attacks"] += 1
        elif "botnet" in reason_lower:
            stats["botnet"] += 1
        elif "exfil" in reason_lower or "data" in reason_lower:
            stats["exfiltration"] += 1

    conf_str   = f" ({conf:.0f}%)" if conf > 0 else ""
    method_str = "" if method in ("Rule", "XGBoost ML") else f" [{method}]"
    log(f"🚨 BLOCKED: {ip} | {reason}{conf_str}{method_str}", "BLOCK")

    def _do_block():
        try:
            cmd = (f"sshpass -p '{Config.PFSENSE_PASS}' ssh -o StrictHostKeyChecking=no "
                   f"{Config.PFSENSE_USER}@{Config.PFSENSE_IP} "
                   f"'pfctl -t EasyRuleBlockHostsWAN -T add {ip}'")
            result = ssh_with_retry(cmd)
            if result and result.returncode == 0:
                log(f"✓ Firewall: {ip}", "FIREWALL")
            else:
                log(f"Firewall block failed for {ip}", "ERROR")
        except Exception as exc:
            log(f"Block error for {ip}: {exc}", "ERROR")

    threading.Thread(target=_do_block, daemon=True).start()


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

def sync_firewall_state():
    """Periodically sync blocked IPs with pfSense and handle external removals."""
    backoff = Config.FW_SYNC_INTERVAL

    while True:
        try:
            cmd = (f"sshpass -p '{Config.PFSENSE_PASS}' ssh -o StrictHostKeyChecking=no "
                   f"{Config.PFSENSE_USER}@{Config.PFSENSE_IP} "
                   f"'pfctl -t EasyRuleBlockHostsWAN -T show'")
            result = ssh_with_retry(cmd)

            if result and result.returncode == 0:
                current = {ln.strip() for ln in result.stdout.splitlines() if ln.strip()}

                with blocked_ips_lock:
                    with grace_ips_lock:
                        removed = blocked_ips - current
                        for ip in removed:
                            if ip in grace_ips:
                                continue

                            with threat_tracker_lock:
                                threat_tracker.pop(ip, None)
                            with flood_tracker_lock:
                                flood_tracker.pop(ip, None)
                            with port_scan_windows_lock:
                                port_scan_windows.pop(ip, None)

                            # Arm both cooldowns so buffered data cannot immediately re-block.
                            zeek_set_cooldown(ip)
                            packet_set_cooldown(ip)

                            # Reset Zeek dedup so cooldown is the sole gatekeeper.
                            with zeek_dedup_lock:
                                for k in [k for k in zeek_alert_seen if k[0] == ip]:
                                    del zeek_alert_seen[k]

                            log(f"♻️  {ip} cleared - ready for new analysis", "SYSTEM")

                        blocked_ips.intersection_update(current)

                backoff = Config.FW_SYNC_INTERVAL
            else:
                log("Firewall sync failed, increasing backoff", "WARNING")
                backoff = min(backoff * 2, 60)

        except Exception as e:
            log(f"Firewall sync error: {e}", "ERROR")
            backoff = min(backoff * 2, 60)

        time.sleep(backoff)


def cleanup_old_trackers():
    """Remove stale trackers and expired cooldown entries to prevent memory growth."""
    while True:
        try:
            time.sleep(300)
            now    = time.time()
            cutoff = now - (Config.ANALYSIS_WINDOW * 2)

            with blocked_ips_lock:
                blocked_copy = blocked_ips.copy()

            old_ips = []
            with threat_tracker_lock:
                for ip, tracker in list(threat_tracker.items()):
                    if now - tracker['last'] > cutoff and ip not in blocked_copy:
                        old_ips.append(ip)

            if old_ips:
                with threat_tracker_lock:
                    for ip in old_ips:
                        threat_tracker.pop(ip, None)
                with flood_tracker_lock:
                    for ip in old_ips:
                        flood_tracker.pop(ip, None)
                with port_scan_windows_lock:
                    for ip in old_ips:
                        port_scan_windows.pop(ip, None)

                log(f'Cleaned {len(old_ips)} stale trackers', 'SYSTEM')

            zeek_cleanup_cooldowns()
            packet_cleanup_cooldowns()

        except Exception as e:
            log(f"Cleanup error: {e}", "ERROR")
            log(traceback.format_exc(), "DEBUG")


# ============================================================================
# SURICATA IDS MONITORING
# ============================================================================

def monitor_suricata_alerts():
    """Tail Suricata eve.json and act on high-severity alerts."""
    if not SURICATA_ENABLED:
        return

    log("Suricata IDS started", "SURICATA")

    wait_count = 0
    while not Config.SURICATA_EVE_LOG.exists():
        if wait_count % 10 == 0:
            log(f"Waiting for Suricata log: {Config.SURICATA_EVE_LOG}", "SYSTEM")
        time.sleep(1)
        wait_count += 1
        if wait_count > 60:
            log("Suricata log not found after 60s", "WARNING")
            return

    try:
        proc = subprocess.Popen(['tail', '-f', '-n', '0', str(Config.SURICATA_EVE_LOG)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

        for line in proc.stdout:
            try:
                event = json.loads(line.strip())
                if event.get('event_type') != 'alert':
                    continue

                src_ip    = event.get('src_ip')
                signature = event.get('alert', {}).get('signature', 'Unknown')
                severity  = event.get('alert', {}).get('severity', 3)

                if not src_ip or is_whitelisted(src_ip):
                    continue

                # Suppress DDOS SYN alerts when the source is already tracked as a port scanner.
                if 'DDOS' in signature and 'SYN' in signature:
                    with threat_tracker_lock:
                        if src_ip in threat_tracker and len(threat_tracker[src_ip]['sus_ports']) >= 3:
                            with stats_lock:
                                stats['suricata_suppressed'] += 1
                            continue

                if any(pat in signature for pat in Config.SURICATA_NOISE):
                    with stats_lock:
                        stats['suricata_suppressed'] += 1
                    continue

                if suricata_is_duplicate(src_ip, signature):
                    with stats_lock:
                        stats['suricata_deduped'] += 1
                    continue

                with blocked_ips_lock:
                    already_blocked = src_ip in blocked_ips

                if already_blocked:
                    with threat_tracker_lock:
                        if src_ip in threat_tracker:
                            tr = threat_tracker[src_ip]
                            if 'suricata_confirmed' not in tr:
                                log(f"🔍 {src_ip} | {signature[:60]}", "SURICATA")
                                log(f"   ✓ Suricata confirmed (already blocked)", "SURICATA")
                                tr['suricata_confirmed'] = True
                                tr['detection_sources'].add('Suricata')
                                with stats_lock:
                                    stats['suricata_detections'] += 1
                                    if len(tr['detection_sources']) > 1 and 'suricata_multi_counted' not in tr:
                                        stats['multi_source'] += 1
                                        tr['suricata_multi_counted'] = True
                                        log(f"🎯 Multi-layer: {', '.join(tr['detection_sources'])}", "SYSTEM")
                    continue

                with threat_tracker_lock:
                    if src_ip in threat_tracker:
                        tr = threat_tracker[src_ip]
                        in_analysis = (time.time() - tr['first_seen']) < Config.ANALYSIS_WINDOW
                        if in_analysis and not tr['blocked']:
                            log(f"🔍 {src_ip} | {signature[:60]} [analysis window]", "SURICATA")
                            tr['detection_sources'].add('Suricata')
                            if 'suricata_counted' not in tr:
                                tr['suricata_counted'] = True
                                with stats_lock:
                                    stats['suricata_detections'] += 1
                            else:
                                with stats_lock:
                                    stats['suricata_suppressed'] += 1
                            continue

                log(f"🔍 {src_ip} | {signature[:60]}", "SURICATA")

                with threat_tracker_lock:
                    if src_ip in threat_tracker and 'suricata_counted' not in threat_tracker[src_ip]:
                        threat_tracker[src_ip]['detection_sources'].add('Suricata')
                        threat_tracker[src_ip]['suricata_counted'] = True

                if severity <= 2:
                    attack_type = signature.split()[0] if ' ' in signature else 'Attack'
                    with stats_lock:
                        stats['suricata_detections'] += 1
                    block_ip(src_ip, f"Suricata: {attack_type}", 95, "Suricata IDS")

            except json.JSONDecodeError:
                continue
            except Exception as e:
                log(f"Suricata event error: {e}", "WARNING")

    except Exception as e:
        log(f"Suricata monitoring failed: {e}", "ERROR")
        log(traceback.format_exc(), "DEBUG")


# ============================================================================
# ZEEK NETWORK MONITOR
# ============================================================================

def monitor_zeek_notices():
    """Tail Zeek notice.log and block on confirmed threat notices."""
    global ZEEK_ENABLED

    log("Zeek Monitor started", "ZEEK")

    waited = 0
    while waited < 60:
        try:
            if not Config.ZEEK_NOTICE_LOG or not Config.ZEEK_NOTICE_LOG.exists():
                discovered = discover_zeek_log()
                if discovered and discovered.exists():
                    Config.ZEEK_NOTICE_LOG = discovered
                    ZEEK_ENABLED = True
                    break
            else:
                break
        except Exception as e:
            log(f"Zeek discovery error: {e}", "WARNING")
        time.sleep(2)
        waited += 2

    if not Config.ZEEK_NOTICE_LOG or not Config.ZEEK_NOTICE_LOG.exists():
        log("Zeek notice.log not found - monitoring disabled", "WARNING")
        return

    try:
        proc = subprocess.Popen(['tail', '-F', str(Config.ZEEK_NOTICE_LOG)],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                text=True, bufsize=1)

        for line in proc.stdout:
            try:
                if line.startswith('#') or not line.strip():
                    continue

                if line.startswith('{'):
                    try:
                        event  = json.loads(line)
                        src_ip = event.get('src')
                        note   = event.get('note', '')
                        msg    = event.get('msg', '')
                    except Exception:
                        continue
                else:
                    parts  = line.strip().split('\t')
                    if len(parts) < 9:
                        continue
                    src_ip = parts[2] if len(parts) > 2 and parts[2] != '-' else None
                    note   = parts[8] if len(parts) > 8 else ''
                    msg    = parts[9] if len(parts) > 9 else ''

                if not src_ip or is_whitelisted(src_ip):
                    continue

                if any(pat in note for pat in Config.ZEEK_NOISE):
                    with stats_lock:
                        stats['zeek_suppressed'] += 1
                    continue

                attack_type = (note
                               .replace('AIDefense::', '')
                               .replace('_Detected', '')
                               .replace('Notice::', '')
                               .replace('_', ' '))

                # Skip Port_Scan notices for single-port or SYN-heavy traffic
                # (those are better handled by Suricata / rule engine).
                if 'Port_Scan' in note or 'Port Scan' in attack_type:
                    with threat_tracker_lock:
                        if src_ip in threat_tracker:
                            tr = threat_tracker[src_ip]
                            if len(tr['sus_ports']) <= 2 or tr['syn'] / max(tr['packets'], 1) > 0.7:
                                with stats_lock:
                                    stats['zeek_suppressed'] += 1
                                continue

                if zeek_is_duplicate(src_ip, attack_type):
                    with stats_lock:
                        stats['zeek_deduped'] += 1
                    continue

                is_action_notice = any(kw in note for kw in
                                       ['AIDefense::', 'Port_Scan', 'SSH_Bruteforce',
                                        'SYN_Flood', 'High_Connection_Rate'])
                if not is_action_notice:
                    continue

                with blocked_ips_lock:
                    already_blocked = src_ip in blocked_ips

                if already_blocked:
                    with threat_tracker_lock:
                        if src_ip in threat_tracker and 'zeek_confirmed' not in threat_tracker[src_ip]:
                            log(f"👁️  {src_ip} | {attack_type[:60]}", "ZEEK")
                            log(f"   ✓ Zeek confirmed (already blocked)", "ZEEK")
                            tr = threat_tracker[src_ip]
                            tr['zeek_confirmed'] = True
                            if 'Zeek' not in tr['detection_sources']:
                                tr['detection_sources'].add('Zeek')
                                with stats_lock:
                                    stats['zeek_detections'] += 1
                                    if len(tr['detection_sources']) > 1 and 'multi_counted' not in tr:
                                        stats["multi_source"] += 1
                                        tr['multi_counted'] = True
                                        log(f"🎯 Multi-layer: {', '.join(tr['detection_sources'])}", "SYSTEM")
                    continue

                if zeek_in_cooldown(src_ip):
                    with stats_lock:
                        stats['zeek_suppressed'] += 1
                    continue

                with threat_tracker_lock:
                    if src_ip in threat_tracker:
                        if (time.time() - threat_tracker[src_ip]['first_seen']) < Config.ANALYSIS_WINDOW:
                            log(f"👁️  {src_ip} | {attack_type[:60]} [analysis window]", "ZEEK")
                            threat_tracker[src_ip]['detection_sources'].add('Zeek')
                            with stats_lock:
                                stats['zeek_suppressed'] += 1
                            continue

                log(f"👁️  {src_ip} | {attack_type[:60]}", "ZEEK")
                log(f"   🚨 New detection - blocking", "ZEEK")

                with threat_tracker_lock:
                    if src_ip in threat_tracker:
                        threat_tracker[src_ip]['detection_sources'].add('Zeek')

                block_ip(src_ip, f"Zeek: {attack_type}", 95, "Zeek Monitor")

            except Exception as e:
                log(f"Zeek line parse error: {e}", "WARNING")

    except Exception as e:
        log(f"Zeek monitoring failed: {e}", "ERROR")
        log(traceback.format_exc(), "DEBUG")


# ============================================================================
# ATTACK DETECTION
# ============================================================================

def fast_flood_check(ip):
    """Detect SYN floods: blocks if SYN count exceeds threshold within 5 seconds."""
    with blocked_ips_lock:
        if ip in blocked_ips:
            return

    with flood_tracker_lock:
        tracker = flood_tracker[ip]
        now = time.time()

        if now - tracker["first"] > 5:
            tracker["syn"]     = 1
            tracker["first"]   = now
            tracker["blocked"] = False
            return

        tracker["syn"] += 1
        if tracker["syn"] > Config.SYN_FLOOD_THRESHOLD and not tracker["blocked"]:
            log(f"⚡ SYN FLOOD: {ip} ({tracker['syn']} pkts/5s)", "ATTACK")
            block_ip(ip, "SYN Flood", 99.0, "Fast Detection")
            tracker["blocked"] = True


def detect_pattern_type(tracker):
    """Detect periodic botnet beacon patterns in packet timing."""
    times = list(tracker["packet_times"])
    if len(times) < 4:
        return None

    intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
    large     = [x for x in intervals if x > 10]

    if len(large) >= 2:
        avg = float(np.mean(large))
        std = float(np.std(large))
        if 30 <= avg <= 120 and std < 20:
            return "BOTNET_BEACON"

    return None


def analyze_threat(ip, tr):
    """Run rule-based and ML-based threat analysis on the current tracker state."""
    if tr["blocked"]:
        return

    sus_count = len(tr["sus_ports"])
    if sus_count == 0:
        return

    now      = time.time()
    duration = now - tr["first"]

    # During the post-unblock packet cooldown, buffered tcpdump packets give
    # the tracker a very short duration with multiple ports, which looks like
    # a fast scan. Suppress detection until the cooldown expires.
    if packet_in_cooldown(ip):
        return

    # --- Priority 1: Fast port scans ---
    if sus_count >= 10 and duration <= 10:
        scan_rate = sus_count / max(duration, 0.1)
        log(f"🔍 FAST SCAN: {ip} ({sus_count} ports in {duration:.1f}s | {scan_rate:.1f} ports/s)", "ATTACK")
        block_ip(ip, f"Fast Port Scan ({sus_count} ports)", 99.0, "Rule")
        tr["blocked"] = True
        return
    elif sus_count >= 5 and duration <= 5:
        scan_rate = sus_count / max(duration, 0.1)
        log(f"🔍 FAST SCAN: {ip} ({sus_count} ports in {duration:.1f}s | {scan_rate:.1f} ports/s)", "ATTACK")
        block_ip(ip, f"Fast Port Scan ({sus_count} ports)", 99.0, "Rule")
        tr["blocked"] = True
        return
    elif sus_count >= 3 and duration <= 2:
        scan_rate = sus_count / max(duration, 0.1)
        log(f"🔍 FAST SCAN: {ip} ({sus_count} ports in {duration:.1f}s | {scan_rate:.1f} ports/s)", "ATTACK")
        block_ip(ip, f"Fast Port Scan ({sus_count} ports)", 99.0, "Rule")
        tr["blocked"] = True
        return

    # --- Priority 2: Brute force ---
    for port, service in ((22, "SSH"), (3389, "RDP")):
        if tr["port_packets"][port] >= Config.BRUTE_FORCE_LIMIT:
            log(f"🔐 {service} BRUTE FORCE: {ip} ({tr['port_packets'][port]} attempts)", "ATTACK")
            block_ip(ip, f"{service} Brute Force", 99.0, "Rule")
            tr["blocked"] = True
            return

    http_pkts = tr["port_packets"].get(80, 0) + tr["port_packets"].get(443, 0)

    # --- Priority 3: Slowloris DoS ---
    if http_pkts >= 20 and duration >= 5 and not tr["slowloris_check_done"]:
        tr["slowloris_check_done"] = True
        pkt_rate       = tr["packets"] / max(duration, 0.1)
        syn_ratio      = tr["syn"] / max(tr["packets"], 1)
        num_connections = tr["syn"]
        avg_pkt_size   = tr["bytes"] / max(tr["packets"], 1)

        if num_connections >= 30 and pkt_rate < 8 and avg_pkt_size < 150 and syn_ratio > 0.6:
            log(f"🐌 SLOWLORIS: {ip} | {num_connections} conn | {pkt_rate:.1f} pkt/s", "ATTACK")
            block_ip(ip, "Slowloris DoS", 99.0, "Rule")
            tr["blocked"] = True
            return

    # --- Priority 4: HTTP attacks (DDoS / exfiltration / web attack) ---
    if http_pkts >= 50 and duration >= 2.0 and not tr["http_check_done"]:
        tr["http_check_done"] = True
        pkt_rate        = tr["packets"] / max(duration, 0.1)
        syn_ratio       = tr["syn"] / max(tr["packets"], 1)
        num_connections = tr["syn"]
        avg_pkt_size    = tr["bytes"] / max(tr["packets"], 1)

        if syn_ratio > 0.85 and pkt_rate > 100:
            log(f"💥 HTTP DDoS: {ip} | {http_pkts} pkts | {pkt_rate:.0f} pkt/s", "ATTACK")
            block_ip(ip, "HTTP DDoS", 99.0, "Rule")
            tr["blocked"] = True
            return
        elif num_connections >= 30 and duration >= 5 and pkt_rate < 100 and avg_pkt_size > 500:
            log(f"📤 DATA EXFIL: {ip} | {num_connections} uploads", "ATTACK")
            block_ip(ip, "Data Exfiltration", 98.0, "Rule")
            tr["blocked"] = True
            return
        else:
            log(f"🌐 WEB ATTACK: {ip} | {http_pkts} requests in {duration:.1f}s", "ATTACK")
            block_ip(ip, "Web Attack", 98.0, "Rule")
            tr["blocked"] = True
            return

    # --- Priority 5: ML classification ---
    pattern          = detect_pattern_type(tr)
    should_trigger_ai = False

    if not tr["ai_analyzed"]:
        is_http_only = ((80 in tr["all_ports"] or 443 in tr["all_ports"]) and sus_count == 1)

        if pattern == "BOTNET_BEACON":
            if duration >= Config.BOTNET_MIN_DURATION and tr["packets"] >= Config.BOTNET_MIN_PACKETS:
                should_trigger_ai = True
                log(f"⚙️  AI trigger [{ip}]: Botnet pattern", "AI")
        elif sus_count >= Config.FAST_SCAN_THRESHOLD:
            should_trigger_ai = True
            log(f"⚙️  AI trigger [{ip}]: Fast multi-port ({sus_count} ports)", "AI")
        elif sus_count >= Config.AI_TRIGGER_ON_PORTS and tr["packets"] >= Config.AI_MIN_PACKETS:
            if sus_count == 2 and duration < Config.BOTNET_MIN_DURATION and not is_http_only:
                return
            should_trigger_ai = True
            log(f"⚙️  AI trigger [{ip}]: Multi-port ({sus_count} ports)", "AI")
        elif tr["packets"] >= 30 and not is_http_only:
            should_trigger_ai = True
            log(f"⚙️  AI trigger [{ip}]: High volume ({tr['packets']} pkts)", "AI")

    if should_trigger_ai:
        tr["ai_analyzed"] = True
        attack_type, confidence = ai_classify_threat(
            ip, tr, is_botnet_pattern=(pattern == "BOTNET_BEACON"))

        min_conf = (50.0 if attack_type and ("Port" in attack_type or "Scan" in attack_type)
                    else Config.AI_CONFIDENCE_THRESHOLD)

        if attack_type and attack_type not in ("BENIGN", None) and confidence >= min_conf:
            if attack_type == "PortScan":
                confidence = 99.0
            log(f"🤖 AI DETECTED: {ip} = {attack_type} ({confidence:.1f}%)", "AI")
            block_ip(ip, f"AI: {attack_type}", confidence, "XGBoost ML")
            tr["blocked"] = True
            return

    # --- Fallback rule-based scan detection ---
    if not tr["ai_analyzed"] and sus_count >= Config.FAST_SCAN_THRESHOLD:
        log(f"🔍 FAST SCAN (rule): {ip} ({sus_count} ports)", "ATTACK")
        block_ip(ip, f"Fast Scan ({sus_count} ports)", 95.0, "Rule")
        tr["blocked"] = True


# ============================================================================
# PACKET PROCESSING
# ============================================================================

def process_packet(src_ip, dst_ip, dst_port, has_syn, packet_size=60):
    """Update threat tracker and trigger analysis for each observed packet."""
    if not src_ip or not is_valid_ip(src_ip):
        return
    if is_whitelisted(src_ip):
        return
    if not src_ip.startswith("192.168.180."):
        return

    with blocked_ips_lock:
        if src_ip in blocked_ips:
            return

    if dst_port < 0 or dst_port > 65535:
        return

    if has_syn:
        fast_flood_check(src_ip)

    with threat_tracker_lock:
        tr = threat_tracker[src_ip]

    now = time.time()
    tr["packet_times"].append(now)
    tr["packet_list"].append({"size": packet_size, "time": now})
    tr["last"]    = now
    tr["packets"] += 1
    tr["bytes"]   += packet_size

    if has_syn:
        tr["syn"] += 1

    if dst_ip and is_valid_ip(dst_ip):
        for prefix in Config.PROTECTED_NETWORKS:
            if dst_ip.startswith(prefix) and dst_ip not in tr["targets"]:
                tr["targets"].add(dst_ip)
                log(f"🎯 {src_ip} → {get_target_name(dst_ip)}", "TARGET")
                break

    if dst_port > 0:
        tr["port_packets"][dst_port] += 1

        with port_scan_windows_lock:
            port_scan_windows[src_ip][dst_port].append(now)

            if now - tr["last_port_scan_cleanup"] > 30:
                for port in list(port_scan_windows[src_ip].keys()):
                    port_scan_windows[src_ip][port] = [
                        t for t in port_scan_windows[src_ip][port]
                        if now - t < Config.PORT_SCAN_WINDOW
                    ]
                tr["last_port_scan_cleanup"] = now

        if dst_port not in tr["all_ports"]:
            tr["all_ports"].add(dst_port)

            if dst_port not in Config.LEGITIMATE_PORTS:
                tr["sus_ports"].add(dst_port)

                with port_scan_windows_lock:
                    port_count   = len([t for t in port_scan_windows[src_ip][dst_port]
                                        if now - t < Config.PORT_SCAN_WINDOW])
                    recent_ports = len([p for p in port_scan_windows[src_ip]
                                        if any(now - t < Config.PORT_SCAN_WINDOW
                                               for t in port_scan_windows[src_ip][p])])

                is_scan = (port_count >= 2) or (recent_ports >= 2)
                if is_scan and dst_port not in {80, 443}:
                    tr["scan_ports"].add(dst_port)

                    duration    = now - tr["first"]
                    sus_count   = len(tr["sus_ports"])
                    is_fast_scan = sus_count >= 3 and duration <= 10

                    if not is_fast_scan and not packet_in_cooldown(src_ip):
                        log(f"📍 {src_ip} → port {dst_port} "
                            f"(sus={len(tr['sus_ports'])}, pkts={tr['packets']})", "ATTACK")

    analyze_threat(src_ip, tr)


_PKT_RE   = re.compile(r"(?:IP\s+)?(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)\s+>\s+(\d{1,3}(?:\.\d{1,3}){3})\.(\d+)")
_FLAGS_RE = re.compile(r"Flags \[([^\]]+)\]")
_LEN_RE   = re.compile(r"\blength (\d+)")


def parse_tcpdump_line(line):
    """Parse a single tcpdump output line and forward to process_packet."""
    m = _PKT_RE.search(line)
    if not m:
        return

    src_ip, src_port_s, dst_ip, dst_port_s = m.groups()

    try:
        dst_port = int(dst_port_s)
    except ValueError:
        return

    flags_match = _FLAGS_RE.search(line)
    flags       = flags_match.group(1) if flags_match else ""
    has_syn     = "S" in flags and "." not in flags

    packet_size = 60
    len_match   = _LEN_RE.search(line)
    if len_match:
        try:
            packet_size = max(0, min(65535, int(len_match.group(1))))
        except ValueError:
            pass

    process_packet(src_ip, dst_ip, dst_port, has_syn, packet_size)


# ============================================================================
# SHUTDOWN & SUMMARY
# ============================================================================

def shutdown_report(signum, frame):
    """Print session summary and exit cleanly."""
    runtime = time.time() - start_time
    sep     = "=" * 70

    print(f"\n\n{Colors.PURPLE}{Colors.BOLD}{sep}{Colors.ENDC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}📊 AI POWERED CYBERSECURITY LAB SUMMARY{Colors.ENDC}")
    print(f"{Colors.PURPLE}{Colors.BOLD}{sep}{Colors.ENDC}")
    print(f"⏱️  Runtime      : {runtime:.2f}s")

    with stats_lock:
        print(f"🛡️  Blocked      : {Colors.RED}{Colors.BOLD}{stats['blocked']}{Colors.ENDC}")
        print("-" * 40)

        ml_status  = f"{Colors.GREEN}✓{Colors.ENDC}" if AI_ENABLED       else f"{Colors.RED}✗{Colors.ENDC}"
        sur_status = f"{Colors.GREEN}✓{Colors.ENDC}" if SURICATA_ENABLED else f"{Colors.RED}✗{Colors.ENDC}"
        zeek_status= f"{Colors.GREEN}✓{Colors.ENDC}" if ZEEK_ENABLED     else f"{Colors.RED}✗{Colors.ENDC}"

        print(f"{Colors.MAGENTA}🤖 ML Detections [{ml_status}]:{Colors.ENDC}    {stats['ai_detections']}")
        print(f"{Colors.ORANGE}🔍 Suricata IDS [{sur_status}]:{Colors.ENDC}   {stats['suricata_detections']}")
        print(f"{Colors.BLUE}👁️  Zeek Monitor [{zeek_status}]:{Colors.ENDC}  {stats['zeek_detections']}")

        multi_color = Colors.GREEN + Colors.BOLD if stats['multi_source'] > 0 else Colors.GREEN
        print(f"{multi_color}🎯 Multi-layer:{Colors.ENDC}       {stats['multi_source']}")
        print("-" * 40)

        def fmt(label, value, emoji):
            color = Colors.YELLOW if value > 0 else ""
            return f"{emoji} {label:15} : {color}{value}{Colors.ENDC if color else ''}"

        print(fmt("Port Scans",  stats['fast'],         "🔍"))
        print(fmt("Brute Force", stats['brute'],        "🔨"))
        print(fmt("SYN Floods",  stats['flood'],        "🌊"))
        print(fmt("Web Attacks", stats['web_attacks'],  "🌐"))
        print(fmt("Botnet",      stats['botnet'],       "🤖"))
        print(fmt("Data Exfil",  stats['exfiltration'], "📤"))

        print(f"{Colors.PURPLE}{Colors.BOLD}{sep}{Colors.ENDC}")

        total_attacks = (stats['fast'] + stats['brute'] + stats['flood'] +
                         stats['ddos'] + stats['web_attacks'] + stats['botnet'] +
                         stats['exfiltration'])
        if total_attacks > 0:
            rate = stats['blocked'] / total_attacks * 100
            print(f"{Colors.BOLD}Detection Rate: {Colors.GREEN}{rate:.1f}%{Colors.ENDC} "
                  f"({stats['blocked']}/{total_attacks} attacks blocked)")

        active_layers = sum([AI_ENABLED, SURICATA_ENABLED, ZEEK_ENABLED])
        if active_layers > 0:
            print(f"{Colors.BOLD}Defense Layers: {Colors.CYAN}{active_layers}/3{Colors.ENDC} active")
            detections = []
            if stats['ai_detections']:      detections.append(f"ML:{stats['ai_detections']}")
            if stats['suricata_detections']:detections.append(f"Suricata:{stats['suricata_detections']}")
            if stats['zeek_detections']:    detections.append(f"Zeek:{stats['zeek_detections']}")
            label = ' | '.join(detections) if detections else "(none recorded)"
            print(f"{Colors.BOLD}Detections by Layer:{Colors.ENDC} {label}")

    print(f"{Colors.PURPLE}{Colors.BOLD}{sep}{Colors.ENDC}\n")

    if bridge_proc:
        bridge_proc.terminate()
    if suricata_proc:
        subprocess.run(['sudo', 'killall', 'suricata'], capture_output=True)

    sys.exit(0)


# ============================================================================
# MAIN
# ============================================================================

def main():
    global bridge_proc, suricata_proc

    signal.signal(signal.SIGINT,  shutdown_report)
    signal.signal(signal.SIGTERM, shutdown_report)

    threading.Thread(target=sync_firewall_state,  daemon=True).start()
    threading.Thread(target=monitor_zeek_notices, daemon=True).start()
    threading.Thread(target=cleanup_old_trackers, daemon=True).start()

    if SURICATA_ENABLED:
        threading.Thread(target=monitor_suricata_alerts, daemon=True).start()
        try:
            subprocess.run(['sudo', 'killall', 'suricata'], capture_output=True)
            time.sleep(2)
            devnull = open(os.devnull, 'w')
            suricata_proc = subprocess.Popen(
                ['sudo', 'suricata', '-c', '/etc/suricata/suricata.yaml', '-i', Config.LOCAL_IF],
                stdout=devnull, stderr=devnull)
            time.sleep(3)
        except Exception as e:
            log(f"Suricata start failed: {e}", "ERROR")
            log(traceback.format_exc(), "DEBUG")

    if Path('/opt/zeek/bin/zeekctl').exists():
        try:
            subprocess.run(['sudo', '/opt/zeek/bin/zeekctl', 'stop'],   capture_output=True)
            time.sleep(2)
            subprocess.run(['sudo', '/opt/zeek/bin/zeekctl', 'deploy'], capture_output=True, timeout=10)
            time.sleep(3)
        except Exception as e:
            log(f"Zeek deploy failed: {e}", "ERROR")
            log(traceback.format_exc(), "DEBUG")

    bridge_cmd = (
        f"sshpass -p '{Config.PFSENSE_PASS}' "
        f"ssh -o StrictHostKeyChecking=no "
        f"{Config.PFSENSE_USER}@{Config.PFSENSE_IP} "
        f"\"tcpdump -i {Config.PFSENSE_WAN_IF} -U -w - "
        f"'not (src host {Config.PFSENSE_IP} and port 22)'\" "
        f"| tcpreplay -i {Config.LOCAL_IF} --topspeed -"
    )
    bridge_proc = subprocess.Popen(bridge_cmd, shell=True, stderr=subprocess.DEVNULL)

    layers_active = sum([AI_ENABLED, SURICATA_ENABLED, ZEEK_ENABLED])
    log(f"🛡️  {layers_active}-layer defense ACTIVE", "SYSTEM")
    log(f"ML {'✓' if AI_ENABLED else '✗'} | Suricata {'✓' if SURICATA_ENABLED else '✗'} | Zeek {'✓' if ZEEK_ENABLED else '✗'}", "SYSTEM")

    proc = subprocess.Popen(
        ["tcpdump", "-i", Config.LOCAL_IF, "-n", "-l"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        for line in proc.stdout:
            try:
                parse_tcpdump_line(line)
            except Exception as e:
                log(f"Packet parse error: {e}", "WARNING")
    except KeyboardInterrupt:
        shutdown_report(None, None)
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()