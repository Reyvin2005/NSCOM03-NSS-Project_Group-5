#!/usr/bin/env python3
"""
===============================================================
IP & TTL SPOOFING / DDOS ANOMALY DETECTION SYSTEM
Version: 1.1 (Interactive Baseline Edition)
Developers: Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan
===============================================================

Scope and Limitations:
1. Vulnerability - Baseline learning phase. The detector relies on the accuracy of initial traffic to build trusted baselines.
2. Heavy Traffic - If too much traffic occurs in a short time, detection accuracy may degrade due to buffer overflow or rate-limit conditions.
3. Detection Scope - System focuses on IP-layer and TTL-based spoofing detection. ARP spoofing and other lower-layer attacks may not be detected.
4. TTL Variation - TTL can vary slightly as packets traverse multiple hops. To reduce false positives, the system allows a ±10 deviation threshold (configurable).
5. System Performance - Depending on the hardware and network speed, performance may vary during long sniffing sessions.

===============================================================
"""

import os
import time
import json
import logging
import signal
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, PcapWriter, conf

# ------------------- CONFIG -------------------
DEFAULT_IFACE = "\\Device\\NPF_Loopback"

BASELINE_DURATION = 30           # seconds for learning baseline (or new-flow learning)
MIN_BASELINE_PACKETS = 10
TTL_CHANGE_THRESHOLD = 30
RATE_WINDOW = 5                  # seconds
RATE_THRESHOLD_PPS = 25
CONSECUTIVE_RATE_WINDOWS = 3     # windows required above threshold to alert

BPF_FILTER = "ip and (src net 10.1.1.0/24 or dst net 10.1.1.0/24)"  # adjust if needed

TTL_OS_MAP = {
    64: "Linux/Unix/macOS/Android/iOS",
    128: "Windows",
    255: "Network Device"
}

BASELINE_FILE = "baseline.json"
RUNS_DIR = "runs"
# ------------------------------------------------

# ---------- Banner text (printed at start) ----------
BANNER = r"""
===============================================================
IP & TTL SPOOFING / DDOS ANOMALY DETECTION SYSTEM
Version: 1.1 
Developers: Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan
===============================================================

Scope and Limitations:
1. Vulnerability – Baseline learning phase. The detector relies on the accuracy of initial traffic to build trusted baselines.
2. Heavy Traffic – If too much traffic occurs in a short time, detection accuracy may degrade due to buffer overflow or rate-limit conditions.
3. Detection Scope – System focuses on IP-layer and TTL-based spoofing detection. ARP spoofing and other lower-layer attacks may not be detected.
4. TTL Variation – TTL can vary slightly as packets traverse multiple hops. To reduce false positives, the system allows a ±10 deviation threshold (configurable).
5. System Performance – Depending on the hardware and network speed, performance may vary during long sniffing sessions.

===============================================================
"""

def ensure_runs_dir():
    os.makedirs(RUNS_DIR, exist_ok=True)

def timestamp_for_name(t):
    return t.strftime("%Y-%m-%d_%H-%M-%S")

def timestamp_for_files(t):
    return t.strftime("%Y%m%d_%H%M%S")

# ---------------- logging / run folder setup (created later per run) ----------------
def configure_run_files(start_time):
    run_name = timestamp_for_name(start_time)
    run_dir = os.path.join(RUNS_DIR, run_name)
    os.makedirs(run_dir, exist_ok=True)

    file_ts = timestamp_for_files(start_time)
    pcap_file = os.path.join(run_dir, f"capture_{file_ts}.pcap")
    json_file = os.path.join(run_dir, f"ddos_detections_{file_ts}.json")
    log_file = os.path.join(run_dir, f"ddos_detector_{file_ts}.log")
    return run_dir, pcap_file, json_file, log_file

# ---------------- baseline persistence helpers ----------------
def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return {}
    try:
        with open(BASELINE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            for k, v in data.items():
                try:
                    v['ttl_avg'] = float(v.get('ttl_avg', 0))
                    v['count'] = int(v.get('count', 0))
                except Exception:
                    pass
            return data
    except Exception:
        return {}

def save_baseline(baseline_data):
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=2)

# ---------------- logger minimal setup (before per-run logging is configured) ----------------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("ddos_detector")

# ---------------- the detector class (keeps same logic you used) ----------------
class DDoSSpoofDetector:
    def __init__(self, iface, run_pcap, run_json, run_log, baseline_mode, baseline_data):
        """
        baseline_mode:
          'fresh' - wipe baseline_data (learn from scratch)
          'add'   - baseline_data is pre-loaded and we will learn+append new flows
          'use'   - baseline_data is pre-loaded and skip learning (start detection immediately)
        """
        self.iface = iface
        self.pcap_path = run_pcap
        self.json_path = run_json
        self.log_path = run_log

        self.baseline_data = baseline_data or {}
        self.baseline_start = None
        self.baseline_established = False

        self.baseline_mode = baseline_mode

        self.src_timestamps = defaultdict(deque)
        self.src_rate_exceed = defaultdict(int)
        self.last_alert_time = {}

        self.detected_anomalies = []
        self.packet_count = 0
        self.running = True
        self.start_time = datetime.now()

        self.pcap_writer = PcapWriter(self.pcap_path, append=False, sync=True)

        try:
            conf.iface = self.iface
        except Exception:
            pass

    def guess_os_from_ttl(self, ttl):
        if ttl <= 64:
            return TTL_OS_MAP[64]
        if ttl <= 128:
            return TTL_OS_MAP.get(128, "Windows")
        return TTL_OS_MAP.get(255, "Network Device")

    def learn_baseline(self, src, dst, ttl):
        flow = f"{src}->{dst}"
        now = datetime.utcnow().isoformat()
        entry = self.baseline_data.get(flow)
        if not entry:
            self.baseline_data[flow] = {
                'count': 1,
                'ttl_sum': int(ttl),
                'ttl_avg': float(ttl),
                'first_seen': now,
                'last_seen': now,
                'os_guess': self.guess_os_from_ttl(ttl),
                'baseline_valid': False
            }
            logger.debug("Baseline add (pending): %s TTL=%s", flow, ttl)
        else:
            entry['count'] += 1
            entry['ttl_sum'] += int(ttl)
            entry['ttl_avg'] = entry['ttl_sum'] / entry['count']
            entry['last_seen'] = now
            if entry['count'] >= MIN_BASELINE_PACKETS and not entry['baseline_valid']:
                entry['baseline_valid'] = True
                logger.info("Baseline validated: %s TTL_avg=%.1f OS=%s",
                            flow, entry['ttl_avg'], entry['os_guess'])

    def detect_packet(self, pkt):
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, int(ip.ttl)
        flow = f"{src}->{dst}"
        now_ts = time.time()
        anomalies = []

        dq = self.src_timestamps[src]
        dq.append(now_ts)
        while dq and (now_ts - dq[0]) > RATE_WINDOW:
            dq.popleft()
        pps = len(dq) / RATE_WINDOW

        if pps > RATE_THRESHOLD_PPS:
            self.src_rate_exceed[src] += 1
        else:
            self.src_rate_exceed[src] = 0

        if self.src_rate_exceed[src] >= CONSECUTIVE_RATE_WINDOWS:
            if not self._recent_alert(f"RATE_{src}"):
                anomalies.append({
                    'type': 'HIGH_RATE_SRC',
                    'severity': 'MEDIUM',
                    'message': f"Source {src} sustained {pps:.1f} pps (> {RATE_THRESHOLD_PPS})",
                    'src': src,
                    'pps': pps,
                    'timestamp': datetime.utcnow().isoformat()
                })

        base = self.baseline_data.get(flow)
        if base and base.get('baseline_valid'):
            if abs(ttl - base['ttl_avg']) > TTL_CHANGE_THRESHOLD:
                ttl_key = f"TTL_{flow}_{ttl}"  # unique alert per spoofed TTL value
                if not self._recent_alert(ttl_key):
                    anomalies.append({
                        'type': 'TTL_MISMATCH',
                        'severity': 'HIGH',
                        'message': f"Flow {flow} TTL changed from {base['ttl_avg']:.1f} to {ttl}",
                        'src': src,
                        'dst': dst,
                        'baseline_ttl': base['ttl_avg'],
                        'current_ttl': ttl,
                        'timestamp': datetime.utcnow().isoformat()
                    })


        return anomalies if anomalies else None

    def _recent_alert(self, key, cooldown=10):
        now = time.time()
        last = self.last_alert_time.get(key, 0)
        if now - last < cooldown:
            return True
        self.last_alert_time[key] = now
        return False

    def log_anomaly(self, anomaly):
        self.detected_anomalies.append(anomaly)
        msg = f"{anomaly['type']} - {anomaly['message']}"
        if anomaly['severity'] == 'HIGH':
            logger.error("DETECTED: %s", msg)
        else:
            logger.warning("SUSPICIOUS: %s", msg)

    def packet_handler(self, pkt):
        if not self.running:
            return False
        try:
            self.pcap_writer.write(pkt)
        except Exception:
            pass

        self.packet_count += 1
        ip = pkt.getlayer(IP)
        if not ip:
            return

        src, dst, ttl = ip.src, ip.dst, int(ip.ttl)

        if not self.baseline_start:
            self.baseline_start = time.time()

        elapsed = time.time() - self.baseline_start if self.baseline_start else 0

        if not self.baseline_established:
            if src.startswith("10.1.1.") or dst.startswith("10.1.1."):
                self.learn_baseline(src, dst, ttl)
            if elapsed >= BASELINE_DURATION:
                self.baseline_established = True
                valid = sum(1 for v in self.baseline_data.values() if v.get('baseline_valid'))
                logger.info("=== BASELINE COMPLETE ===")
                logger.info("Learned %d flows (%d valid). Now monitoring for attacks...",
                            len(self.baseline_data), valid)
            return

        anomalies = self.detect_packet(pkt)
        if anomalies:
            for a in anomalies:
                self.log_anomaly(a)

        if self.packet_count % 50 == 0:
            mode = "DETECTION" if self.baseline_established else "BASELINE"
            logger.info("Status: %s | Packets: %d | Flows: %d",
                        mode, self.packet_count, len(self.baseline_data))

    def stop(self, sig=None, frame=None):
        logger.info("Keyboard interrupt received. Stopping detector gracefully...")
        self.running = False

    def generate_report(self):
        end_time = datetime.now()
        duration_sec = (end_time - self.start_time).total_seconds()
        hrs = int(duration_sec // 3600)
        mins = int((duration_sec % 3600) // 60)
        secs = int(duration_sec % 60)

        session_summary = {
            "session_start": self.start_time.strftime("%B %d %H:%M:%S"),
            "session_end": end_time.strftime("%B %d %H:%M:%S"),
            "duration": f"{hrs}h {mins}m {secs}s",
            "detections": self.detected_anomalies
        }

        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(session_summary, f, indent=2)
        except Exception:
            logger.exception("Failed to write session JSON")

        try:
            save_baseline(self.baseline_data)
        except Exception:
            logger.exception("Failed to save baseline to baseline.json")

        logger.info("=" * 60)
        logger.info("SESSION END")
        logger.info(f"To: {end_time.strftime('%B %d %H:%M:%S')}")
        logger.info(f"Duration: {hrs}h {mins}m {secs}s")
        logger.info("=" * 60)

        # Console summary with explicit end timestamp and duration
        print("\n" + "=" * 60)
        print("DDoS SPOOFING DETECTION SUMMARY")
        print("=" * 60)
        print(f"Packets analyzed: {self.packet_count}")
        print(f"Flows learned: {len(self.baseline_data)}")
        print(f"Detections logged: {len(self.detected_anomalies)}")
        print(f"Session Start: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Session End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Session Duration: {hrs}h {mins}m {secs}s")
        if self.detected_anomalies:
            print("\nDETECTIONS (recent):")
            for d in self.detected_anomalies[-30:]:
                print(f" - [{d['timestamp']}] {d['type']}: {d['message']}")
        print("=" * 60)

    def start(self):
        signal.signal(signal.SIGINT, self.stop)
        logger.info("=== Detector Started ===")
        if self.baseline_mode == "use":
            self.baseline_established = True
            logger.info("Using existing baseline (skip learning).")
        else:
            logger.info("Baseline mode: %s (learning window: %ds)", self.baseline_mode, BASELINE_DURATION)
            logger.info("Start legitimate client/s during baseline window to learn flows.")

        logger.info("Press Ctrl+C to stop and see report.")
        # Print start timestamp to console explicitly
        print(f"\n[INFO] Detection session starting at {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        try:
            while self.running:
                sniff(prn=self.packet_handler, iface=self.iface, filter=BPF_FILTER, store=0, timeout=1)
        except Exception as e:
            logger.exception("Sniff error: %s", e)
        finally:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
            self.generate_report()
            logger.info("Detector stopped cleanly.")

# ---------------- Interactive baseline management functions ----------------
def interactive_edit_baseline(baseline_data):
    if not baseline_data:
        print("No baseline present to edit.")
        return baseline_data
    flows = list(baseline_data.keys())
    print("\nCurrent baseline flows:")
    for i, f in enumerate(flows, 1):
        e = baseline_data[f]
        valid = "VALID" if e.get('baseline_valid') else "PENDING"
        print(f"{i:3d}) {f} TTL_avg={e.get('ttl_avg'):.1f} count={e.get('count')} OS={e.get('os_guess')} ({valid})")
    print("\nEnter flow numbers to delete (comma-separated), or blank to cancel:")
    sel = input("Delete> ").strip()
    if not sel:
        print("No changes made.")
        return baseline_data
    to_remove = set()
    for part in sel.split(","):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(flows):
                to_remove.add(flows[idx])
        except Exception:
            continue
    if not to_remove:
        print("No valid selections.")
        return baseline_data
    print("Removing the following flows:")
    for r in to_remove:
        print(" -", r)
        baseline_data.pop(r, None)
    save_baseline(baseline_data)
    print("Baseline updated and saved to", BASELINE_FILE)
    return baseline_data

# ---------------- main interactive startup ----------------
def main():
    # Print banner and prompt for starting
    print(BANNER)
    try:
        start_input = input("Enter 1 to start the program or press Ctrl+C to exit: ").strip()
    except KeyboardInterrupt:
        print("\nExiting (user cancelled).")
        return
    if start_input != "1":
        print("Input not '1'. Exiting.")
        return

    ensure_runs_dir()

    baseline_exists = os.path.exists(BASELINE_FILE)
    baseline_data = {}
    if baseline_exists:
        baseline_data = load_baseline()
        print(f"[INFO] Found existing baseline with {len(baseline_data)} flows.")
    else:
        print("[INFO] No baseline found. You will need to run a fresh baseline.")

    print("\nChoose how to start detector:")
    if baseline_exists:
        print("  1) Run fresh baseline (wipe existing baseline and learn new)")
        print("  2) Add to baseline (load existing baseline and learn new flows during baseline)")
        print("  3) Edit / Delete flows from baseline")
        print("  4) Use existing baseline (skip learning, start detection immediately)")
        choice = input("Enter 1/2/3/4 > ").strip()
    else:
        print("  1) Run fresh baseline (create baseline now)")
        choice = input("Enter 1 > ").strip() or "1"

    baseline_mode = "fresh"
    if baseline_exists:
        if choice == "1":
            baseline_mode = "fresh"
            baseline_data = {}
            if os.path.exists(BASELINE_FILE):
                try:
                    os.remove(BASELINE_FILE)
                    print("[INFO] Removed old baseline.json (fresh start).")
                except Exception:
                    pass
        elif choice == "2":
            baseline_mode = "add"
        elif choice == "3":
            baseline_data = interactive_edit_baseline(baseline_data)
            print("\nBaseline edit complete.")
            print("Do you want to start detection now using the updated baseline? (y/n)")
            run_now = input("> ").strip().lower()
            if run_now == "y":
                baseline_mode = "use"
            else:
                print("Exiting (no detection started). You can run detect.py later.")
                return
        elif choice == "4":
            baseline_mode = "use"
        else:
            print("Invalid choice, defaulting to 'use' if baseline exists.")
            baseline_mode = "use"
    else:
        baseline_mode = "fresh"

    run_start = datetime.now()
    run_dir, pcap_file, json_file, log_file = configure_run_files(run_start)

        # Reconfigure logging cleanly (avoid double printing)
    root = logging.getLogger()

    # Remove ALL existing handlers before adding new ones
    for h in list(root.handlers):
        root.removeHandler(h)

    fh = logging.FileHandler(log_file, encoding="utf-8", mode='w')
    sh = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    sh.setFormatter(formatter)

    root.addHandler(fh)
    root.addHandler(sh)
    root.setLevel(logging.INFO)


    logger.info("Created run folder: %s", run_dir)
    logger.info("Pcap file: %s", pcap_file)
    logger.info("JSON file: %s", json_file)
    logger.info("Log file: %s", log_file)

    detector = DDoSSpoofDetector(iface=DEFAULT_IFACE,
                                 run_pcap=pcap_file,
                                 run_json=json_file,
                                 run_log=log_file,
                                 baseline_mode=baseline_mode,
                                 baseline_data=baseline_data)

    if baseline_mode == "use":
        detector.baseline_established = True
    else:
        detector.baseline_established = False

    try:
        detector.start()
    except KeyboardInterrupt:
        detector.stop()
    finally:
        pass

if __name__ == "__main__":
    main()

