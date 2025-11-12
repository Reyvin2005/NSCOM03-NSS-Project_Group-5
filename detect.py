#!/usr/bin/env python3
"""
detect.py - DDoS IP Spoofing & TTL Anomaly Detector (Windows-safe, graceful Ctrl+C)

Features:
- Loopback-ready (DEFAULT_IFACE uses your NPF loopback device name)
- Baseline learning, TTL mismatch detection, sustained high-rate detection
- Debounced alerts to reduce spam
- PCAP output, JSON-lines detections, logging
- Graceful shutdown: Ctrl+C stops quickly and prints a summary
"""

import time
import json
import logging
import signal
from datetime import datetime
from collections import defaultdict, deque
from scapy.all import sniff, IP, PcapWriter, conf

# ------------------- CONFIG -------------------
DEFAULT_IFACE = "\\Device\\NPF_Loopback"  # adjust if your loopback device uses a different name

BASELINE_DURATION = 30           # seconds to learn baseline
MIN_BASELINE_PACKETS = 10        # flow must be seen this many times to be "valid"

TTL_CHANGE_THRESHOLD = 30        # TTL deviation threshold to consider spoofing
RATE_WINDOW = 5                  # seconds for rate calculation (sliding window)
RATE_THRESHOLD_PPS = 25          # packets/sec threshold to consider high-rate
CONSECUTIVE_RATE_WINDOWS = 3     # require this many consecutive windows > threshold

PCAP_FILENAME = "capture.pcap"
DETECTIONS_FILE = "ddos_detections.json"
LOGFILE = "ddos_detector.log"

# BPF filter to restrict capture to your test subnet
BPF_FILTER = "ip and (src net 10.1.1.0/24 or dst net 10.1.1.0/24)"

TTL_OS_MAP = {
    64: "Linux/Unix/macOS/Android/iOS",
    128: "Windows",
    255: "Network Device"
}
# ------------------------------------------------

# Logging (file uses utf-8)
file_handler = logging.FileHandler(LOGFILE, encoding="utf-8")
stream_handler = logging.StreamHandler()
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[file_handler, stream_handler])
logger = logging.getLogger("ddos_detector")


class DDoSSpoofDetector:
    def __init__(self, iface=DEFAULT_IFACE):
        self.iface = iface
        self.baseline_data = {}   # flow -> {count, ttl_sum, ttl_avg, ..., baseline_valid}
        self.baseline_start = None
        self.baseline_established = False

        self.pcap = PcapWriter(PCAP_FILENAME, append=True, sync=True)
        self.detected_anomalies = []

        # per-source rate tracking
        self.src_timestamps = defaultdict(deque)
        self.src_rate_exceed = defaultdict(int)

        # debounce map for repeating alerts
        self.last_alert_time = {}

        self.packet_count = 0
        self.running = True

        # prefer this iface for scapy send() usage
        try:
            conf.iface = self.iface
        except Exception:
            pass

        logger.info("Initialized detector on %s", self.iface)
        logger.info("Baseline duration: %ds | TTL threshold: %d | PPS threshold: %d",
                    BASELINE_DURATION, TTL_CHANGE_THRESHOLD, RATE_THRESHOLD_PPS)

    # --- signal handler to stop gracefully ---
    def stop(self, sig=None, frame=None):
        logger.info("Keyboard interrupt received. Stopping detector gracefully...")
        self.running = False

    # --- helper: coarse OS guess from TTL ---
    def guess_os_from_ttl(self, ttl):
        if ttl <= 64:
            return TTL_OS_MAP[64]
        if ttl <= 128:
            return TTL_OS_MAP.get(128, "Windows")
        return TTL_OS_MAP.get(255, "Network Device")

    # --- baseline learning ---
    def learn_baseline(self, src, dst, ttl):
        flow = f"{src}->{dst}"
        now = datetime.utcnow().isoformat()
        entry = self.baseline_data.get(flow)
        if not entry:
            self.baseline_data[flow] = {
                'count': 1, 'ttl_sum': int(ttl), 'ttl_avg': float(ttl),
                'first_seen': now, 'last_seen': now,
                'os_guess': self.guess_os_from_ttl(ttl),
                'baseline_valid': False
            }
        else:
            entry['count'] += 1
            entry['ttl_sum'] += int(ttl)
            entry['ttl_avg'] = entry['ttl_sum'] / entry['count']
            entry['last_seen'] = now
            if entry['count'] >= MIN_BASELINE_PACKETS and not entry['baseline_valid']:
                entry['baseline_valid'] = True
                logger.info("Baseline validated: %s TTL_avg=%.1f OS=%s", flow, entry['ttl_avg'], entry['os_guess'])

    # --- detection logic for a single packet ---
    def detect_packet(self, pkt):
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        src, dst, ttl = ip.src, ip.dst, int(ip.ttl)
        flow = f"{src}->{dst}"
        now_ts = time.time()
        anomalies = []

        # rate tracking: sliding window
        dq = self.src_timestamps[src]
        dq.append(now_ts)
        while dq and (now_ts - dq[0]) > RATE_WINDOW:
            dq.popleft()
        pps = len(dq) / RATE_WINDOW

        # sustained high-rate detection
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

        # TTL mismatch detection (only for validated baseline flows)
        base = self.baseline_data.get(flow)
        if base and base.get('baseline_valid'):
            if abs(ttl - base['ttl_avg']) > TTL_CHANGE_THRESHOLD:
                if not self._recent_alert(f"TTL_{flow}"):
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

    # --- simple debounce for duplicate alerts ---
    def _recent_alert(self, key, cooldown=10):
        now = time.time()
        last = self.last_alert_time.get(key, 0)
        if now - last < cooldown:
            return True
        self.last_alert_time[key] = now
        return False

    # --- logging & saving anomaly to file ---
    def log_anomaly(self, anomaly):
        self.detected_anomalies.append(anomaly)
        msg = f"{anomaly['type']} - {anomaly['message']}"
        if anomaly['severity'] == 'HIGH':
            logger.error("DETECTED: %s", msg)
        else:
            logger.warning("SUSPICIOUS: %s", msg)
        try:
            with open(DETECTIONS_FILE, 'a', encoding='utf-8') as f:
                f.write(json.dumps(anomaly) + "\n")
        except Exception as e:
            logger.exception("Failed to write detection file: %s", e)

    # --- packet handler passed to sniff ---
    def packet_handler(self, pkt):
        # stop condition
        if not self.running:
            return False

        try:
            self.pcap.write(pkt)
        except Exception:
            pass

        self.packet_count += 1
        ip = pkt.getlayer(IP)
        if not ip:
            return

        src, dst, ttl = ip.src, ip.dst, int(ip.ttl)

        # start baseline timer on first packet
        if not self.baseline_start:
            self.baseline_start = time.time()

        elapsed = time.time() - self.baseline_start if self.baseline_start else 0

        # baseline phase
        if not self.baseline_established:
            # only learn flows in the test subnet
            if src.startswith("10.1.1.") or dst.startswith("10.1.1."):
                self.learn_baseline(src, dst, ttl)
            if elapsed >= BASELINE_DURATION:
                self.baseline_established = True
                valid = sum(1 for v in self.baseline_data.values() if v.get('baseline_valid'))
                logger.info("=== BASELINE COMPLETE ===")
                logger.info("Learned %d flows (%d valid). Now monitoring for attacks...", len(self.baseline_data), valid)
            return

        # detection phase
        anomalies = self.detect_packet(pkt)
        if anomalies:
            for a in anomalies:
                self.log_anomaly(a)

        # periodic status
        if self.packet_count % 50 == 0:
            mode = "DETECTION" if self.baseline_established else "BASELINE"
            logger.info("Status: %s | Packets: %d | Flows: %d", mode, self.packet_count, len(self.baseline_data))

    # --- final summary printed on exit ---
    def generate_report(self):
        print("\n" + "="*60)
        print("DDoS SPOOFING DETECTION SUMMARY")
        print("="*60)
        print(f"Packets analyzed: {self.packet_count}")
        print(f"Flows learned: {len(self.baseline_data)}")
        print(f"Detections logged: {len(self.detected_anomalies)}")
        if self.detected_anomalies:
            print("\nDETECTIONS (recent):")
            for d in self.detected_anomalies[-30:]:
                print(f" - [{d['timestamp']}] {d['type']}: {d['message']}")
        print("="*60)

    # --- start loop: sniff with short timeout to enable fast Ctrl+C response ---
    def start(self):
        signal.signal(signal.SIGINT, self.stop)
        logger.info("=== Detector Started ===")
        logger.info("Start client.py during baseline, then attacker.py for tests.")
        logger.info("Press Ctrl+C to stop and see report.")
        try:
            # run sniff repeatedly with a short timeout so we break quickly on Ctrl+C
            while self.running:
                sniff(prn=self.packet_handler, iface=self.iface, filter=BPF_FILTER, store=0, timeout=1)
        except Exception as e:
            logger.exception("Sniff error: %s", e)
        finally:
            try:
                self.pcap.close()
            except Exception:
                pass
            self.generate_report()
            logger.info("Detector stopped cleanly.")

if __name__ == "__main__":
    detector = DDoSSpoofDetector()
    detector.start()
