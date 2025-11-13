# NSS Project — IP Spoofing & TTL / DoS Detector

**Project**: IP Address Spoofing detector using TTL analysis and DoS-rate detection

**Version**: 1.1 (Interactive Baseline Edition)

**Authors**: Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan

---

## Overview

This repository contains a small lab toolkit to demonstrate TTL-based IP spoofing detection and basic DoS (high-rate) anomaly detection on an isolated test network (loopback/virtual interface). The detector learns per-flow TTL baselines, persists them, and raises alerts when an observed TTL deviates significantly or when a source sustains a high packet-per-second rate.

Files included:

* `detect.py` — Detector (baseline learning + detection). Interactive startup and baseline editing included.
* `Client1.py` — Legitimate traffic generator (source `10.1.1.20`, TTL=128, Windows-like stack).
* `Client2.py` — Legitimate traffic generator (source `10.1.1.40`, TTL=64, Linux-like stack).
* `attack.py` — Deterministic spoofing attacker (spoofs `10.1.1.20` → target `10.1.1.10`), no markers.

---

## Prerequisites

1. Python 3.8+ installed.
2. `scapy` installed (`pip install scapy`).
3. Run the scripts with sufficient privileges to send/receive raw IP packets (administrator/root on many systems).
4. The environment uses a WinPcap/Npcap loopback adapter name in configs: `\Device\NPF_Loopback`. Adjust `DEFAULT_IFACE` / `LOOP_IFACE` in the scripts if your interface name differs. Use `scapy.show_interfaces()` to list available interface names.

> Note: These tools are intended for a controlled lab environment (e.g., local VM or isolated testbed). Do **not** run spoofing attacks on shared or production networks.

---

## Quick start

Follow these steps in **different terminal windows** so processes run concurrently when necessary.

### 1) Prepare the detector baseline

1. Open a terminal and run:

   ```bash
   python detect.py
   ```
2. When the banner appears, enter `1` to start.
3. If prompted and you have no prior `baseline.json`, choose the default option to **run a fresh baseline** (enter `1`). The detector will enter a baseline learning window (default: 30 seconds).
4. When the detector prints `Baseline mode: fresh (learning window: 30s)` or similar, **do not start the attacker** yet.

### 2) Start legitimate clients (during baseline)

Start legitimate traffic generators so the detector can learn normal flows and TTLs.

* Terminal 2 (Client1):

  ```bash
  python Client1.py
  ```

  This generates packets from `10.1.1.20` with TTL=128.

* Terminal 3 (Client2):

  ```bash
  python Client2.py
  ```

  This generates packets from `10.1.1.40` with TTL=64.

Let both clients run throughout the detector's baseline window (30 seconds by default). The detector will mark flows as valid after it sees enough packets per flow (default `MIN_BASELINE_PACKETS = 10`).

### 3) Verify baseline completion

After the baseline window ends, the detector will log `=== BASELINE COMPLETE ===` and show how many flows were learned and how many are valid. If flows are missing:

* Ensure clients used the same interface (check `LOOP_IFACE` in clients and `DEFAULT_IFACE` in `detect.py`).
* Ensure BPF_FILTER in `detect.py` includes your test IP range (default filters `10.1.1.0/24`).

### 4) Run the attacker (detection stage)

When the detector is in detection mode (baseline established), run the attacker:

```bash
python attack.py
```

This attacker spoofs `10.1.1.20` and will send waves with TTLs that differ from the baseline (and also some high-rate waves). Watch the detector logs for `TTL_MISMATCH` and `HIGH_RATE_SRC` alerts.

### 5) Stop processes and review outputs

* Stop the attacker and clients with `Ctrl+C`.
* Stop the detector with `Ctrl+C` to trigger the session summary and report generation. The detector will write:

  * A `.pcap` capture in `runs/<timestamp>/`
  * A JSON report `ddos_detections_<ts>.json` in the run folder
  * A `.log` file containing the logged alerts
* The detector will also save (or update) `baseline.json` in the working directory.

---

## Running modes and CLI tips

The detector has three useful baseline modes at startup:

* `fresh`: wipe existing `baseline.json` and learn new flows during the baseline window.
* `add`: load current baseline and continue learning/appending new flows in a new baseline window.
* `use`: skip learning and start detection immediately using the loaded `baseline.json`.

---

## Expected detector outputs & interpretation

**Alert types** you will see in logs (and in JSON report):

* `TTL_MISMATCH`: A per-flow TTL deviated from its learned average by more than `TTL_CHANGE_THRESHOLD`. Severity: HIGH.

  * Likely cause: IP spoofing or a different OS stack for the same source IP.
* `HIGH_RATE_SRC`: A single source sustained a high packets-per-second rate above `RATE_THRESHOLD_PPS` for consecutive windows. Severity: MEDIUM.

  * Likely cause: DoS flood or high-rate scanning from a single IP.

**Where to look**:

* `runs/<timestamp>/ddos_detections_<ts>.json` — human-readable session summary and detections
* `runs/<timestamp>/capture_<ts>.pcap` — full packet capture you can open with Wireshark
* `runs/<timestamp>/ddos_detector_<ts>.log` — full runtime log with timestamps and messages

---

## Troubleshooting checklist

* No flows learned during baseline:

  * Confirm client scripts and detector use the same `LOOP_IFACE` / `DEFAULT_IFACE` and that Scapy shows that interface.
  * Confirm BPF filter matches traffic (adjust `BPF_FILTER` to `"ip"` for broad capture while debugging).
* Detector immediately flags TTL mismatches during baseline:

  * Ensure you started legitimate clients before/during the baseline window.
  * Consider increasing `BASELINE_DURATION` or lowering `MIN_BASELINE_PACKETS` for short tests.
* No alerts from attacker:

  * Confirm attacker spoofs an IP that is present in baseline (e.g., `SPOOFED_IP` should match a learned flow like `10.1.1.20`).
  * Check that attacker uses same `TARGET_IP` as detector's `DEFAULT_IFACE` traffic destination.

---

## Safety & ethical notice

These scripts perform packet injection and IP spoofing. Use them **only** in isolated labs or on networks where you have explicit permission. Running spoofed traffic on production or public networks can disrupt services and may violate law or policy.

---

## Contact

Project authors: Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan
