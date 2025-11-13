# NSS Project — IP Spoofing & TTL / DoS Detector

**Project:** IP address spoofing & DoS detector using TTL analysis and high-rate detection  
**Version:** 1.1 
**Authors:** Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan

---

## Summary (one line)
Lightweight lab tool that learns normal traffic (baseline), then detects IP-spoofing by TTL changes and DoS-like high-rate sources on an isolated test network.

---

## Files in this repo
- `detect.py`  — Main detector (interactive baseline management, detection, run logging, pcaps)
- `Client1.py` — Legitimate client simulator (Windows-like TTL=128)
- `Client2.py` — Legitimate client simulator (Linux-like TTL=64)
- `attack.py`  — Attacker simulator (spoofs a legitimate IP, varies TTL and rate)
- `baseline.json` — (auto-created) Saved baseline of learned flows
- `runs/`      — Per-run folders with `.pcap`, `.json`, and `.log` outputs
- `README.txt` — This document

---

## What this does (plain)
1. **Learn**: while in baseline mode the detector records flows (src→dst), counts packets and records average TTL per flow.
2. **Validate**: a flow becomes a trusted baseline entry once it has enough packets (configurable).
3. **Detect**: after baseline completes, the detector checks every captured packet:
   - If a flow’s TTL deviates from its baseline average by more than `TTL_CHANGE_THRESHOLD` → raise `TTL_MISMATCH`.
   - If a single source maintains > `RATE_THRESHOLD_PPS` for `CONSECUTIVE_RATE_WINDOWS` windows → raise `HIGH_RATE_SRC` (possible DoS).
4. **Log**: all packets are saved to a pcap; anomalies are saved to a JSON report and written to the run log.

---

## Detection logic
**TTL-based spoofing**  
- Baseline stores a per-flow average TTL (e.g., `10.1.1.20->10.1.1.10: ttl_avg=128`).  
- For new packets on a validated flow we compute `abs(current_ttl - ttl_avg)`.  
- If this difference > `TTL_CHANGE_THRESHOLD` (default **±10**) we flag `TTL_MISMATCH`.  
- Notes:
  - TTL decreases by 1 per router hop; the baseline captures TTL *as observed at the detector*. Use ±10 to account for typical path changes on a local lab.
  - The threshold is configurable at top-of-file (`TTL_CHANGE_THRESHOLD`) and can be changed to ±40 for noisier networks.

**High-rate (DoS) detection**  
- For each source IP we keep a sliding window of timestamps (window length `RATE_WINDOW` seconds).
- Packets-per-second (pps) = `count_in_window / RATE_WINDOW`.
- If `pps > RATE_THRESHOLD_PPS` for `CONSECUTIVE_RATE_WINDOWS` windows we flag `HIGH_RATE_SRC`.
- This reduces false positives from brief bursts.

**Debouncing alerts**
- Each distinct alert key is suppressed for a short cooldown (default 10s) to avoid log spam from repeated identical events.

---

## Configuration
Edit constants near the top of `detect.py`:

- `DEFAULT_IFACE` — scapy interface name (e.g. `\Device\NPF_Loopback` on Windows with Npcap)
- `BASELINE_DURATION` — seconds to learn baseline (default `30`)
- `MIN_BASELINE_PACKETS` — minimum packets for a flow to be considered valid
- `TTL_CHANGE_THRESHOLD` — TTL deviation threshold (default `10`)
- `RATE_WINDOW` — sliding window (seconds) for rate calculation (default `5`)
- `RATE_THRESHOLD_PPS` — pps threshold for high-rate (default `25`)
- `CONSECUTIVE_RATE_WINDOWS` — consecutive over-threshold windows before alert

---

## Quick start — Step-by-step simulation (run in separate terminals)

Follow these steps in *different terminal windows* so detector, clients, and attacker run concurrently when needed.

### 0) Pre-checks (one-time)
1. Install requirements:
   - Python 3.8+ installed.
   - Scapy: `pip install scapy`
   - On Windows: install Npcap (required for packet capture/send).
2. Confirm Scapy sees your interfaces:
   - Run a short Python snippet or open a Python REPL and do:
     ```py
     from scapy.all import show_interfaces
     show_interfaces()
     ```
   - Note the loopback interface name (example on Windows: `\Device\NPF_Loopback` or a GUID device string). Use that name for `DEFAULT_IFACE` / `LOOP_IFACE` in the scripts.
3. IP Address Mappings
   - Make sure Clients are mapped to an Ip address in the loopback interface that you will be using
     Tip: You can add a specific IP Address by using the command:
     `netsh interface ipv4 add address "[enter interface]" [add Ip address you want to use]`
---
### 1) Start the detector (terminal A)
1. Open Terminal A and run:
   ```bash
   python detect.py
   ```
2. When the banner appears, enter `1` to start the program.
3. Choose baseline option when prompted:
   - If this is your first run or you want a clean baseline → **enter 1** (fresh baseline).
   - If you have a saved `baseline.json` and want to reuse it → choose the **use** option.
   - You can also select **add** (append new flows) or **edit** to delete flows.
4. After choosing `fresh` or `add`, the detector will begin a baseline learning window (default `BASELINE_DURATION = 30` seconds). **Do not** run the attacker yet.

**What to expect:** detector prints status logs; it will say `Baseline mode: fresh (learning window: 30s)` or similar.

---

### 2) Start legitimate clients (terminals B and C) — *during baseline*
Start the traffic generators so the detector learns normal flows and TTLs.

Terminal B:
```bash
python Client1.py
```
- Client1 sends packets from `10.1.1.20` (TTL=128 by default).

Terminal C:
```bash
python Client2.py
```
- Client2 sends packets from `10.1.1.40` (TTL=64 by default).

**Keep both clients running** until the detector logs `=== BASELINE COMPLETE ===` and shows learned flows. A flow becomes VALID after `MIN_BASELINE_PACKETS` packets (default 10).

---

### 3) Verify baseline completion (Terminal A)
- Look for:
  ```
  === BASELINE COMPLETE ===
  Learned X flows (Y valid). Now monitoring for attacks...
  ```
- If flows are missing:
  - Confirm `DEFAULT_IFACE` in `detect.py` and `LOOP_IFACE` in clients match the interface from `show_interfaces()`.
  - Temporarily set `BPF_FILTER = "ip"` to capture all IP traffic while debugging.

---

### 4) Run the attacker (Terminal D) — detection stage
Once baseline is established:

Terminal D:
```bash
python attack.py
```
- `attack.py` spoofs the legitimate IP (default `10.1.1.20`) and sends waves with varied TTLs and periodic high-rate bursts.
- Watch Terminal A (detector logs) for alerts:
  - `TTL_MISMATCH` — TTL deviated from baseline
  - `HIGH_RATE_SRC` — sustained high packets-per-second from a source

---

### 5) Stop processes and collect outputs
1. Stop attacker and clients with `Ctrl+C` in their terminals.
2. Stop detector with `Ctrl+C` in Terminal A to trigger the session report.

**Files produced** (in `runs/<timestamp>/`):
- `capture_<ts>.pcap` — full packet capture (open in Wireshark)
- `ddos_detections_<ts>.json` — session summary + detections
- `ddos_detector_<ts>.log` — full runtime log
- `baseline.json` — updated baseline (saved in working dir)

---


---

## Troubleshooting (quick fixes)
- **No flows learned**: ensure clients and detector use the same interface; try setting `BPF_FILTER = "ip"` temporarily.
- **Immediate TTL alerts during baseline**: start clients before baseline completes or increase `BASELINE_DURATION`.
- **No alerts when attacking**: ensure attacker spoofs an IP present in the baseline; confirm attacker and detector share the same loopback interface.

---

## Safety & ethics (must read)
Do not use these tools on public or production networks. They intentionally send spoofed packets and floods which are disruptive. Use only in isolated lab environments where you have permission.

---

===============================================================
