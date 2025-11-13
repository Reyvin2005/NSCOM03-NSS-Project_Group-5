# NSS Project — IP Spoofing & TTL / DoS Detector

**Project:** IP address spoofing & DoS detector using TTL analysis and high-rate detection  
**Version:** 1.1 (Interactive Baseline Edition)  
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

## Detection logic (more detail)
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

## Configuration (quick)
Edit constants near the top of `detect.py`:

- `DEFAULT_IFACE` — interface name (e.g. `\Device\NPF_Loopback` on Windows with Npcap)
- `BASELINE_DURATION` — seconds to learn baseline (default `30`)
- `MIN_BASELINE_PACKETS` — minimum packets for a flow to be considered valid
- `TTL_CHANGE_THRESHOLD` — TTL deviation threshold (default `10`)
- `RATE_WINDOW` — sliding window (seconds) for rate calc (default `5`)
- `RATE_THRESHOLD_PPS` — pps threshold for high-rate (default `25`)
- `CONSECUTIVE_RATE_WINDOWS` — consecutive over-threshold windows before alert

---

## Quick start (short)
1. Install requirements: `pip install scapy` and install Npcap on Windows.  
2. Start `detect.py` (run as admin/root). Choose baseline option: fresh/add/use/edit.  
3. Run `Client1.py` and `Client2.py` during baseline so detector learns flows.  
4. After baseline completes, run `attack.py`. Watch logs for `TTL_MISMATCH` and `HIGH_RATE_SRC`.  
5. Stop detector with Ctrl+C to produce session summary and saved run files in `runs/<timestamp>/`.

---

## Troubleshooting (quick fixes)
- **No flows learned**: ensure clients and detector use the same interface; try setting `BPF_FILTER = "ip"` temporarily.
- **Immediate TTL alerts during baseline**: start clients before baseline completes or increase `BASELINE_DURATION`.
- **No alerts when attacking**: ensure attacker spoofs an IP present in the baseline; confirm attacker and detector share the same loopback interface.

---

## Safety & ethics (must read)
Do not use these tools on public or production networks. They intentionally send spoofed packets and floods which are disruptive. Use only in isolated lab environments where you have permission.

---

## Appendix C — Short code discussion (for the paper)
- The detector is intentionally minimal and deterministic so behavior is reproducible in a student lab.
- The **baseline approach** mimics host-behavior modelling: we record a simple scalar (average TTL) per flow and a flow packet count. This keeps state small and explainable.
- **Why TTL?** Many OS families use different initial TTL values (common defaults: 64, 128, 255). If the same source IP suddenly appears with differing TTLs, it likely signals spoofing or traffic from a different network path/host.
- **Limitations**:
  - TTL alone is not conclusive — routing changes or NAT could cause TTL differences. That is why baseline validation and rate detection are combined; TTL mismatches are flagged with HIGH severity but should be correlated with other evidence.
  - The system does not attempt TCP handshake validation (e.g., SYN/ACK responses), which could further reduce false positives.
  - Performance and accuracy drop under very heavy traffic; for larger testbeds consider sampling or using a more optimized packet capture pipeline (e.g., PF_RING, DPDK).
- **Potential improvements for future work**:
  - Combine TTL anomalies with TCP/IP fingerprinting, RTT analysis, and MAC-to-IP mapping (where available).
  - Add active probing (challenge-response) to validate suspicious sources.
  - Integrate rate-limiting mitigations (e.g., token bucket) or automated quarantine in a controlled environment.

---

## Contact
Authors: Ivan Antonio Alvarez, Joshua Benedict Co, Reyvin Matthew Tan  
Use the code for your lab report and include Appendix C (code + short discussion) when you submit.

===============================================================
