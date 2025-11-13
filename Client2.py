#!/usr/bin/env python3
"""
client.py - Legitimate traffic generator for baseline.
Sends consistent TTL=64 packets from 10.1.1.40 -> 10.1.1.10 on loopback.
"""
import time
import random
import signal
from scapy.all import IP, TCP, UDP, send, conf

LOOP_IFACE = "\\Device\\NPF_Loopback"
SRC_IP = "10.1.1.40"
DST_IP = "10.1.1.10"
TTL = 64                # Linux/MacOS-like TTL for baseline
SLEEP_SEC = 2.0          # gentle rate

running = True
def stop(sig, frame):
    global running
    running = False

signal.signal(signal.SIGINT, stop)

def main():
    conf.iface = LOOP_IFACE
    print("=== LEGITIMATE CLIENT STARTED ===")
    print(f"iface: {LOOP_IFACE} | {SRC_IP} -> {DST_IP} | TTL={TTL}")
    print("Press Ctrl+C to stop")
    count = 0
    start = time.time()
    try:
        while running:
            count += 1
            pkt = IP(src=SRC_IP, dst=DST_IP, ttl=TTL)/TCP(dport=80, flags='S', sport=random.randint(20000,60000))
            send(pkt, verbose=0)   # L3 send; conf.iface used
            print(f"[{count}] LEGIT TCP SYN {SRC_IP}->{DST_IP} TTL={TTL}")
            # occasional other types
            if count % 5 == 0:
                pkt2 = IP(src=SRC_IP, dst=DST_IP, ttl=TTL)/TCP(dport=8080, flags='A', sport=random.randint(20000,60000))
                send(pkt2, verbose=0)
                print(f"[{count}] LEGIT TCP ACK 8080")
            if count % 8 == 0:
                pkt3 = IP(src=SRC_IP, dst=DST_IP, ttl=TTL)/UDP(dport=53, sport=random.randint(20000,60000))
                send(pkt3, verbose=0)
                print(f"[{count}] LEGIT UDP DNS")
            time.sleep(SLEEP_SEC)
    except Exception as e:
        print("Client exception:", e)
    finally:
        dur = time.time() - start
        print("\n=== CLIENT SUMMARY ===")
        print(f"Packets sent: {count}")
        print(f"Duration: {dur:.2f}s | Rate: {count/dur if dur>0 else 0:.2f} pkt/s")
        print("Goodbye.")

if __name__ == "__main__":
    main()
