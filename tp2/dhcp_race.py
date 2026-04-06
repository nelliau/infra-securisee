from scapy.all import *

def h(p):
    if DHCP not in p or p[DHCP].options[0][1] not in (1,3): return
    m = "offer" if p[DHCP].options[0][1]==1 else "ack"
    pkt = Ether(src=get_if_hwaddr("eth0"),dst=p[Ether].src)/IP(src="10.1.20.100",dst="255.255.255.255")/UDP(sport=67,dport=68)/BOOTP(op=2,yiaddr="10.1.20.251",xid=p[BOOTP].xid,chaddr=p[BOOTP].chaddr)
    sendp(pkt/DHCP(options=[("message-type",m),("server_id","10.1.20.100"),("subnet_mask","255.255.255.0"),("router","10.1.20.1"),"end"]),iface="eth0",verbose=0)

sniff(iface="eth0",filter="udp port 68",prn=h)
