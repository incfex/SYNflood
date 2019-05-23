#!/usr/bin/python
from scapy.all import IP, TCP

a = IP()
a.src = "1.2.3.4"
a.dst = "10.0.2.15"
a.ihl = 5
b = TCP()
b.sport = 1551
b.dport = 23
b.seq = 1551
b.flags = 'S'

pkt = a/b

with open("packet", "wb") as f:
    f.write(bytes(pkt))