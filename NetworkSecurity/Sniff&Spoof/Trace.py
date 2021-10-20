#!/usr/bin/python3

from scapy.all import *
import sys

MAX_TTL = 255
a = IP()
a.ttl = 1
a.dst = sys.argv[1]
b = ICMP()

while a.ttl <= MAX_TTL:
    reply = sr1(a/b, timeout=7, verbose=0)
    if reply == None:
        print(str(a.ttl) + "\t* * *")
        a.ttl += 1
        continue
    else:
        print(str(a.ttl) + "\t" + reply.src)
        a.ttl += 1
    if reply.src == a.dst:
        break
