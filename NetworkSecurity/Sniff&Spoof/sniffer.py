#!/usr/bin/env python3
from scapy.all import *
def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface='ens33', filter='net 128.230.0.0/16', prn=print_pkt)

