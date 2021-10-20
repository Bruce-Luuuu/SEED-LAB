#!/usr/bin/python3
from scapy.all import *


def send_packet(pkt):
    if (pkt[2].type == 8):
        src = pkt[1].src
        dst = pkt[1].dst
        seq = pkt[2].seq
        id = pkt[2].id
        load = pkt[3].load

        print('Original Packet: src IP ' + str(src) + '   dst IP ' + str(dst))
        reply = IP(src=dst, dst=src) / ICMP(type=0, id=id, seq=seq) / load
        print('Spoofing Packet: src IP ' + str(dst) + '   dst IP ' + str(src))
        send(reply)


pkt = sniff(iface='ens33', filter='icmp', prn=send_packet)

