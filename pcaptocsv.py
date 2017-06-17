#/usr/bin/python

import dpkt
from dpkt.ip import IP
from dpkt.ethernet import Ethernet
import struct
import socket
import csv

def ip_to_str(address):
    return socket.inet_ntoa(address)

f = open('test-virus.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
c = csv.writer(open("a.csv", "wb"))  # <=== moved here
for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    do_not_fragment = bool(dpkt.ip.IP_DF)
    more_fragments = bool(dpkt.ip.IP_MF)
    fragment_offset = bool(dpkt.ip.IP_OFFMASK)

    Source = "%s" % ip_to_str(ip.src)
    Destination = "%s" % ip_to_str(ip.dst)
    Length = "%d" % (ip.len)
    TTL = "%d" % (ip.ttl)
    OFF = ip.off
    TOS = ip.tos
    Protocol = ip.p
    data = (Source, Destination, Length, TTL, TOS, OFF, Protocol)
    c.writerow(data)
