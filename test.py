#!/usr/bin/python3


import socket
from ip_packet import IPV4_PACKET
from arp_packet import ARP_PACKET

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

id = 1

try:
    while True:
        packet, addr = s.recvfrom(65535)
        # ipv4_packet = IPV4_PACKET(packet,id)
        # if ipv4_packet.is_ipv4() :
        #     print(ipv4_packet)
        #     id+=1
        arp_packet = ARP_PACKET(packet,id)
        if arp_packet.is_arp() :
            print(arp_packet)
            id+=1
except KeyboardInterrupt:
    print("Arrêt de l'écoute")
    s.close()
