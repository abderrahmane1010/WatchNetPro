#!/usr/bin/python3


import socket
from protocols.ip_packet import IPV4_PACKET
from protocols.arp_packet import ARP_PACKET
from packets.packet import *

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

id = 1

try:
    while True:
        packet, addr = s.recvfrom(65535)
        packet_class = Packet(packet)
        ipv4_packet = IPV4_PACKET(packet,id)
        if ipv4_packet.is_ipv4() :
            print(ipv4_packet)
            id+=1
            packet_class.pass_protocols()
            print(packet_class)
        # arp_packet = ARP_PACKET(packet,id)
        # if arp_packet.is_arp() :
        #     print(arp_packet)
        #     id+=1
except KeyboardInterrupt:
    print("Arrêt de l'écoute")
    s.close()
