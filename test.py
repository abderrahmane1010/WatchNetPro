#!/usr/bin/python3


import socket
from protocols.ip_packet import IPV4_PACKET
from protocols.arp_packet import ARPPacket
from packets.packet import *
import utils.colors

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

id = 1

try:
    while True:
        packet, addr = s.recvfrom(65535)
        packet_class = Packet(packet)
        # ipv4_packet = IPV4_PACKET(packet,id)
        # if packet_class.is_ipv4() :
        #     print(ipv4_packet)
        #     id+=1
        #     packet_class.pass_protocols()
        #     print(packet_class)
        arp_packet = ARPPacket(packet,id)
        # if packet_class.is_address_source("129.88.43.109"):
        #     ipv4_packet = IPV4_PACKET(packet,id)
        #     print(ipv4_packet)
        #     packet_class.pass_protocols()
        #     print(packet_class)
        if packet_class.is_arp() :
            arp_packet.unpack_arp()
            # print(arp_packet)
            print(arp_packet.who_has_form())

        #     id+=1
        #     packet_class.pass_protocols()
        #     print(packet_class)
except KeyboardInterrupt:
    print("Arrêt de l'écoute")
    s.close()
