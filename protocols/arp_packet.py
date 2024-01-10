"""
    Ethernet transmission layer (not necessarily accessible to
         the user):
        48.bit: Ethernet address of destination
        48.bit: Ethernet address of sender
        16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION

    Ethernet packet data:
       H 16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
                         Packet Radio Net.) [Hardware type]


       H 16.bit: (ar$pro) Protocol address space.  For Ethernet
                         hardware, this is from the set of type
                         fields ether_typ$<protocol>. [Protocol type]


        B 8.bit: (ar$hln) byte length of each hardware address
                Ex : Ethernet=address MAC=> 6 octects = 48 bits

        B 8.bit: (ar$pln) byte length of each protocol address
                Ex : Address IP => 4 octects = 32 bits

        H 16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
                        1 : Request,
						2 : Replay

        6s nbytes: (ar$sha) Hardware address of sender of this
                         packet, n from the ar$hln field.
        4s mbytes: (ar$spa) Protocol address of sender of this
                         packet, m from the ar$pln field.
        6s nbytes: (ar$tha) Hardware address of target of this
                         packet (if known).
        4s mbytes: (ar$tpa) Protocol address of target.
"""

from struct import *
import socket


class ARP_PACKET:

    def __init__(self, packet, id):
        self.packet = packet
        self.packet_header = packet[14:42]
        self.id = id
    
    def arp_type(self,number):
        if number == 1:
            return "Request"
        elif number == 2:
            return "Replay"
        else :
            return "Unknown"
        
    def unpack_arp(self, packet_header):
        arp = unpack('!HHBBH6s4s6s4s', packet_header)
        hard_type, protocol_type, length_hard, length_protocol, operation = arp[:5]
        hard_address_source = ':'.join(['%02x' % byte for byte in arp[5]])
        protocol_address_source = socket.inet_ntoa(arp[6])
        hard_address_dest = ':'.join(['%02x' % byte for byte in arp[7]])
        to = "Broadcast" if hard_address_dest == '00:00:00:00:00:00' else hard_address_dest
        protocol_address_dest = socket.inet_ntoa(arp[8])
        return hard_type, protocol_type, length_hard, length_protocol, operation, hard_address_source, protocol_address_source, to, protocol_address_dest
    
    def __str__(self):
        hard_type, protocol_type, length_hard, length_protocol, operation, mac_source, ip_source, mac_dest, ip_dest = self.unpack_arp(self.packet_header)
        return f'{self.id} : {mac_source} | {ip_source} -> {mac_dest} | {ip_dest} [{self.arp_type(operation)}]'
