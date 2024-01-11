import socket
import resources.network_layer_protocols
import resources.application_layer_protocols
import resources.transport_layer_protocols
from struct import *
import utils.colors

class Packet :
    def __init__(self, packet):
        self.packet = packet
        self.ip_header = unpack('!BBHLBBH4s4s',self.packet[14:34])
        self.protocol_network = "Undefined"
        self.protocol_transport = "Undefined"
        self.protocol_application = "Undefined"
        self.number = 0
    
    def is_ipv4(self):
        return self.packet[12:14] == b'\x08\x00'

    def is_arp(self):
        return self.packet[12:14] == b'\x08\x06'
    
    def is_address_source(self,address):
        return socket.inet_ntoa(self.ip_header[7]) == address
    
    def is_address_destination(self,address):
        return socket.inet_ntoa(self.ip_header[8]) == address
    
    def pass_protocols(self):
        network = self.packet[12:14]
        network_hex_string = ''.join(f'{byte:02x}' for byte in network)
        self.protocol_network  = resources.network_layer_protocols.etherType.get(network_hex_string, "Undefined")
        if(network == b'\x08\x00'):
            header_length = ( self.ip_header[0] & 0x0F ) * 4
            transport = self.ip_header[5]
            self.protocol_transport = resources.application_layer_protocols.protocol_number.get(int(transport), "Undefined")
            dest_port = int.from_bytes(self.packet[14+header_length+2:14+header_length+4], byteorder='big')
            self.number = dest_port
            if(transport == 6): # TCP
                # tcp_header = unpack('!HHLLBBHHH', self.packet[14+header_length:14+header_length+20])
                self.protocol_application = resources.transport_layer_protocols.tcp_ports.get(dest_port, "Undefined")
            if(transport == 17): # UDP
                self.protocol_application = resources.transport_layer_protocols.udp_ports.get(dest_port, "Undefined")
        return 0
            
        
    def __str__(self):
        return f' {utils.colors.colorize(self.protocol_network,"warning") if self.protocol_network=="ARP" else self.protocol_network} | {self.number} | {self.protocol_transport} | {self.protocol_application}'
