import socket
import resources.network_layer_protocols
import resources.transport_layer_protocols
import resources.application_layer_protocols
from struct import *

class Packet :
    def __init__(self, packet):
        self.packet = packet
        self.protocol_network = "Initial"
        self.protocol_transport = "Initial"
        self.number = 0
        self.protocol_application = "Initial"
        
    def pass_protocols(self):
        network = self.packet[12:14]
        network_hex_string = ''.join(f'{byte:02x}' for byte in network)
        self.protocol_network  = resources.network_layer_protocols.etherType.get(network_hex_string, "Undefined")
        if(network == b'\x08\x00'):
            ip_header  = unpack('!BBHLBBH4s4s',self.packet[14:34])
            header_length = ( ip_header[0] & 0x0F ) * 4
            transport = ip_header[5]
            self.protocol_transport = resources.transport_layer_protocols.protocol_number.get(int(transport), "Undefined")
            dest_port = int.from_bytes(self.packet[14+header_length+2:14+header_length+4], byteorder='big')
            self.number = dest_port
            if(transport == 6): # TCP
                # tcp_header = unpack('!HHLLBBHHH', self.packet[14+header_length:14+header_length+20])
                self.protocol_application = resources.application_layer_protocols.tcp_ports.get(dest_port, "Undefined")
            if(transport == 17): # UDP
                self.protocol_application = resources.application_layer_protocols.udp_ports.get(dest_port, "Undefined")
        return self.number
            
        
    def __str__(self):
        return f'{self.protocol_network} | {self.number} | {self.protocol_transport} | {self.protocol_application}'
