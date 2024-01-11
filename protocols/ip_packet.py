"""
IP header :

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

* FIRST 32 bits :

Version:  4 bits
	The Version field indicates the format of the internet header.  This
	document describes version 4.
	IPV4 : 0100 
	IPV6 : 0110


IHL:  4 bits
	Internet header length (in 32 bit words)
	for example : IHL = 1000 = 8 => The length of the header is 8*4 = 32bytes = 256bits
	(Also, the number of lines in the header schema (above))

Type of Service:  8 bits
	The Type of Service provides an indication of the abstract
    parameters of the quality of service desired.
	      Bits 0-2:  Precedence.
      Bit    3:  0 = Normal Delay,      1 = Low Delay.
      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
      Bit  6-7:  Reserved for Future Use.

         0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+

        Precedence

          111 - Network Control
          110 - Internetwork Control
          101 - CRITIC/ECP
          100 - Flash Override
          011 - Flash
          010 - Immediate
          001 - Priority
          000 - Routine

Total Length:  16 bit
	Total Length is the length of the datagram, measured in octets,
    including internet header and data. (up to 2^16 = 65.535)	


-----------------------------------------------------------------------------------------

* Second 32 bits : 

Identification:  16 bits

    An identifying value assigned by the sender to aid in assembling the
    fragments of a datagram.

Flags:  3 bits

    Various Control Flags.

      Bit 0: reserved, must be zero
      Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
      Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

          0   1   2
        +---+---+---+
        |   | D | M |
        | 0 | F | F |
        +---+---+---+

Fragment Offset:  13 bits

    This field indicates where in the datagram this fragment belongs.
	The fragment offset is measured in units of 8 octets (64 bits).  The
    first fragment has offset zero.

-----------------------------------------------------------------------------------------

* Third 32 bits :

Time to Live:  8 bits
	This field indicates the maximum time the datagram is allowed to
    remain in the internet system.  If this field contains the value
    zero, then the datagram must be destroyed.

Protocol:  8 bits
	This field indicates the next level protocol used in the data
    portion of the internet datagram.  The values for various protocols
    are specified in "Assigned Numbers" (https://datatracker.ietf.org/doc/html/rfc790)
	
	https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

Header Checksum:  16 bits
	A checksum on the header only.  Since some header fields change
    (e.g., time to live), this is recomputed and verified at each point
    that the internet header is processed.

-----------------------------------------------------------------------------------------

* Fourth 32 bits :

Source Address:  32 bits

    The source address.

-----------------------------------------------------------------------------------------

* Fifth 32 bits :

Destination Address:  32 bits

    The destination address.


"""

"""

EtherType 

0x0800 	Internet Protocol version 4 (IPv4)
0x0806 	Address Resolution Protocol (ARP)
0x0842 	Wake-on-LAN1
0x22F3 	IETF TRILL Protocol
0x6003 	DECnet Phase IV
0x8035 	Reverse Address Resolution Protocol (RARP)
0x809b 	AppleTalk (Ethertalk)
0x80F3 	AppleTalk Address Resolution Protocol (AARP)
0x8100 	VLAN-tagged frame (IEEE 802.1Q) & Shortest Path Bridging IEEE 802.1aq2
0x8137 	Novell IPX (alternatif)
0x8138 	Novell
0x8204 	QNX Qnet
0x86DD 	Internet Protocol, VEtherType 	Protocoleersion 6 (IPv6)
0x8808 	Ethernet flow control
0x8809 	Slow Protocols (IEEE 802.3)
0x8819 	CobraNet
0x8847 	MPLS unicast
0x8848 	MPLS multicast
0x8863 	PPPoE Discovery Stage
0x8864 	PPPoE Session Stage
0x8870 	Jumbo Frames
0x887B 	HomePlug 1.0 MME
0x888E 	EAP over LAN (IEEE 802.1X)
0x8892 	Profinet RT
0x8896 	Ethersound
0x889A 	HyperSCSI (SCSI over Ethernet)
0x88A2 	ATA over Ethernet
0x88A4 	EtherCAT Protocol
0x88A8 	Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq3
0x88AB 	Powerlink
0x88CC 	Link Layer Discovery Protocol (LLDP)
0x88CD 	Sercos
0x88E1 	HomePlug AV MME[citation nécessaire]
0x88E3 	Media Redundancy Protocol (IEC62439-2)
0x88E5 	MAC security (IEEE 802.1ae)
0x88F7 	Precision Time Protocol (IEEE 1588)
0x8902 	IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
0x8906 	Fibre Channel over Ethernet (FCoE)
0x8914 	FCoE Initialization Protocol
0x8915 	RDMA over Converged Ethernet (RoCE)
0x9000 	Configuration Testing Protocol (Loop)4, utilisé notamment pour les keepalives Ethernet chez Cisco5
0x9100 	Q-in-Q
0xCAFE 	Veritas Low Latency Transport (LLT)6 for Veritas Cluster Server

"""

from struct import *
import socket 
from resources import application_layer_protocols as alp

class IPV4_PACKET:
	
	def __init__(self, packet, id):
		self.packet = packet
		self.packet_header = packet[14:34]
		self.id = id

	
	def unpack_header(self,packet_header):
		ip_header  = unpack('!BBHLBBH4s4s',packet_header)
		version = ip_header[0] >> 4
		header_length = ( ip_header[0] & 0x0F ) * 4
		total_length = ip_header[2]
		protocol = ip_header[5]
		source_address = socket.inet_ntoa(ip_header[7])
		destination_address = socket.inet_ntoa(ip_header[8])
		return version, header_length, total_length, protocol, source_address, destination_address

	def get_ethPacket(self):
		return self.packet
	
	# def __str__(self):
	# 	version, header_length, total_length, protocol, source_address, destination_address = self.unpack_header(self.packet_header)
	# 	return f'{self.id} | IPV{version}, Header : {header_length} bytes | Total : {total_length} bytes | {protocol_number.get(str(protocol), "Unknown")} | {source_address} -> {destination_address}'

	def __str__(self):
		version, header_length, total_length, protocol, source_address, destination_address = self.unpack_header(self.packet_header)
		return f'{self.id} | {alp.protocol_number.get(str(protocol), "Unknown")} | {source_address} -> {destination_address}'
