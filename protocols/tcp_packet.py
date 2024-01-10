import socket 

class TCP_PACKET:
	"""
	TCP header format 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   

   * Source Port:  16 bits 
   * Destination Port : 16 bits
   * Sequence number : 32 bits
   * Acknoledgment Number : 32 bits
   * Data Offset : 4 bits, Reserved:  6 bits
   * Control Bits:  6 bits (from left to right):
    URG:  Urgent Pointer field significant
    ACK:  Acknowledgment field significant
    PSH:  Push Function
    RST:  Reset the connection
    SYN:  Synchronize sequence numbers
    FIN:  No more data from sender
    * Window:  16 bits
    * Checksum:  16 bits
	"""
	def __init__(self, packet, id):
		self.packet = packet
		self.packet_header = packet[14:34]
		self.id = id

 	# def get_tcp_header(packet, iph_length):
    # 	return packet[14+iph_length:14+iph_length+20]
	
	
	def unpack_header(self,packet_header):
		return 
	# def __str__(self):
	# 	version, header_length, total_length, protocol, source_address, destination_address = self.unpack_header(self.packet_header)
	# 	return f'{self.id} | IPV{version}, Header : {header_length} bytes | Total : {total_length} bytes | {protocol_number.get(str(protocol), "Unknown")} | {source_address} -> {destination_address}'

	def __str__(self):
		version, header_length, total_length, protocol, source_address, destination_address = self.unpack_header(self.packet_header)
		return f'{self.id} | {protocol_number.get(str(protocol), "Unknown")} | {source_address} -> {destination_address}'
