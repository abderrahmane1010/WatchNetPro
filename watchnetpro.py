#!/usr/bin/python3
"""
Capture des paquets avec des sockets :
    Lorsque vous utilisez des sockets bruts pour capturer des paquets sur la plupart des systèmes d'exploitation modernes, le préambule et le SFD sont généralement gérés par le matériel réseau (comme la carte réseau) et ne sont pas inclus dans les paquets transmis au logiciel.
    Ce que votre socket reçoit commence habituellement avec l'adresse MAC de destination, suivi de l'adresse MAC source, puis du champ Type/Longueur.
"""

import socket
import struct
from protocols.ip_packet import IPV4_PACKET
def is_ipv4(packet):
    return packet[12:14] == b'\x08\x00'

def get_tcp_header(packet, iph_length):
    return packet[14+iph_length:14+iph_length+20]

def parse_ipv4_packet(packet):
    # L'en-tête IP commence à l'octet 14
    ip_header = packet[14:34] # L'en-tête IP standard est de 20 octets
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    """
    iph[0]    B : version_ihl
    iph[1]    B : ToS / ECN
    iph[2]    H : Logueur totale du packet IP (sur 16 bits : 2^16 = 65536 bit = 8192 bytes)
    iph[3]    H : packet identifier (identifiant unique pour le packet sur 16 bits)
    iph[4]    H : Drapeaux (3bit) + Fragment offset (13 bits) = (16 bits)
    iph[5]    B : TTL (8 Bit)
    iph[6]    B : protcole de la couche supérieur (TCP, UDP, ICMP...)
    iph[7]    H : checksum of the packet header
    iph[8]    4s : Adresse source 
    iph[9]    4s : Adresse destination
    """
    version_ihl = iph[0] # Il contient le B : unsigned char => 1 byte => Ex : 0100 1000 (IPV4 - 8 x 4 (car c'est en unité de 4)  = 32 byte)
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    if protocol == 6:  # TCP
        tcp_header = get_tcp_header(packet, iph_length)
        parse_tcp_segment(tcp_header, packet, iph_length)

    print(f"Version IP : {version}, Longueur en-tête : {iph_length}, TTL : {ttl}, Protocole : {protocol}, Adresse source : {s_addr}, Adresse destination : {d_addr}")


def parse_tcp_segment(tcp_header, packet, iph_length):
    """
    tcph[0] H : port source (16 bits)
    tcph[1] H : port destination
    tcph[2] L : Numéro de séquence (du premier octet de données dans ce segment) (32 bits)
    tcph[3] L : numéro d'accusé de réception
    tcph[4] B : Longueur de l'en-tête TCP (en unité de 32 bits) (4 bits) / Réservé (3 bits)
    tcph[5] B : Flags (9 bits)
    tcph[6] H : Fenêtre (16 bits) 
    tcph[7] H : CHecksum (16 bits)
    tcph[8] H : Pointeur Urgent
    """
    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
    source_port, dest_port = tcph[:2]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = 14 + iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    # Extraire les données et tenter de détecter HTTP ou HTTPS
    data = packet[h_size:]
    if source_port == 80 or dest_port == 80:
        print("Paquet potentiellement HTTP détecté")
    elif source_port == 443 or dest_port == 443:
        print("Paquet potentiellement HTTPS détecté")
    else:
        print("Autre paquet TCP détecté")


# Créer un socket brut
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

print("En écoute des paquets...")

try:
    while True:
        packet, addr = s.recvfrom(65535) # Recevoir un paquet
        # if is_ipv4(packet):
        #     print("Paquet IPv4 détecté")
        #     parse_ipv4_packet(packet)
        # else:
        #     print("Paquet non-IP détecté")
except KeyboardInterrupt:
    print("Arrêt de l'écoute")
    s.close()
