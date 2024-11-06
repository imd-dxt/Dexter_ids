# classs.py

import socket
import struct

class EthernetFrame:
    IPV4_ETHERTYPE = 0x0800  # EtherType for IPv4

    def __init__(self, data):
        # Parse Ethernet frame
        dest, src, proto, payload = self.ethernet_head(data)
        self.DESTINATION = dest
        self.SOURCE = src
        self.ETHER_TYPE = proto
        self.Data = payload
        
        # Parse IPv4 header if EtherType indicates IPv4
        self.ipv4_packet = None
        if self.ETHER_TYPE == self.IPV4_ETHERTYPE:
            self.ipv4_packet = IPV4(payload)
    def get_mac_addr(self, data):
        """Convert bytes to MAC address format."""
        return ':'.join(format(byte, '02x') for byte in data)
    
    def ethernet_head(self, raw_data):
        """Parse Ethernet frame header."""
        dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        dest_mac = self.get_mac_addr(dest)
        src_mac = self.get_mac_addr(src)
        payload = raw_data[14:]
        return dest_mac, src_mac, proto, payload
    def  parse_(self): # method used to define the string representation of an object
        ether = hex(self.ETHER_TYPE)
        source = self.mac_to_str(self.SOURCE)
        dest = self.mac_to_str(self.DESTINATION)
        length = len(self.Data)

        return f"[ Ethernet - {ether}; Source: {source}; Dest: {dest}; Len: {length} ]"


class IPV4:
    ID = 0x0800
    def __init__(self, data):
        # Parse IPv4 header
        VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, payload = self.ipv4_head(data)

        # Extract version and IHL
        self.VERSION = VER_IHL >> 4
        self.IHL = VER_IHL & 0x0F

        # Extract other IPv4 fields
        self.LENGTH = LEN
        self.TTL = TTL
        self.PROTOCOL = PROTO
        self.SOURCE = SOURCE
        self.DESTINATION = DEST
        options_len = 0
        if self.IHL > 5:
            # This line calculates the length of the options field in bytes.
            options_len = (self.IHL - 5) * 4

        self.OPTIONS = payload[:options_len]
        self.PAYLOAD = payload[options_len:]

    def ipv4_to_str(self, data):
        """Convert bytes to IPv4 address format."""
        return '.'.join(str(byte) for byte in data)
    
    def ipv4_head(self, raw_data):
        VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST = struct.unpack('! B B H H H B B H 4s 4s', raw_data[:20])
        return VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, raw_data[20:]
    def parse_(self):
        proto = hex(self.PROTOCOL)

        source = self.ipv4_to_str(self.SOURCE)
        dest = self.ipv4_to_str(self.DESTINATION)

        return f"[ IPV4 - Proto: {proto}; Source: {source}; Dest: {dest} ]"
class TCP:
    ID = 0x06
    def __init__(self, data):
        SOURCE_PORT, DEST_PORT, SEQUENCE_NUM, ACK_NUM, OFFSET_FLAGS, WINDOW_SIZE, CHECKSUM, URGENT_POINTER, LEFTOVER= self.tcp_head(data)
        
        self.SRC_PORT = SOURCE_PORT
        self.DST_PORT = DEST_PORT
        self.SEQ_NUM = SEQUENCE_NUM
        self.ACK_NUM = ACK_NUM
        self.OFFSET_FLAGS = OFFSET_FLAGS
        
        self.FLAGS = {
            "FIN": bool(self.OFFSET_FLAGS & 0x01),
            "SYN": bool((self.OFFSET_FLAGS >> 1) & 0x01),
            "RST": bool((self.OFFSET_FLAGS >> 2) & 0x01),
            "PSH": bool((self.OFFSET_FLAGS >> 3) & 0x01),
            "ACK": bool((self.OFFSET_FLAGS >> 4) & 0x01),
            "URG": bool((self.OFFSET_FLAGS >> 5) & 0x01),
            "ECE": bool((self.OFFSET_FLAGS >> 6) & 0x01),
            "CWR": bool((self.OFFSET_FLAGS >> 7) & 0x01),
            "NS":  bool((self.OFFSET_FLAGS >> 8) & 0x01)
        }
        self.OFFSET = OFFSET_FLAGS >> 12
        
        self.WIN_SIZE = WINDOW_SIZE
        
        self.CHKSUM  = CHECKSUM
        
        self.URG_PTR= URGENT_POINTER
        options_len = 0
        if self.OFFSET > 5:
            # This line calculates the length of the options field in bytes.
            options_len = (self.OFFSET - 5) * 4 
        self.PARAMS = LEFTOVER[:options_len]
        self.PAYLOAD = LEFTOVER[options_len:]
    def tcp_head(self, data):
        SOURCE_PORT,DEST_PORT,SEQUENCE_NUM,ACK_NUM,OFFSET_FLAGS,WIN_SIZE,CHKSUM, URG_PTR = struct.unpack('! H H I I H H H H',data[:20])
        return SOURCE_PORT,DEST_PORT,SEQUENCE_NUM,ACK_NUM,OFFSET_FLAGS,WIN_SIZE,CHKSUM, URG_PTR, data[20:]
    def parse_tcp(self):
        flags = []
        for key in self.FLAGS:
            if self.FLAGS[key]:
                flags.append(key)
         return f"[ TCP - Source Port: {self.SRC_PORT}; Destination Port: {self.DST_PORT}; Sequence: {self.SEQ_NUM}; ACK: {self.ACK_NUM}; Flags: {flags} ]"