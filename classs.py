import socket
import struct

class EthernetFrame:
    ID = 0x0800  # EtherType for IPv4

    def __init__(self, data):
        # Parse Ethernet frame
        dest, src, proto, payload = self.ethernet_head(data)
        self.DESTINATION = dest
        self.SOURCE = src
        self.ETHER_TYPE = proto
        self.Data = payload

        # Parse IPv4 header if EtherType indicates IPv4
        if self.ETHER_TYPE == self.ID:
            # Adjusted to unpack the exact number of returned values
            VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, LEFTOVER = self.ipv4_head(self.Data)

            # Byte 0
            self.VERSION = VER_IHL >> 4
            self.IHL = VER_IHL & 0x0F

            # BYTE 2 & 3
            self.LENGTH = LEN

            # BYTE 9
            self.PROTOCOL = PROTO

            # BYTE 12 & 13
            self.SOURCE = SOURCE

            # BYTE 14 & 15
            self.DESTINATION = DEST

            options_len = 0
            if self.IHL > 5:
                # Calculate the length of the options field in bytes.
                options_len = (self.IHL - 5) * 4

            self.OPTIONS = LEFTOVER[:options_len]
            self.PAYLOAD = LEFTOVER[options_len:]

    def get_mac_addr(self, data):
        """Convert bytes to MAC address format."""
        return ':'.join(format(byte, '02x') for byte in data)

    def ipv4_to_str(self, data):
        """Convert bytes to IPv4 address format."""
        return '.'.join(str(byte) for byte in data)

    def ethernet_head(self, raw_data):
        """Parse Ethernet frame header."""
        dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        dest_mac = self.get_mac_addr(dest)
        src_mac = self.get_mac_addr(src)
        prototype = socket.htons(proto)
        payload = raw_data[14:]
        return dest_mac, src_mac, prototype, payload

    def ipv4_head(self, raw_data):
        """Parse IPv4 header if the EtherType is IPv4."""
        version_header_length = raw_data[0]
        header_length = (version_header_length & 15) * 4
        VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST = struct.unpack('! B B H H H B B H 4s 4s', raw_data[:20])
        payload = raw_data[header_length:]  # Capture payload after header
        return VER_IHL, DSCP_ECN, LEN, ID, FLAGS_OFFSET, TTL, PROTO, CHECKSUM, SOURCE, DEST, payload

    def parse_ipv4(self):
        # Translate IPv4 payload Protocol to human readable name

        source = self.ipv4_to_str(self.SOURCE)
        dest = self.ipv4_to_str(self.DESTINATION)
        if self.ETHER_TYPE == self.ID:  # Check if the EtherType indicates IPv4
            ipv4 = self.ipv4_head(self.Data)
            return ipv4
        return None