# classs.py
import struct
import time
from colorama import Fore,init
import threading
import socket
import queue
class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.pckt_queue = queue.Queue()
        self.num_worker_threads = 2
        self.processing_threads = []
        self.running = True  # Flag to control thread execution

    def packet_capture(self):
        try:
            ETH_P_ALL = 0x03
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            s.bind((self.interface, 0))
            
            while self.running:
                raw_data, addr = s.recvfrom(65535)
                self.pckt_queue.put(raw_data)
        except Exception as e:
            print(f"Error in packet_capture: {e}")

    def packet_processing(self):
        while self.running:
            try:
                raw_data = self.pckt_queue.get(timeout=1)  # Timeout allows thread to check the running flag
                eth = EthernetFrame(raw_data)  # Parse the Ethernet frame

                # Print Ethernet frame details
                print(Fore.GREEN + f"[*] Ethernet - {hex(eth.ETHER_TYPE)}; Source: {eth.SOURCE}; Dest: {eth.DESTINATION}; Data: {eth.Data[:20]}...")
                self.pckt_queue.task_done()

                if eth.ETHER_TYPE == IPV4.ID:
                    ipv4 = IPV4(eth.Data)
                    print(Fore.YELLOW +"->" + ipv4.parse_())  # Use the parse_ method of the IPV4 instance
                    if ipv4.PROTOCOL == TCP.ID:
                        tcp = TCP(ipv4.PAYLOAD)
                        print(Fore.CYAN +"   └─ " + tcp.parse_tcp())
                    elif ipv4.PROTOCOL == UDP.ID:
                        udp = UDP(ipv4.PAYLOAD)
                        print(Fore.CYAN +"   └─ " + udp.parse_udp())
            except queue.Empty:
                pass  # Allows the thread to continue checking if there are new packets
            except Exception as e:
                print(f"Error in packet_processing: {e}")

    def start_sniff(self):
        try:
            capture_thread = threading.Thread(target=self.packet_capture, daemon=True)
            capture_thread.start()

            for _ in range(self.num_worker_threads):
                process_thread = threading.Thread(target=self.packet_processing, daemon=True)
                process_thread.start()
                self.processing_threads.append(process_thread)

            while self.running:
                time.sleep(0.1)  
            
        except KeyboardInterrupt:
            print("\n[!] Stopping sniffer...")
            self.running = False
            for thread in self.processing_threads:
                thread.join() 
            print("[:)] THALLAAA")
class EthernetFrame:
    IPV4_ETHERTYPE = 0x0800  # EtherType for IPv4

    def __init__(self, data):
        dest, src, proto, payload = self.ethernet_head(data)
        self.DESTINATION = dest
        self.SOURCE = src
        self.ETHER_TYPE = proto
        self.Data = payload
        
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
    def  parse_(self): 
        ether = hex(self.ETHER_TYPE)
        source = self.mac_to_str(self.SOURCE)
        dest = self.mac_to_str(self.DESTINATION)
        length = len(self.Data)

        return f"[ Ethernet - {ether}; Source: {source}; Dest: {dest}; Len: {length} ]"


class IPV4:
    ID = 0x0800
    def __init__(self, data):
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
        SOURCE_PORT, DEST_PORT, SEQUENCE_NUM, ACK_NUM, OFFSET_FLAGS, WINDOW_SIZE, CHCKSUM, URGENT_POINTER, LEFTOVER= self.tcp_head(data)
        
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
        
        self.CHKSUM  = CHCKSUM
        
        self.URG_PTR= URGENT_POINTER
        options_len = 0
        if self.OFFSET > 5:
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
        return f" TCP - Source Port: {self.SRC_PORT}; Destination Port: {self.DST_PORT}; Sequence: {self.SEQ_NUM}; ACK: {self.ACK_NUM}; Flags: {flags} "
class UDP:
    ID = 0x11
    def __init__(self, data):
        SOURCE_PORT, DEST_PORT, LEN, CHKSUM, PAYLOAD = self.udp_head(data)
        self.SRC_PORT = SOURCE_PORT
        self.DST_PORT = DEST_PORT
        self.LENGTH = LEN
        self.CHKSUM = CHKSUM
        self.PAYLOAD = PAYLOAD

    def udp_head(self, data):
        """Unpack the UDP header from the data."""
        SRC_PORT, DST_PORT, LENGTH, CHKSUM = struct.unpack('! H H H H', data[:8])
        return SRC_PORT, DST_PORT, LENGTH, CHKSUM, data[8:]

    def parse_udp(self):
        """Return a string representation of the UDP packet."""
        return f" UDP - Source Port: {self.SRC_PORT}; Destination Port: {self.DST_PORT}; Length: {self.LENGTH}"
