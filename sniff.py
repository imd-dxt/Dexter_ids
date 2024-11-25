import struct
import time
from colorama import Fore
import threading
import socket
import queue
from ids import detect_port_scan,detect_ssh_brute_force,detect_suspicious_http,ARPSpoofingDetector
class PacketSniffer:
    def __init__(self, interface):
        self.interface = interface
        self.pckt_queue = queue.Queue()
        self.num_worker_threads = 2
        self.processing_threads = []
        self.running = True  # flag to control thread execution

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
                raw_data = self.pckt_queue.get(timeout=1)  # timeout allows thread to check the running flag
                eth = EthernetFrame(raw_data)

                print(Fore.GREEN + eth.parse_())
                self.pckt_queue.task_done()
                if eth.ETHER_TYPE == IPV4.ID:
                    ipv4 = IPV4(eth.Data)
                    arp = ARPSpoofingDetector()
                    arp_spoof = arp.detect_spoofing(ipv4.SOURCE, eth.SOURCE)
                    print(Fore.YELLOW +"->" + ipv4.parse_()) 
                    if arp_spoof:
                        print(Fore.RED + arp_spoof)
                    if ipv4.PROTOCOL == TCP.ID:
                        tcp = TCP(ipv4.PAYLOAD)
                        print(Fore.CYAN +"   └─ " + tcp.parse_tcp())
                        print(Fore.CYAN + hex_data(tcp.PAYLOAD, 5))
                        port_scan = detect_port_scan(ipv4.SOURCE,tcp.DST_PORT)
                        if tcp.DST_PORT == 22: 
                            ssh_attempts = detect_ssh_brute_force(ipv4.SOURCE)
                            if ssh_attempts:
                                print(Fore.RED + ssh_attempts)
                        elif tcp.DST_PORT == 80:
                            http_attempts = detect_suspicious_http(tcp.http_data)
                            if http_attempts:
                                print(Fore.Red + http_attempts)
                        elif port_scan :
                            print(Fore.Red + port_scan)
                    elif ipv4.PROTOCOL == UDP.ID:
                        udp = UDP(ipv4.PAYLOAD)
                        print(Fore.CYAN +"   └─ " + udp.parse_udp())
                        print(Fore.CYAN + hex_data(udp.PAYLOAD, 5))
                    elif ipv4.PROTOCOL == ICMP.ID:
                        icmp = ICMP(ipv4.PAYLOAD)
                        print(Fore.CYAN + "   └─ " + icmp.parse_icmp())
            except queue.Empty:
                pass  # allows the thread to continue checking if there are new packets
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
    IPV4_ETHERTYPE = 0x0800  

    def __init__(self, data):
        dest, src, proto, payload = self.ethernet_head(data)
        self.DESTINATION = dest
        self.SOURCE = src
        self.ETHER_TYPE = proto
        self.Data = payload
        self.http_data = ''
        self.ipv4_packet = None
        if self.ETHER_TYPE == self.IPV4_ETHERTYPE:
            self.ipv4_packet = IPV4(payload)
    def get_mac_addr(self, data):
        return ':'.join(format(byte, '02x') for byte in data)
    
    def ethernet_head(self, raw_data):

        dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
        dest_mac = self.get_mac_addr(dest)
        src_mac = self.get_mac_addr(src)
        payload = raw_data[14:]
        return dest_mac, src_mac, proto, payload
    def  parse_(self): 
        ether = hex(self.ETHER_TYPE)
        length = len(self.Data)

        return f"[*] Ethernet - {ether}; Source: {self.SOURCE}; Dest: {self.DESTINATION}; Len: {length} ]"


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
            # This line calculates the length of the options field in bytes
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
        result = f" TCP - Source Port: {self.SRC_PORT}; Destination Port: {self.DST_PORT}; Sequence: {self.SEQ_NUM}; ACK: {self.ACK_NUM}; Flags: {flags} "
        if self.SRC_PORT == 80 or self.DST_PORT == 80:
            self.http_data = self.decode_http_request()
            if self.http_data:
                result += f"\n   └─ HTTP Request: {self.http_data}"
        return result

    def decode_http_request(self):
        try:
            payload_str = self.PAYLOAD.decode('utf-8', errors='ignore')  
            if payload_str.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE')):
                headers = payload_str.split('\r\n')
                return "\n".join(headers[:5])
        except Exception as e:
            return f"Error decoding HTTP: {e}"
        return None
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
        SRC_PORT, DST_PORT, LENGTH, CHKSUM = struct.unpack('! H H H H', data[:8])
        return SRC_PORT, DST_PORT, LENGTH, CHKSUM, data[8:]

    def parse_udp(self):

        return f" UDP - Source Port: {self.SRC_PORT}; Destination Port: {self.DST_PORT}; Length: {self.LENGTH}"
class ICMP:
    ID = 1  # ICMP protocol ID

    def __init__(self, payload):
        self.Type, self.Code, self.Checksum = struct.unpack('!BBH', payload[:4])
        self.Data = payload[4:]

    def parse_icmp(self):
        type_meaning = {
            0: "Echo Reply",
            8: "Echo Request",
            3: "Destination Unreachable",
            11: "Time Exceeded"
        }
        return (f"ICMP Packet - Type: {self.Type} "
                f"({type_meaning.get(self.Type, 'Unknown')}), "
                f"Code: {self.Code}, Checksum: {self.Checksum}")
def hex_data(bytes_input,left_padding=5):
    byte_width=32
    current = 0
    end = len(bytes_input)
    result = ""

    
    while current < end:
        # byte_slice howa line lwl li ghadi itprinta
        byte_slice = bytes_input[current: current + byte_width]

        # Adds the specified number of spaces for indentation at the beginning of each line.
        result += " " * left_padding

        # hex section
        for b in byte_slice:
            result += "%02X" % b #covert each byte to 2 chars hexadecimal string
        
        #filtre
        # If byte_slice is shorter than byte_width (i.e., at the end of the input), this loop adds spaces to align the output correctly.
        for _ in range(byte_width - len(byte_slice)):
            result += " " * 3
        # The extra " " (two spaces) separates the hex section from the ASCII section.
        result += "  "

        # printable character section
        for b in byte_slice:
            if (b >=32) and (b <= 127):
                result += chr(b)
            else:
                result += "."
        result += "\n"
        current += byte_width
    return result