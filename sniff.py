import socket
import struct
import sys
import argparse
from classs import EthernetFrame

def get_args():
    parser = argparse.ArgumentParser(description="A simple network sniffer")
    parser.add_argument('interface', help="Network interface to sniff on")
    return parser.parse_args()
    

def main(interface):
   ETH_P_ALL = 0x03
   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
   s.bind((interface,0))
   while True:
      raw_data, addr = s.recvfrom(65530)
      eth = EthernetFrame(raw_data)
      print(f"[ Ethernet - {eth.ETHER_TYPE}; Source: {eth.SOURCE}; Dest: {eth.DESTINATION}; Data: {eth.Data} ]")
      ipv4_info = eth.parse_ipv4()
      if eth.ETHER_TYPE == EthernetFrame.ID:
            print("IPv4 Packet:")
            print(f"  - Version: {eth.VERSION}")
            print(f"  - Header Length: {eth.IHL * 4} bytes")
            print(f"  - Total Length: {eth.LENGTH}")
            print(f"  - TTL: {eth.TTL}")
            print(f"  - Protocol: {eth.PROTOCOL}")
            print(f"  - Source IP: {eth.ipv4_to_str(eth.SOURCE)}")
            print(f"  - Destination IP: {eth.ipv4_to_str(eth.DESTINATION)}")
            print(f"  - Payload: {eth.PAYLOAD[:20]}...")  # Print a snippet of the payload for brevity

      print("-" * 50)  # Divider between packets
if __name__ == "__main__":
   args=get_args()
   main(args.interface)

