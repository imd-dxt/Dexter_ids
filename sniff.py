import socket
import argparse
import struct
import sys
from classs import EthernetFrame,IPV4,TCP
from colorama import Fore,init
init()
def get_args():
    parser = argparse.ArgumentParser(description="A simple network sniffer")
    parser.add_argument('interface', help="Network interface to sniff on")
    return parser.parse_args()
    

def main(interface):
   ETH_P_ALL = 0x03
   s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
   s.bind((interface,0))
   while True:
        raw_data, addr = s.recvfrom(65535)  # Capture packet data
        eth = EthernetFrame(raw_data)  # Parse the Ethernet frame

        # Print Ethernet frame details
        print(Fore.GREEN +f"[*] Ethernet - {hex(eth.ETHER_TYPE)}; Source: {eth.SOURCE}; Dest: {eth.DESTINATION}; Data: {eth.Data[:20]}... ")

        if eth.ETHER_TYPE == IPV4.ID:
            ipv4 = IPV4(eth.Data)
            print("->" + ipv4.parse_())  # Use the parse_ method of the IPV4 instance
            if ipv4.PROTOCOL == TCP.ID:
                    tcp = TCP(ipv4.PAYLOAD)
                    print("   └─ " + tcp.parse_tcp())
                    
        print("-" * 50)  
if __name__ == "__main__":
   args=get_args()
   main(args.interface)

