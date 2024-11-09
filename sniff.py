
import argparse
from classs import PacketSniffer

def get_args():
    parser = argparse.ArgumentParser(description="A simple network sniffer")
    parser.add_argument('interface', help="Network interface to sniff on")
    return parser.parse_args()
    

def main(interface):
    sniffer = PacketSniffer(interface)
    sniffer.start_sniff()
if __name__ == "__main__":
   args=get_args()
   main(args.interface)

