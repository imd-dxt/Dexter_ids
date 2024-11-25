# Python-Based Intrusion Detection System (IDS)

This project implements a signature-based **Intrusion Detection System (IDS)** using Python. The IDS utilizes a packet sniffer to capture network traffic and detect potential malicious activities such as ARP spoofing, port scanning, brute force attacks, and suspicious HTTP traffic.

## Features
- **Packet Sniffer**: Captures and processes packets on a specified network interface.
- **ARP Spoofing Detection**: Identifies MAC address inconsistencies for the same IP address.
- **Port Scanning Detection**: Flags potential port scanning activities by monitoring the number of distinct ports accessed by a source IP.
- **SSH Brute Force Detection**: Detects repeated failed SSH login attempts from a single source IP within a short time frame.
- **Suspicious HTTP Traffic Detection**: Flags HTTP requests containing keywords associated with potential attacks (e.g., `admin`, `cmd.exe`, `eval()`).
- **Protocol Parsing**: Processes Ethernet, IPv4, TCP, UDP, and ICMP packets with detailed output.

## Prerequisites
- Python 3.x
- Libraries:
  - `struct`
  - `socket`
  - `queue`
  - `argparse`
  - `colorama`

Install the required libraries using:
```bash
pip install colorama
```
## Usage
Clone the repository:

bash
Copier le code
git clone <repository-url>
cd <repository-folder>
Run the program with the desired network interface:

bash
Copier le code
python main.py <interface>
Replace <interface> with your network interface (e.g., eth0, wlan0).

## Example:
```bash
python main.py eth0
```

## Project Structure
ids.py: Contains the detection logic for various types of network intrusions.
sniff.py: Implements the packet sniffer and protocol parsing logic.
main.py: Entry point to run the IDS. It initializes the packet sniffer.
classs.py: Defines protocol-specific classes (e.g., Ethernet, IPv4, TCP) used for parsing captured packets.
## Detection Mechanisms
1. ARP Spoofing Detection
Tracks MAC-IP associations.
Alerts when a single IP is linked to multiple MAC addresses.
2. Port Scanning Detection
Monitors the number of unique destination ports accessed by each source IP.
Flags an alert if more than 10 ports are accessed within a short time.
3. SSH Brute Force Detection
Tracks failed login attempts to port 22.
Flags an alert if more than 5 failed attempts occur from the same source IP within 30 seconds.
4. Suspicious HTTP Traffic Detection
Scans HTTP requests for malicious patterns (you can add ones in the code) such as:
admin
login.php
cmd.exe
eval(
base64_decode
## Output
The program outputs parsed network traffic and intrusion alerts in real time, using Colorama for color-coded messages:

Green: General traffic details.
Yellow: ARP and IP layer details.
Cyan: TCP/UDP/ICMP protocol details.
Red: Alerts for suspicious or malicious activities.
Limitations
The IDS operates in real-time and may drop packets under high traffic volumes due to processing limitations.
Works only with raw sockets and requires elevated permissions (run as root or administrator).
License
This project is licensed under the MIT License.

## Author
Created by *AFIF Imad*
**Contact:** imadafif.00@gmail.com
**LinkedIn:** www.linkedin.com/in/imadafif









