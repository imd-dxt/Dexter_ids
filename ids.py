from collections import defaultdict
class ARPSpoofingDetector:
    def __init__(self):
        self.arp_table = {}
        self.alert_log = []
    def detect_spoofing(self, ip, mac):
        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                self.log_alert(ip, self.arp_table[ip], mac)
        else:
            self.arp_table[ip] = mac
    def log_alert(self, ip, mac1, mac2):
        alert = f"[ALERT] ARP Spoofing Detected: IP {ip} is associated with multiple MACs: {mac1} and {mac2}"
        self.alert_logs.append(alert)
        return alert

def detect_suspicious_http(http_data):
    suspicious_keywords = ["admin", "login.php", "cmd.exe", "eval(", "base64_decode"]
    for keyword in suspicious_keywords:
        if keyword in http_data:
            return f"[ALERT] Suspicious HTTP traffic detected: {keyword}"

port_scan_tracker = defaultdict(set)

def detect_port_scan(source_ip, dest_port):
    port_scan_tracker[source_ip].add(dest_port)
    if len(port_scan_tracker[source_ip]) > 10:
        return f"[ALERT]Port scanning detected from IP {source_ip}"
    return None

ssh_attempts = defaultdict(lambda: {"failures": 0, "last_attempt_time": time.time()})

def detect_ssh_brute_force(source_ip):
    stats = ssh_attempts[source_ip]
    stats["failures"] += 1
    duration = time.time() - stats["last_attempt_time"]
    if stats["failures"] > 5 and duration < 30:
        return f"[ALERT] Potential SSH brute force detected from {source_ip} ({stats['failures']} failed attempts in {duration:.2f}s)"
    elif duration >= 30:
        # Reset tracker after 30 seconds
        ssh_attempts[source_ip] = {"failures": 0, "last_attempt_time": time.time()}
    return None