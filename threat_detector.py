class ThreatDetector:
    def __init__(self):
        self.ip_count = {}
        self.port_scan_attempts = {}

    def detect_dos(self, packet_info):
        src_ip = packet_info.get("src_ip")
        if src_ip:
            self.ip_count[src_ip] = self.ip_count.get(src_ip, 0) + 1
            if self.ip_count[src_ip] > 10:  # Lowered threshold
                return f"⚠️ Possible DoS attack detected from {src_ip}"
        return None

    def detect_port_scan(self, packet_info):
        src_ip = packet_info.get("src_ip")
        dport = packet_info.get("dport")

        if src_ip and dport and packet_info.get("protocol") == "TCP":
            key = src_ip
            if dport not in self.port_scan_attempts.get(key, set()):
                self.port_scan_attempts.setdefault(key, set()).add(dport)
            if len(self.port_scan_attempts[key]) > 5:  # Lowered threshold
                return f"🚨 Port scanning detected from {src_ip}"
        return None

    def check_packet(self, packet_info):
        threats = []
        dos = self.detect_dos(packet_info)
        scan = self.detect_port_scan(packet_info)
        if dos:
            threats.append(dos)
        if scan:
            threats.append(scan)
        return threats