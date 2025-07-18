# packet_sniffer.py
from scapy.all import sniff

def start_sniffing(interface=None, count=5, timeout=10):
    print(f"[+] Starting packet capture on interface: {interface or 'default'}")
    packets = sniff(iface=interface, count=count, timeout=timeout)
    print(f"[+] Captured {len(packets)} packets.")
    return packets