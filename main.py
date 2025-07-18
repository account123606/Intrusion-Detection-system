import tkinter as tk
from tkinter import ttk
from packet_sniffer import start_sniffing
from protocol_analyzer import analyze_packet
from threat_detector import ThreatDetector
from logger import log_threat
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading

# Initialize components
detector = ThreatDetector()
packets = []
threat_logs = []
def update_dashboard():
    global packets, threat_logs

    new_packets = start_sniffing(count=5)
    packets.extend(new_packets)

    for pkt in new_packets:
        pkt_info = analyze_packet(pkt)
        if pkt_info:
            threats = detector.check_packet(pkt_info)
            print("[DEBUG] Threats detected:", threats)
            for threat in threats:
                log_threat(threat)
                threat_logs.append(threat)

    update_packet_details()
    update_threat_alerts()         # <-- MUST BE HERE
    update_traffic_graph()

    root.after(2000, update_dashboard)

def update_packet_details():
    packet_list.delete(0, tk.END)
    for pkt in packets[-5:]:
        pkt_info = analyze_packet(pkt)
        if pkt_info is not None:
            src_ip = pkt_info.get('src_ip', 'Unknown')
            dst_ip = pkt_info.get('dst_ip', 'Unknown')
            proto = pkt_info.get('protocol', 'N/A')
            packet_list.insert(tk.END, f"{src_ip} → {dst_ip} ({proto})")
        else:
            packet_list.insert(tk.END, "Non-IP Packet")
def update_threat_alerts():
    threat_list.delete(0, tk.END)  # Clear existing items
    for threat in threat_logs[-10:]:  # Show up to last 10 threats
        threat_list.insert(tk.END, threat)
def update_traffic_graph():
    x_data = list(range(len(packets)))
    y_data = [len(pkt) for pkt in packets]

    ax.clear()
    ax.plot(x_data, y_data, color='green')
    ax.set_title("Real-Time Traffic")
    ax.set_xlabel("Packet Index")
    ax.set_ylabel("Size (bytes)")
    canvas.draw()

def start_monitoring():
    global packets, threat_logs
    packets = []
    threat_logs = []
    update_dashboard()

def stop_monitoring():
    pass

# Create GUI
root = tk.Tk()
root.title("Intrusion Detection System Dashboard")
root.geometry("800x600")

# Packet Details Frame
packet_frame = ttk.LabelFrame(root, text="PACKET DETAILS")
packet_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

packet_list = tk.Listbox(packet_frame, height=5)
packet_list.pack(fill=tk.BOTH, expand=True)

# Threat Alerts Frame
threat_frame = ttk.LabelFrame(root, text="THREAT ALERTS")
threat_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

threat_list = tk.Listbox(threat_frame, height=5)
threat_list.pack(fill=tk.BOTH, expand=True)

# Traffic Graph Frame
graph_frame = ttk.LabelFrame(root, text="REAL-TIME TRAFFIC")
graph_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

fig = Figure(figsize=(5, 3), dpi=100)
ax = fig.add_subplot(111)
canvas = FigureCanvasTkAgg(fig, master=graph_frame)
canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

# Control Panel
control_frame = ttk.Frame(root)
control_frame.pack(pady=10, padx=10, fill=tk.X)

start_button = ttk.Button(control_frame, text="START MONITORING", command=start_monitoring)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = ttk.Button(control_frame, text="STOP MONITORING", command=stop_monitoring)
stop_button.pack(side=tk.LEFT, padx=5)

# --- Main Function to Start GUI ---
def main():
    global threat_logs
    threat_logs = []  # Reset threat logs on start

    # 👇 Optional: Add a test threat to verify GUI works
    threat_logs.append("🚨 Test Threat Alert - This Should Show in GUI")

    # Start the Tkinter GUI loop
    root.mainloop()

if __name__ == "__main__":
    main()

# Run GUI
root.mainloop()