import scapy.all as scapy
import sqlite3
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from mpl_toolkits.mplot3d import Axes3D
import time

# Initialize database
conn = sqlite3.connect("ids_logs.db")
cursor = conn.cursor()
cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        alert_message TEXT
    )
""")
conn.commit()

SIGNATURES = {
    "TCP": {80: "HTTP Attack", 23: "Telnet Bruteforce"},
    "UDP": {53: "DNS Attack"},
    "ICMP": {8: "Ping Flood"}
}

def log_alert(timestamp, src_ip, dst_ip, protocol, alert_msg):
    cursor.execute("""
        INSERT INTO alerts (timestamp, source_ip, destination_ip, protocol, alert_message)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, src_ip, dst_ip, protocol, alert_msg))
    conn.commit()
    print(f"[ALERT] {alert_msg} from {src_ip} to {dst_ip} at {timestamp}")

def packet_callback(packet):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = "UNKNOWN"
        alert_msg = ""

        if packet.haslayer(scapy.TCP):
            protocol = "TCP"
            port = packet[scapy.TCP].dport
            alert_msg = SIGNATURES.get("TCP", {}).get(port, "")
        elif packet.haslayer(scapy.UDP):
            protocol = "UDP"
            port = packet[scapy.UDP].dport
            alert_msg = SIGNATURES.get("UDP", {}).get(port, "")
        elif packet.haslayer(scapy.ICMP):
            protocol = "ICMP"
            icmp_type = packet[scapy.ICMP].type
            alert_msg = SIGNATURES.get("ICMP", {}).get(icmp_type, "")

        if alert_msg:
            log_alert(timestamp, src_ip, dst_ip, protocol, alert_msg)

def display_alerts_table():
    cursor.execute("SELECT * FROM alerts")
    data = cursor.fetchall()
    df = pd.DataFrame(data, columns=["ID", "Timestamp", "Source IP", "Destination IP", "Protocol", "Alert Message"])
    print("\nDetected Alerts:")
    print(df.to_string(index=False))

def visualize_alerts():
    cursor.execute("SELECT protocol, COUNT(*) FROM alerts GROUP BY protocol")
    data = cursor.fetchall()
    
    if not data:
        print("No alerts recorded.")
        return
    
    protocols = [item[0] for item in data]
    counts = [item[1] for item in data]
    xpos = np.arange(len(protocols))
    
    fig = plt.figure(figsize=(12, 6))
    ax = fig.add_subplot(111, projection='3d')
    ax.bar(xpos, counts, zs=0, zdir='y', alpha=0.9, color='royalblue')
    
    ax.set_xlabel('Protocol', fontsize=12)
    ax.set_ylabel('Alert Count', fontsize=12)
    ax.set_zlabel('Frequency', fontsize=12)
    ax.set_xticks(xpos)
    ax.set_xticklabels(protocols, fontsize=10)
    ax.set_title('3D IDS Alerts Visualization', fontsize=14, fontweight='bold')
    
    plt.show()

if __name__ == "__main__":
    print("Starting IDS...")
    try:
        scapy.sniff(prn=packet_callback, store=False, timeout=10)
    except KeyboardInterrupt:
        print("Stopping IDS...")
    finally:
        display_alerts_table()
        visualize_alerts()
        conn.close()
