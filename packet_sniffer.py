from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import datetime
from collections import defaultdict

# Database setup
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    time TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER
)
""")
conn.commit()

# Detection data
port_scan = defaultdict(set)
flood_count = defaultdict(int)

PORT_SCAN_THRESHOLD = 10
FLOOD_THRESHOLD = 20

def alert(msg):
    print("[ALERT]", msg)
    with open("alerts.log", "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def process_packet(packet):
    if IP in packet:
        time = str(datetime.datetime.now())
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)

        protocol = "OTHER"
        src_port = 0
        dst_port = 0

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        # Store in DB
        cursor.execute("INSERT INTO packets VALUES (?,?,?,?,?,?,?)",
                       (time, src_ip, dst_ip, protocol, src_port, dst_port, length))
        conn.commit()

        # Port scan detection
        port_scan[src_ip].add(dst_port)
        if len(port_scan[src_ip]) > PORT_SCAN_THRESHOLD:
            alert(f"Port scan detected from {src_ip}")

        # Flood detection
        flood_count[src_ip] += 1
        if flood_count[src_ip] > FLOOD_THRESHOLD:
            alert(f"Flood attack detected from {src_ip}")

        print(f"{src_ip} -> {dst_ip} | {protocol} | {dst_port}")

def start_sniffer():
    print("Starting Packet Sniffer...")
    sniff(prn=process_packet, store=0)

start_sniffer()