import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP
import threading
import datetime

rules = []
log_file = "firewall_log.txt"
running = False

def log_packet(packet, action):
    with open(log_file, "a") as f:
        f.write(f"{datetime.datetime.now()} - {action} - {packet.summary()}\n")

def check_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0

        for rule in rules:
            rule_ip, rule_port, rule_proto, action = rule
            if (rule_ip == src or rule_ip == "ANY") and (rule_port == port or rule_port == "ANY") and (rule_proto == proto or rule_proto == "ANY"):
                log_packet(packet, action)
                return action
        log_packet(packet, "ALLOWED")

def start_sniffing():
    global running
    running = True
    sniff(prn=check_packet, store=0, stop_filter=lambda x: not running)

def start_firewall():
    thread = threading.Thread(target=start_sniffing)
    thread.daemon = True
    thread.start()
    messagebox.showinfo("Firewall", "Firewall Started")

def stop_firewall():
    global running
    running = False
    messagebox.showinfo("Firewall", "Firewall Stopped")

def add_rule():
    ip = ip_entry.get()
    port = port_entry.get()
    proto = proto_entry.get().upper()
    action = action_entry.get().upper()

    if port != "ANY":
        port = int(port)

    rules.append((ip, port, proto, action))
    rule_list.insert(tk.END, f"{ip} | {port} | {proto} | {action}")

# GUI
root = tk.Tk()
root.title("Personal Firewall")
root.geometry("500x400")

tk.Label(root, text="IP Address (or ANY)").pack()
ip_entry = tk.Entry(root)
ip_entry.pack()

tk.Label(root, text="Port (or ANY)").pack()
port_entry = tk.Entry(root)
port_entry.pack()

tk.Label(root, text="Protocol (TCP/UDP/ANY)").pack()
proto_entry = tk.Entry(root)
proto_entry.pack()

tk.Label(root, text="Action (ALLOW/BLOCK)").pack()
action_entry = tk.Entry(root)
action_entry.pack()

tk.Button(root, text="Add Rule", command=add_rule).pack()

rule_list = tk.Listbox(root, width=60)
rule_list.pack()

tk.Button(root, text="Start Firewall", command=start_firewall).pack()
tk.Button(root, text="Stop Firewall", command=stop_firewall).pack()

root.mainloop()