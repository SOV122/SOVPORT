#!/usr/bin/env python3

import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import json
import nmap
from scapy.all import ICMP, IP, sr1

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return port if result == 0 else None
    except Exception as e:
        return str(e)

def scan_ports(host, ports, nm, output_widget):
    for port in ports:
        result = scan_port(host, port)
        if result:
            output_widget.insert(tk.END, f"Port {port} is open.\n")
            nm.scan(hosts=host, arguments=f"-p {port} --version-all")
            service_info = nm[host]['hostnames'][0] if nm[host]['hostnames'] else 'Unknown'
            output_widget.insert(tk.END, f"Service on port {port}: {service_info}\n")
        else:
            output_widget.insert(tk.END, f"Port {port} is closed or filtered.\n")
        output_widget.update()

def ping_sweep(network, output_widget):
    live_hosts = []
    for i in range(1, 255):
        ip = f"{network}.{i}"
        packet = IP(dst=ip)/ICMP()
        try:
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                live_hosts.append(ip)
                output_widget.insert(tk.END, f"Live host found: {ip}\n")
        except PermissionError:
            messagebox.showerror("Error", "Permission error: Please run this script with elevated privileges (e.g., admin).")
            return []
        except Exception as e:
            output_widget.insert(tk.END, f"Error: {e}\n")
    return live_hosts

def detect_os(host, nm, output_widget):
    try:
        nm.scan(hosts=host, arguments="-O")
        if 'osclass' in nm[host]:
            os_info = nm[host]['osclass']
            output_widget.insert(tk.END, f"Operating System Info: {os_info}\n")
        else:
            output_widget.insert(tk.END, "OS Detection: No information available.\n")
    except Exception as e:
        output_widget.insert(tk.END, f"Error in OS detection: {e}\n")

def save_results(filename, data, output_widget):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        output_widget.insert(tk.END, f"Results saved to {filename}\n")
    except IOError as e:
        output_widget.insert(tk.END, f"Error saving file: {e}\n")

def start_scan():
    host = entry_host.get()
    scan_type = var_scan_type.get()
    nm = nmap.PortScanner()
    output_widget.delete(1.0, tk.END)

    if scan_type == "port":
        try:
            port = int(entry_port.get())
            scan_ports(host, [port], nm, output_widget)
        except ValueError:
            output_widget.insert(tk.END, "Invalid port number. Please enter a valid integer.\n")

    elif scan_type == "range":
        try:
            start_port = int(entry_start_port.get())
            end_port = int(entry_end_port.get())
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                output_widget.insert(tk.END, "Invalid port range. Ensure ports are within 1-65535 and start is less than end.\n")
            else:
                scan_ports(host, range(start_port, end_port + 1), nm, output_widget)
        except ValueError:
            output_widget.insert(tk.END, "Invalid port range. Please enter valid integers.\n")

    elif scan_type == "subnet":
        network = entry_network.get()
        if not network.replace('.', '').isdigit() or len(network.split('.')) != 3:
            output_widget.insert(tk.END, "Invalid network format. Please enter a valid network.\n")
        else:
            live_hosts = ping_sweep(network, output_widget)
            save_results("live_hosts.json", {"hosts": live_hosts}, output_widget)

    elif scan_type == "aggressive":
        try:
            scan_ports(host, range(1, 65536), nm, output_widget)
            detect_os(host, nm, output_widget)
            save_results("detailed_scan_results.json", nm.csv(), output_widget)
        except Exception as e:
            output_widget.insert(tk.END, f"Error during aggressive scan: {e}\n")

    else:
        output_widget.insert(tk.END, "Unknown scan type. Exiting.\n")

root = tk.Tk()
root.title("SOVPORT")

tk.Label(root, text="IP/Domain").grid(row=0, column=0, padx=10, pady=10, sticky='e')
entry_host = tk.Entry(root)
entry_host.grid(row=0, column=1, padx=10, pady=10)

tk.Label(root, text="Scan Type").grid(row=1, column=0, padx=10, pady=10, sticky='e')
var_scan_type = tk.StringVar(value="port")
tk.OptionMenu(root, var_scan_type, "port", "range", "subnet", "aggressive").grid(row=1, column=1, padx=10, pady=10)

tk.Label(root, text="Port").grid(row=2, column=0, padx=10, pady=10, sticky='e')
entry_port = tk.Entry(root)
entry_port.grid(row=2, column=1, padx=10, pady=10)

tk.Label(root, text="Start Port").grid(row=3, column=0, padx=10, pady=10, sticky='e')
entry_start_port = tk.Entry(root)
entry_start_port.grid(row=3, column=1, padx=10, pady=10)

tk.Label(root, text="End Port").grid(row=4, column=0, padx=10, pady=10, sticky='e')
entry_end_port = tk.Entry(root)
entry_end_port.grid(row=4, column=1, padx=10, pady=10)

tk.Label(root, text="Network").grid(row=5, column=0, padx=10, pady=10, sticky='e')
entry_network = tk.Entry(root)
entry_network.grid(row=5, column=1, padx=10, pady=10)

tk.Button(root, text="Start Scan", command=start_scan).grid(row=6, column=0, columnspan=2, pady=10)

output_widget = scrolledtext.ScrolledText(root, width=80, height=20)
output_widget.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

root.mainloop()
