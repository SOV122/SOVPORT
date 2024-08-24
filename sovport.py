#!/usr/bin/env python3

import socket
import json
import sys
import nmap
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress
from scapy.all import ICMP, IP, sr1
import os
import platform

console = Console()

def print_banner():
    console.print(Panel("""
  █████████     ███████   █████   ████████████████    ███████   ███████████  ███████████
 ███░░░░░███  ███░░░░░███░░███   ░░███░░███░░░░░███ ███░░░░░███░░███░░░░░███░█░░░███░░░█
░███    ░░░  ███     ░░███░███    ░███ ░███    ░██████     ░░███░███    ░███░   ░███  ░ 
░░█████████ ░███      ░███░███    ░███ ░██████████░███      ░███░██████████     ░███    
 ░░░░░░░░███░███      ░███░░███   ███  ░███░░░░░░ ░███      ░███░███░░░░░███    ░███    
 ███    ░███░░███     ███  ░░░█████░   ░███       ░░███     ███ ░███    ░███    ░███    
░░█████████  ░░░███████░     ░░███     █████       ░░░███████░  █████   █████   █████   
 ░░░░░░░░░     ░░░░░░░        ░░░     ░░░░░          ░░░░░░░   ░░░░░   ░░░░░   ░░░░░    
    """, title="SOVPORT", subtitle="Made by SOV", style="bold red"))

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            return port if result == 0 else None
    except Exception as e:
        console.print(f"[bold red]Error:[/bold red] {e}", style="bold red")
        return None

def scan_ports(host, ports, nm):
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(ports))
        for port in ports:
            if scan_port(host, port):
                console.print(f"[bold green]Port {port} is open.[/bold green]")
                nm.scan(hosts=host, arguments=f"-p {port} --version-all")
                if 'scan' in nm.all_hosts():
                    service_info = nm.csv().splitlines()[1].split(',')[2]
                    console.print(f"[bold cyan]Service on port {port}: {service_info}[/bold cyan]")
            else:
                console.print(f"[bold red]Port {port} is closed or filtered.[/bold red]")
            progress.update(task, advance=1)

def ping_sweep(network):
    live_hosts = []
    for i in range(1, 255):
        ip = f"{network}.{i}"
        packet = IP(dst=ip)/ICMP()
        try:
            response = sr1(packet, timeout=1, verbose=False)
            if response:
                live_hosts.append(ip)
                console.print(f"[bold green]Live host found: {ip}[/bold green]")
        except PermissionError:
            console.print("[bold red]Permission error: Please run this script with elevated privileges (e.g., sudo).[/bold red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] {e}", style="bold red")
    return live_hosts

def detect_os(host, nm):
    try:
        nm.scan(hosts=host, arguments="-O")
        if 'osclass' in nm[host]:
            os_info = nm[host]['osclass']
            console.print(f"[bold cyan]Operating System Info: {os_info}[/bold cyan]")
        else:
            console.print(f"[bold red]OS Detection: No information available.[/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error in OS detection:[/bold red] {e}", style="bold red")

def save_results(filename, data):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        console.print(f"[bold cyan]Results saved to {filename}[/bold cyan]")
    except IOError as e:
        console.print(f"[bold red]Error saving file:[/bold red] {e}", style="bold red")

def main():
    if platform.system() == 'Windows':
        os.system('cls')
    else:
        os.system('clear')
    
    print_banner()

    host = Prompt.ask("Enter IP/Domain", default="example.com")
    scan_type = Prompt.ask("Enter scan type (port, range, subnet, aggressive)", default="port")
    
    nm = nmap.PortScanner()

    if scan_type == "port":
        port_str = Prompt.ask("Enter Port", default="80")
        try:
            port = int(port_str)
            scan_ports(host, [port], nm)
        except ValueError:
            console.print("[bold red]Invalid port number. Please enter a valid integer.[/bold red]")
    
    elif scan_type == "range":
        try:
            start_port = int(Prompt.ask("Enter start port", default="1"))
            end_port = int(Prompt.ask("Enter end port", default="65535"))
            if start_port < 1 or end_port > 65535 or start_port > end_port:
                console.print("[bold red]Invalid port range. Ensure ports are within 1-65535 and start is less than end.[/bold red]")
            else:
                scan_ports(host, range(start_port, end_port + 1), nm)
        except ValueError:
            console.print("[bold red]Invalid port range. Please enter valid integers.[/bold red]")

    elif scan_type == "subnet":
        network = Prompt.ask("Enter network (e.g., 192.168.1)", default="192.168.1")
        if not network.replace('.', '').isdigit() or len(network.split('.')) != 3:
            console.print("[bold red]Invalid network format. Please enter a valid network.[/bold red]")
        else:
            live_hosts = ping_sweep(network)
            save_results("live_hosts.json", {"hosts": live_hosts})

    elif scan_type == "aggressive":
        try:
            scan_ports(host, range(1, 65536), nm)
            detect_os(host, nm)
            save_results("detailed_scan_results.json", nm.csv())
        except Exception as e:
            console.print(f"[bold red]Error during aggressive scan:[/bold red] {e}", style="bold red}")

    else:
        console.print("[bold red]Unknown scan type. Exiting.[/bold red]")

    console.print("\n[bold cyan]Press Enter to exit...[/bold cyan]")
    input()

if __name__ == "__main__":
    main()
