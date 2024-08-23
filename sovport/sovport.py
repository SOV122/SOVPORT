#!/usr/bin/env python3

import socket
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.progress import Progress
from scapy.all import ICMP, IP, sr1

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

def scan_ports(host, ports):
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=len(ports))
        for port in ports:
            if scan_port(host, port):
                console.print(f"[bold green]Port {port} is open.[/bold green]")
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

def save_results(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)
    console.print(f"[bold cyan]Results saved to {filename}[/bold cyan]")

def main():
    print_banner()

    host = Prompt.ask("Enter IP/Domain", default="example.com")
    scan_type = Prompt.ask("Enter scan type (port, range, subnet)", default="port")
    
    if scan_type == "port":
        port_str = Prompt.ask("Enter Port", default="80")
        try:
            port = int(port_str)
            scan_ports(host, [port])
        except ValueError:
            console.print("[bold red]Invalid port number. Please enter a valid integer.[/bold red]")
    
    elif scan_type == "range":
        start_port = int(Prompt.ask("Enter start port", default="1"))
        end_port = int(Prompt.ask("Enter end port", default="1024"))
        scan_ports(host, range(start_port, end_port + 1))

    elif scan_type == "subnet":
        network = Prompt.ask("Enter network (e.g., 192.168.1)", default="192.168.1")
        live_hosts = ping_sweep(network)
        save_results("live_hosts.json", {"hosts": live_hosts})

    else:
        console.print("[bold red]Unknown scan type. Exiting.[/bold red]")

    console.print("\n[bold cyan]Press Enter to exit...[/bold cyan]")
    input()

if __name__ == "__main__":
    main()
