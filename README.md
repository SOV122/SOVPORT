# SOVPORT

SOVPORT is a network scanning tool designed to perform various types of scans on IP addresses and networks. It includes functionalities such as port scanning, subnet scanning, and OS detection, and it presents results in a user-friendly format using the `rich` library for terminal graphics.

## Features

- **Port Scanning:** Scan specific ports or a range of ports.
- **Subnet Scanning:** Perform a ping sweep to identify live hosts in a subnet.
- **OS Detection:** Basic OS detection using Nmap.
- **Interactive UI:** User-friendly terminal interface using `rich` and `dialog`.

## Requirements

Before running the script, you need to install the following dependencies:

- `scapy` for network packet manipulation.
- `rich` for terminal graphics.
- `python-nmap` for interfacing with Nmap.

## Installation

To install the necessary dependencies, use the provided `install.sh` script:

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/your-repository.git
   cd your-repository
