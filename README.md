# SOVPORT

SOVPORT is a network scanning tool designed to perform various types of network scans. It includes functionalities such as port scanning, subnet scanning, and OS detection, all presented in a user-friendly terminal interface using the `rich` library.

## Features

- **Port Scanning:** Scan specific ports or a range of ports on a given host.
- **Subnet Scanning:** Perform a ping sweep to identify live hosts in a subnet.
- **OS Detection:** Basic OS detection capabilities using Nmap.
- **Interactive Terminal Interface:** User-friendly UI with `rich` and `dialog` for a better experience.

## Requirements

Before running the script, you need to install the following dependencies:

- `scapy` for network packet manipulation.
- `rich` for enhanced terminal output.
- `python-nmap` for Nmap integration.

## Installation

To install the necessary dependencies, use the provided `install.sh` script:

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/your-repository.git
   cd your-repository
