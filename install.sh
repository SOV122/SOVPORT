#!/bin/bash

show_progress() {
    (
        for i in $(seq 1 100); do
            sleep 0.05
            echo $i
        done
    ) | dialog --gauge "Installing dependencies, please wait..." 10 70 0
}

install_python_packages() {
    echo "Installing Python packages..."
    pip install scapy rich python-nmap
}

install_system_packages() {
    echo "Installing system packages..."
    sudo apt-get update
    sudo apt-get install -y dialog python3-pip python3-tk
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        dialog --title "Error" --msgbox "This script must be run as root. Please run with sudo." 6 40
        exit 1
    fi
}

check_root
install_system_packages
install_python_packages
show_progress
dialog --title "Installation Complete" --msgbox "All required packages have been installed successfully!" 6 40
clear
