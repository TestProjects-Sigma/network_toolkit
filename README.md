# Network Toolkit

A comprehensive network troubleshooting toolkit with a graphical user interface built using Python and CustomTkinter.

## Overview

Network Toolkit is a desktop application designed for system administrators and IT professionals to quickly diagnose and troubleshoot network issues. It provides a user-friendly interface for common network utilities.

## Features

Currently implemented:
- **Ping**: Test connectivity to hosts
- **DNS Lookup**: Query DNS records with optional custom DNS servers
- **Traceroute**: Trace network path to hosts with hop-by-hop analysis
- **Speed Test**: Measure network download and upload speeds and latency
- **WHOIS Lookup**: Retrieve domain registration information
- **Port Scanner**: Scan for open ports on a host
- **SSH Terminal**: Connect to remote servers via SSH
- **SMTP Tester**: Test email delivery and SMTP server configurations
- **Mail Header Analyzer**: Analyze email headers for authentication and routing information
- **Network Packet Analyzer**: Capture and analyze network traffic in real-time

## Installation

### Prerequisites

- Python 3.8+ installed
- Git (optional, for cloning the repository)
- Administrator/root privileges (for packet capture functionality)

### Setting up a Virtual Environment

Setting up a virtual environment is recommended to avoid conflicts with other Python projects.

#### Windows

```bash
# Navigate to the project directory
cd path\to\network_toolkit

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### macOS/Linux

```bash
# Navigate to the project directory
cd path/to/network_toolkit

# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Manual Installation (without virtual environment)

If you prefer not to use a virtual environment, you can install dependencies directly:

```bash
pip install customtkinter==5.2.1 ping3==4.0.3 dnspython==2.4.0 speedtest-cli==2.1.3 python-whois==0.8.0 paramiko==3.3.1 scapy==2.5.0
```

## Running the Application

After installing the dependencies, you can run the application with:

```bash
python main.py
```

## Project Structure

```
network_toolkit/
├── main.py                     # Main application entry point
├── requirements.txt            # Dependencies
├── config.ini                  # Configuration settings
├── README.md                   # Documentation
├── logs/                       # Log files directory
└── src/
    ├── __init__.py
    ├── gui/                    # GUI components
    │   ├── __init__.py
    │   └── main_window.py      # Main application window
    ├── tools/                  # Network tool implementations
    │   ├── __init__.py
    │   ├── ping.py             # Ping functionality
    │   ├── dns_lookup.py       # DNS lookup functionality
    │   ├── traceroute.py       # Traceroute functionality
    │   ├── speedtest.py        # Speed test functionality
    │   ├── whois_lookup.py     # WHOIS lookup functionality
    │   ├── port_scanner.py     # Port scanning functionality
    │   ├── ssh_terminal.py     # SSH terminal functionality
    │   ├── smtp_tester.py      # SMTP testing functionality
    │   ├── mail_header_analyzer.py # Email header analysis
    │   └── packet_analyzer.py  # Network packet analysis── dns_lookup.py       # DNS lookup functionality
    │   ├── traceroute.py       # Traceroute functionality
    │   ├── speedtest.py        # Speed test functionality
    │   ├── whois_lookup.py     # WHOIS lookup functionality
    │   ├── port_scanner.py     # Port scanning functionality
    │   ├── ssh_terminal.py     # SSH terminal functionality
    │   ├── smtp_tester.py      # SMTP testing functionality
    │   └── mail_header_analyzer.py # Email header analysis
    └── utils/                  # Shared utilities
        ├── __init__.py
        └── logger.py           # Logging functionality
```

## Usage

### Ping Tool

1. Click on the "Ping" button in the sidebar
2. Enter a hostname or IP address
3. Specify the number of ping packets to send
4. Click "Execute Ping"
5. View the results in the output window

### DNS Lookup Tool

1. Click on the "DNS Lookup" button in the sidebar
2. Enter a domain name
3. Select the DNS record type (A, AAAA, MX, etc.)
4. Optionally enter a custom DNS server (e.g., 8.8.8.8 for Google DNS)
5. Click "Lookup"
6. View the results in the output window

### Traceroute Tool

1. Click on the "Traceroute" button in the sidebar
2. Enter a hostname or IP address
3. Optionally adjust the maximum hops and timeout values
4. Click "Execute Traceroute"
5. View the hop-by-hop path in the output window

### Speed Test Tool

1. Click on the "Speed Test" button in the sidebar
2. Click "Start Speed Test"
3. Wait for the test to complete (progress bar shows status)
4. View your download/upload speeds and latency results

### WHOIS Lookup Tool

1. Click on the "WHOIS" button in the sidebar
2. Enter a domain name
3. Click "Lookup"
4. View the domain registration information including owner, dates, and nameservers

### Port Scanner Tool

1. Click on the "Port Scanner" button in the sidebar
2. Enter a host name or IP address
3. Select common ports using the checkboxes
4. Optionally enter custom ports in the field (comma-separated)
5. Click "Start Scan"
6. View the scan results showing open ports and services

### SSH Terminal Tool

1. Click on the "SSH Terminal" button in the sidebar
2. Enter the host, port, username, and password (or select a key file)
3. Click "Connect"
4. Once connected, use the terminal to send commands
5. View the command output in the terminal area
6. Click "Disconnect" when finished

### SMTP Tester Tool

1. Click on the "SMTP Tester" button in the sidebar
2. Enter the SMTP server details in the Connection tab
3. Configure the email message in the Message tab
4. Set security and authentication options in the Security tab
5. Click "Send Test Email"
6. View the detailed test results including connection logs

### Mail Header Analyzer Tool

1. Click on the "Header Analyzer" button in the sidebar
2. Paste email headers into the input area (or click "Load Example")
3. Click "Analyze Headers"
4. View the detailed analysis including:
   - Authentication results (SPF, DKIM, DMARC)
   - Delivery path and timing
   - Security assessment
   - Spam likelihood

### Network Packet Analyzer Tool

1. Click on the "Packet Analyzer" button in the sidebar
2. Select a network interface (or use "All Interfaces")
3. Optionally enter a filter expression (e.g., "tcp port 80" for HTTP traffic)
4. Set a packet capture limit (default: 1000)
5. Click "Start Capture" to begin monitoring
6. View captured packets in the "Packets" tab and statistics in the "Statistics" tab
7. Click "Stop Capture" when finished

## Development

This project uses a modular architecture for easy expansion:

- The GUI is built with CustomTkinter for modern appearance
- Each network tool is implemented in its own module
- Logging is implemented for debugging and tracking
- Threading is used to keep the UI responsive during operations

## License

This project is licensed under the MIT License - see the LICENSE file for details.
