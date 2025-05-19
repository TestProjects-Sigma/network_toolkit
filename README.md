# Network Toolkit

A comprehensive network troubleshooting toolkit with a graphical user interface built using Python and CustomTkinter.

## Overview

Network Toolkit is a desktop application designed for system administrators and IT professionals to quickly diagnose and troubleshoot network issues. It provides a user-friendly interface for common network utilities.

## Features

Currently implemented:
- **Ping**: Test connectivity to hosts
- **DNS Lookup**: Query DNS records with optional custom DNS servers

Coming soon:
- Traceroute
- Speed Test
- WHOIS Lookup

## Installation

### Prerequisites

- Python 3.8+ installed
- Git (optional, for cloning the repository)

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
pip install customtkinter==5.2.1 ping3==4.0.3 dnspython==2.4.0 speedtest-cli==2.1.3 python-whois==0.8.0
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
    │   └── dns_lookup.py       # DNS lookup functionality
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

## Development

This project uses a modular architecture for easy expansion:

- The GUI is built with CustomTkinter for modern appearance
- Each network tool is implemented in its own module
- Logging is implemented for debugging and tracking
- Threading is used to keep the UI responsive during operations

## License

This project is licensed under the MIT License - see the LICENSE file for details.
