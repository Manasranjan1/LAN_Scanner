# Network Scanner

A Python-based network scanner that discovers devices on your local network using ARP requests. The scanner provides detailed information about discovered devices and can export results to CSV format.

## Features

- Scans local network for active devices
- Displays IP and MAC addresses of discovered devices
- Exports results to CSV file
- Includes timestamp for each discovered device
- Configurable scan timeout and IP range
- Command-line interface for easy usage

## Requirements

- Python 3.6 or higher
- Scapy
- Pandas

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage with default settings:
```bash
python network_scanner.py
```

Customize the scan:
```bash
python network_scanner.py --ip-range 192.168.0.1/24 --timeout 3 --output results.csv
```

### Command Line Arguments

- `--ip-range`: Specify the IP range to scan (default: 192.168.1.1/24)
- `--timeout`: Set the timeout for ARP requests in seconds (default: 2)
- `--output`: Specify the output CSV filename (default: scan_results.csv)

## Output Format

The scanner provides two types of output:
1. Console output with a formatted table of discovered devices
2. CSV file containing:
   - IP addresses
   - MAC addresses
   - Timestamp of discovery

## Note

This script requires administrative/root privileges to perform ARP scanning. Run with appropriate permissions:

Windows:
```bash
# Run PowerShell as Administrator
python network_scanner.py
```

Linux/macOS:
```bash
sudo python network_scanner.py
```

## Security Considerations

- Use this tool only on networks you own or have permission to scan
- Be aware that network scanning may be detected by security systems
- Respect privacy and legal restrictions in your jurisdiction 