from scapy.all import ARP, Ether, srp
import csv
from datetime import datetime
import argparse
import sys

def scan_network(ip_range, timeout=2):
    """
    Scan the network for devices using ARP requests.
    
    Args:
        ip_range (str): IP range to scan (e.g., "192.168.1.1/24")
        timeout (int): Timeout for ARP requests in seconds
        
    Returns:
        list: List of dictionaries containing device information
    """
    try:
        # Create ARP packet
        arp = ARP(pdst=ip_range)
        # Create Ethernet frame
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        # Combine packet
        packet = ether / arp

        print(f"Scanning network range: {ip_range}")
        # Send packet and capture response
        result = srp(packet, timeout=timeout, verbose=False)[0]

        devices = []
        for sent, received in result:
            devices.append({
                'IP': received.psrc,
                'MAC': received.hwsrc,
                'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return devices
    
    except Exception as e:
        print(f"Error during scanning: {str(e)}")
        return []

def export_to_csv(devices, filename):
    """
    Export the scan results to a CSV file using built-in csv module.
    
    Args:
        devices (list): List of dictionaries containing device information
        filename (str): Name of the CSV file to create
    """
    try:
        if not devices:
            print("No devices found to export")
            return

        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['IP', 'MAC', 'Timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for device in devices:
                writer.writerow(device)
        print(f"Results exported to {filename}")
    
    except Exception as e:
        print(f"Error exporting to CSV: {str(e)}")

def display_results(devices):
    """
    Display the scan results in a formatted way.
    
    Args:
        devices (list): List of dictionaries containing device information
    """
    if not devices:
        print("No devices found")
        return

    print("\nFound Devices:")
    print("-" * 60)
    print(f"{'IP Address':<15} {'MAC Address':<18} {'Timestamp':<20}")
    print("-" * 60)
    
    for device in devices:
        print(f"{device['IP']:<15} {device['MAC']:<18} {device['Timestamp']:<20}")

def main():
    parser = argparse.ArgumentParser(description='Network Scanner using ARP')
    parser.add_argument('--ip-range', type=str, default='192.168.1.1/24',
                      help='IP range to scan (default: 192.168.1.1/24)')
    parser.add_argument('--timeout', type=int, default=2,
                      help='Timeout for ARP requests in seconds (default: 2)')
    parser.add_argument('--output', type=str, default='scan_results.csv',
                      help='Output CSV file name (default: scan_results.csv)')
    
    args = parser.parse_args()

    print("Network Scanner Starting...")
    devices = scan_network(args.ip_range, args.timeout)
    display_results(devices)
    
    if devices:
        export_to_csv(devices, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")
        sys.exit(1) 