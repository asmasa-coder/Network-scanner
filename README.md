# Network Scanner (Scapy)

A basic network reconnaissance tool built with Python and Scapy.
For educational use only. Scan only networks you are authorized to test.

## Features
- Host discovery: ICMP ping sweep or ARP scan
- TCP SYN port scanning (Open / Closed / Filtered)
- Service names and OS guess (from TTL)
- Multithreaded scanning
- Results as a table, JSON or CSV

## Install
pip install scapy

## Usage
sudo python3 Scanner.py -t 192.168.1.0/24 -p 22,80,443 -o results.json

Options:
- -t  target IP or subnet
- -p  ports (22,80 or 1-1024)
- -o  output file (.json or .csv)
- --mode  icmp (default) or arp

## Testing
Tested in GitHub Codespaces on 127.0.0.1 with a local HTTP server on port 80:
port 80 detected as Open, ports 22 and 443 as Closed.
Invalid IPs and ports are rejected with an error message.
ARP mode needs a real local network.
