import sys
 import argparse 
import json
 from scapy.all import IP, TCP, ICMP, sr1
def ping_sweep(target): print(f"[*] Searching for active hosts in: {target} ...") active_hosts = []
ip_packet = IP(dst=target)/ICMP()
response = sr1(ip_packet, timeout=1, verbose=0)

if response:
    active_hosts.append({'ip': target, 'mac': 'N/A (Cloud/Routed)'})
else:
    active_hosts.append({'ip': target, 'mac': 'N/A'})
    
return active_hosts
def scan_ports(ip, ports): 
  port_results = {} 
  for port in ports: 
    syn_packet = IP(dst=ip)/TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)
    if response is None:
        port_results[port] = "Filtered"
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            rst_packet = IP(dst=ip)/TCP(dport=port, flags="R")
            sr1(rst_packet, timeout=1, verbose=0)
            port_results[port] = "Open"
        elif response.getlayer(TCP).flags == 0x14:
            port_results[port] = "Closed"
        else:
            port_results[port] = "Filtered"
    else:
        port_results[port] = "Filtered"
return port_results
def main(): parser = argparse.ArgumentParser(description="Network Reconnaissance Tool using Scapy") parser.add_argument("-t", "--target", required=True, help="Target IP address") parser.add_argument("-p", "--ports", default="22,80,443", help="Ports to scan (e.g. 22,80,443)") parser.add_argument("-o", "--output", help="Output JSON file name")
args = parser.parse_args()

try:
    ports_list = [int(p.strip()) for p in args.ports.split(",")]
except ValueError:
    print("[!] Error: Invalid port numbers.")
    sys.exit(1)

hosts = ping_sweep(args.target)

results = []
for host in hosts:
    print(f"[*] Scanning ports for {host['ip']}...")
    host['ports'] = scan_ports(host['ip'], ports_list)
    results.append(host)

print("\n" + "="*40)
print("           SCAN RESULTS           ")
print("="*40)
for item in results:
    print(f"\nHost: {item['ip']}")
    for port, status in item['ports'].items():
        print(f"  Port {port:<5} : {status}")

if args.output:
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Results successfully saved to {args.output}")
if name == "main": main()
