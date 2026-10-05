import sys
import csv
import json
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from scapy.all import Ether, ARP, IP, TCP, ICMP, srp, sr1, send, conf

SERVICES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"}


def guess_os(ttl):
    if ttl is None:
        return "Unknown"
    if ttl <= 64:
        return "Linux/Unix"
    if ttl <= 128:
        return "Windows"
    return "Network device"


def arp_scan(subnet):
    print(f"[*] ARP scan: {subnet}")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(pkt, timeout=2, verbose=0)
    return [{"ip": r.psrc, "mac": r.hwsrc, "os": "Unknown"} for _, r in answered]


def probe_host(ip):
    r = sr1(IP(dst=ip) / ICMP(), timeout=1, verbose=0)
    if r is None:
        return None
    return {"ip": ip, "mac": "N/A", "os": guess_os(r[IP].ttl)}


def ping_sweep(target):
    print(f"[*] Ping sweep: {target}")
    net = ipaddress.ip_network(target, strict=False)
    ips = [str(i) for i in (list(net.hosts()) or [net.network_address])]
    with ThreadPoolExecutor(max_workers=50) as ex:
        results = list(ex.map(probe_host, ips))
    return [h for h in results if h]


def scan_port(ip, port):
    r = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=0)
    if r is None:
        return port, "Filtered"
    if r.haslayer(TCP):
        flags = int(r[TCP].flags)
        if flags & 0x12 == 0x12:
            send(IP(dst=ip) / TCP(sport=r[TCP].dport, dport=port,
                                  seq=r[TCP].ack, flags="R"), verbose=0)
            return port, "Open"
        if flags & 0x04:
            return port, "Closed"
    return port, "Filtered"


def scan_ports(ip, ports):
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(lambda p: scan_port(ip, p), ports))
    return dict(sorted(results))


def print_table(hosts):
    print(f"\n{'IP':<16}{'MAC':<20}{'OS guess':<16}Open ports")
    print("-" * 70)
    for h in hosts:
        op = [f"{p}/{SERVICES.get(p, '?')}" for p, s in h["ports"].items() if s == "Open"]
        print(f"{h['ip']:<16}{h['mac']:<20}{h['os']:<16}{', '.join(op) or '-'}")
    print()
    for h in hosts:
        print(f"Host: {h['ip']}")
        for p, s in h["ports"].items():
            print(f"  Port {p:<6}: {s}")


def save_csv(hosts, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["ip", "mac", "os", "port", "state"])
        for h in hosts:
            for p, s in h["ports"].items():
                w.writerow([h["ip"], h["mac"], h["os"], p, s])


def parse_ports(text):
    ports = []
    for part in text.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    if not ports or not all(1 <= p <= 65535 for p in ports):
        raise ValueError("bad port")
    return ports


def main():
    ap = argparse.ArgumentParser(
        description="Network Reconnaissance Tool using Scapy (authorized networks only)",
        epilog="Example: sudo python3 Scanner.py -t 192.168.1.0/24 -p 22,80,443 -o results.json")
    ap.add_argument("-t", "--target", required=True, help="IP or subnet, e.g. 192.168.1.0/24")
    ap.add_argument("-p", "--ports", default="22,80,443", help="e.g. 22,80,443 or 1-1024")
    ap.add_argument("-o", "--output", help="save to .json or .csv")
    ap.add_argument("--mode", choices=["icmp", "arp"], default="icmp",
                    help="host discovery method (default: icmp)")
    args = ap.parse_args()

    try:
        ipaddress.ip_network(args.target, strict=False)
        ports = parse_ports(args.ports)
    except ValueError:
        print("[!] Invalid target or ports")
        sys.exit(1)

    if args.target.startswith("127."):
        try:
            from scapy.arch.linux import L3RawSocket
            conf.L3socket = L3RawSocket
        except ImportError:
            pass

    hosts = arp_scan(args.target) if args.mode == "arp" else ping_sweep(args.target)
    if not hosts:
        print("[!] No hosts responded")
        sys.exit(0)

    for h in hosts:
        h["ports"] = scan_ports(h["ip"], ports)
    print_table(hosts)

    if args.output:
        if args.output.endswith(".csv"):
            save_csv(hosts, args.output)
        else:
            with open(args.output, "w") as f:
                json.dump(hosts, f, indent=2)
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
