import nmap
import socket

def get_local_ip():
    """Get the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Could not get local IP: {e}")
        return "127.0.0.1"

def scan_host(ip):
    """Scan the host using Nmap and look for vulnerabilities."""
    print(f"\n[+] Scanning {ip} for open ports and known vulnerabilities...\n")
    scanner = nmap.PortScanner()

    try:
        # -sV: probe open ports to determine service/version info
        # --script vuln: run Nmap vulnerability detection scripts
        scanner.scan(hosts=ip, arguments='-sV --script vuln')

        for host in scanner.all_hosts():
            print(f"Host: {host} ({scanner[host].hostname()})")
            print(f"State: {scanner[host].state()}")

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].keys()
                for port in sorted(ports):
                    service = scanner[host][proto][port]
                    print(f"\nPort: {port}/{proto}")
                    print(f"Service: {service['name']} | Product: {service.get('product', 'N/A')}")

                    # Print any script outputs (vulnerabilities)
                    if 'script' in service:
                        print("[!] Vulnerabilities/Findings:")
                        for script, output in service['script'].items():
                            print(f" - {script}: {output}")

    except Exception as e:
        print(f"Scan failed: {e}")

if __name__ == "__main__":
    target_ip = get_local_ip()
    print(f"[*] Detected Local IP: {target_ip}")
    scan_host(target_ip)
