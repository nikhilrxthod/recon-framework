import socket
import concurrent.futures

# Common ports worth checking in bug bounty recon
COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def probe_port(host, port, service):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return {
                "port": port,
                "service": service,
                "state": "open"
            }
    except Exception:
        pass
    finally:
        sock.close()
    return None


def scan_ports(domain):
    open_ports = []

    try:
        host = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": f"Could not resolve {domain}", "open": []}

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {
            executor.submit(probe_port, host, port, service): port
            for port, service in COMMON_PORTS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    return {"host": host, "open": open_ports}
