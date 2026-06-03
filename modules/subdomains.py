import socket
import concurrent.futures

# Common subdomains wordlist — enough to find real stuff, not bloated
WORDLIST = [
    "www", "mail", "ftp", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "api", "dev", "stage", "portal",
    "admin", "test", "beta", "app", "cdn", "login", "auth", "dashboard",
    "static", "media", "images", "upload", "git", "gitlab", "jenkins",
    "jira", "confluence", "support", "help", "docs", "forum", "status",
    "monitor", "cms", "old", "new", "panel", "cpanel", "whm", "internal",
    "intranet", "network", "backup", "db", "database", "mysql", "phpmyadmin",
    "demo", "preview", "preprod", "prod", "staging", "uat", "qa", "v2", "v1",
    "cloud", "assets", "redirect", "mobile", "pay",
    "checkout", "crm", "erp", "smtp2", "ns3",
]


def resolve_subdomain(subdomain, domain):
    hostname = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(hostname)
        return {"subdomain": hostname, "ip": ip, "status": "live"}
    except socket.gaierror:
        return None


def enumerate_subdomains(domain):
    found = []

    # Also check the root domain
    try:
        ip = socket.gethostbyname(domain)
        found.append({"subdomain": domain, "ip": ip, "status": "live"})
    except socket.gaierror:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(resolve_subdomain, sub, domain): sub
            for sub in WORDLIST
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])
