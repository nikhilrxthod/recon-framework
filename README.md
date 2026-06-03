# Bug Bounty Recon Framework

A lightweight web-based reconnaissance tool built for bug bounty hunting and penetration testing. Enter a target domain and get subdomain enumeration, port scanning, security header analysis, and tech stack detection — all in one dashboard.

Built from the workflow I developed during 3 years of bug bounty hunting on HackerOne.

![screenshot](screenshot.png)

---

## Features

- **Subdomain Enumeration** — multi-threaded DNS brute-force using a curated wordlist
- **Port Scanner** — checks 20 common ports (HTTP, SSH, RDP, MySQL, Redis, MongoDB, etc.)
- **Security Header Analysis** — detects missing headers (CSP, HSTS, X-Frame-Options, etc.) and info-leaking headers (Server, X-Powered-By)
- **Tech Stack Detection** — fingerprints CMS, frameworks, CDNs, and JS libraries via headers + HTML patterns
- **Report Export** — download a full `.txt` report of the scan

---

## Project Structure

```
recon-framework/
├── app.py                  # Flask app + routing
├── requirements.txt
├── README.md
├── modules/
│   ├── subdomains.py       # DNS subdomain enumeration
│   ├── portscan.py         # TCP port scanner
│   ├── headers.py          # HTTP security header checker
│   ├── techstack.py        # Technology fingerprinting
│   └── report.py           # Report generator
├── templates/
│   └── index.html          # Dashboard UI
└── reports/                # Saved scan reports (auto-created)
```

---

## Installation

```bash
git clone https://github.com/nikhilrxthod/recon-framework.git
cd recon-framework
pip install -r requirements.txt
python app.py
```

Then open your browser at: `http://localhost:5000`

---

## Usage

1. Enter a target domain (e.g. `example.com`) — no `http://` needed
2. Click **Start Scan**
3. Wait for each module to complete (status updates live)
4. Review results in the dashboard
5. Click **Download Report** to save a `.txt` report

---

## How Each Module Works

### Subdomain Enumeration
Resolves 60+ common subdomain prefixes (`www`, `api`, `dev`, `admin`, `mail`, etc.) against the target using `socket.gethostbyname()`. Multi-threaded with 30 workers for speed.

### Port Scanner
Probes 20 common ports using raw TCP sockets (`connect_ex`). Includes ports relevant to bug bounty: 8080, 9200 (Elasticsearch), 6379 (Redis), 27017 (MongoDB), 5432 (PostgreSQL).

### Security Headers
Makes an HTTP request and checks response headers against OWASP recommendations. Flags missing headers by risk level (High/Medium/Low) and detects information-leaking headers like `Server` and `X-Powered-By`.

### Tech Stack Detection
Fingerprints the target using a combination of response headers, HTML patterns, and cookie names. Detects WordPress, Django, Laravel, React, Nginx, Cloudflare, and 15+ more.

---

## Disclaimer

This tool is for educational purposes and authorized security testing only. Only scan targets you have permission to test. Unauthorized scanning may be illegal.

---

## Author

**Nikhil Sahu**

- GitHub: [github.com/nikhilrxthod](https://github.com/heynick1337)
- LinkedIn: [linkedin.com/in/sahunikhil01](https://linkedin.com/in/sahunikhil01)
