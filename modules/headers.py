import requests

# Headers that matter for bug bounty / security assessments
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS connections",
        "risk": "High"
    },
    "Content-Security-Policy": {
        "description": "Prevents XSS and injection attacks",
        "risk": "High"
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking attacks",
        "risk": "Medium"
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "risk": "Medium"
    },
    "Referrer-Policy": {
        "description": "Controls referrer information leakage",
        "risk": "Low"
    },
    "Permissions-Policy": {
        "description": "Controls browser feature access",
        "risk": "Low"
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (older browsers)",
        "risk": "Low"
    },
}

# Headers that leak server info — useful for fingerprinting
INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


def check_headers(domain):
    url = f"https://{domain}"
    fallback_url = f"http://{domain}"

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"})
    except requests.RequestException:
        try:
            resp = requests.get(fallback_url, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"})
        except requests.RequestException:
            return {"error": "Could not reach target", "missing": [], "present": [], "info_leak": []}

    response_headers = {k.lower(): v for k, v in resp.headers.items()}

    missing = []
    present = []

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() in response_headers:
            present.append({
                "header": header,
                "value": response_headers[header.lower()],
                "description": meta["description"],
                "risk": meta["risk"]
            })
        else:
            missing.append({
                "header": header,
                "description": meta["description"],
                "risk": meta["risk"]
            })

    # Check for information-leaking headers
    info_leak = []
    for h in INFO_HEADERS:
        if h.lower() in response_headers:
            info_leak.append({
                "header": h,
                "value": response_headers[h.lower()]
            })

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "missing": missing,
        "present": present,
        "info_leak": info_leak
    }
