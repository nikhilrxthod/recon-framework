import requests
import re

# Fingerprints — header values, cookies, HTML patterns
FINGERPRINTS = {
    "WordPress":     {"html": [r"wp-content", r"wp-includes"], "headers": {}},
    "Joomla":        {"html": [r"/components/com_"], "headers": {}},
    "Drupal":        {"html": [r"Drupal.settings", r"/sites/default/files/"], "headers": {"X-Generator": r"Drupal"}},
    "Django":        {"html": [], "headers": {"X-Frame-Options": r"SAMEORIGIN"}, "cookies": ["csrftoken"]},
    "Laravel":       {"html": [], "headers": {}, "cookies": ["laravel_session"]},
    "Ruby on Rails": {"html": [], "headers": {"X-Runtime": r"\d+\.\d+"}},
    "ASP.NET":       {"html": [r"__VIEWSTATE", r"__EVENTVALIDATION"], "headers": {"X-AspNet-Version": r".+"}},
    "PHP":           {"html": [], "headers": {"X-Powered-By": r"PHP"}},
    "Node.js":       {"html": [], "headers": {"X-Powered-By": r"Express"}},
    "Nginx":         {"html": [], "headers": {"Server": r"nginx"}},
    "Apache":        {"html": [], "headers": {"Server": r"Apache"}},
    "Cloudflare":    {"html": [], "headers": {"CF-Ray": r".+", "Server": r"cloudflare"}},
    "AWS":           {"html": [], "headers": {"Server": r"AmazonS3|awselb"}},
    "Bootstrap":     {"html": [r"bootstrap\.min\.css", r"bootstrap\.css"]},
    "jQuery":        {"html": [r"jquery\.min\.js", r"jquery-\d"]},
    "React":         {"html": [r"react\.js", r"react-dom", r"__reactFiber"]},
    "Vue.js":        {"html": [r"vue\.min\.js", r"__vue__"]},
    "Angular":       {"html": [r"ng-version", r"angular\.min\.js"]},
}


def detect_tech(domain):
    url = f"https://{domain}"
    fallback = f"http://{domain}"
    detected = []

    try:
        resp = requests.get(url, timeout=8, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"})
    except requests.RequestException:
        try:
            resp = requests.get(fallback, timeout=8, allow_redirects=True,
                                headers={"User-Agent": "Mozilla/5.0 (ReconFramework)"})
        except requests.RequestException:
            return {"error": "Could not reach target", "detected": []}

    html = resp.text
    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = list(resp.cookies.keys())

    for tech, fp in FINGERPRINTS.items():
        matched = False

        # Check HTML patterns
        for pattern in fp.get("html", []):
            if re.search(pattern, html, re.IGNORECASE):
                matched = True
                break

        # Check response headers
        if not matched:
            for header, pattern in fp.get("headers", {}).items():
                if header.lower() in headers:
                    if re.search(pattern, headers[header.lower()], re.IGNORECASE):
                        matched = True
                        break

        # Check cookies
        if not matched:
            for cookie in fp.get("cookies", []):
                if cookie in cookies:
                    matched = True
                    break

        if matched:
            detected.append(tech)

    return {"detected": detected, "total": len(detected)}
