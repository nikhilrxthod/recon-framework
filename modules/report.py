import os
from datetime import datetime


def generate_report(job_id, target, results):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = []

    lines.append("=" * 60)
    lines.append("  BUG BOUNTY RECON FRAMEWORK — SCAN REPORT")
    lines.append("=" * 60)
    lines.append(f"  Author    : Nikhil Sahu")
    lines.append(f"  Target    : {target}")
    lines.append(f"  Job ID    : {job_id}")
    lines.append(f"  Timestamp : {timestamp}")
    lines.append("=" * 60)
    lines.append("")

    # ── Subdomains
    lines.append("[1] SUBDOMAIN ENUMERATION")
    lines.append("-" * 40)
    subs = results.get("subdomains", [])
    if isinstance(subs, list) and subs:
        lines.append(f"  Found {len(subs)} live subdomain(s):\n")
        for s in subs:
            lines.append(f"  {s['subdomain']:<40} {s['ip']}")
    else:
        lines.append("  No subdomains found.")
    lines.append("")

    # ── Ports
    lines.append("[2] PORT SCAN")
    lines.append("-" * 40)
    ports = results.get("ports", {})
    if "error" in ports:
        lines.append(f"  Error: {ports['error']}")
    else:
        open_ports = ports.get("open", [])
        lines.append(f"  Host : {ports.get('host', target)}")
        lines.append(f"  Open : {len(open_ports)} port(s)\n")
        for p in open_ports:
            lines.append(f"  {p['port']:<8} {p['service']:<20} {p['state']}")
        if not open_ports:
            lines.append("  No common ports found open.")
    lines.append("")

    # ── Headers
    lines.append("[3] SECURITY HEADERS")
    lines.append("-" * 40)
    headers = results.get("headers", {})
    if "error" in headers:
        lines.append(f"  Error: {headers['error']}")
    else:
        missing = headers.get("missing", [])
        present = headers.get("present", [])
        info_leak = headers.get("info_leak", [])
        lines.append(f"  Present : {len(present)} header(s)")
        lines.append(f"  Missing : {len(missing)} header(s)\n")

        if missing:
            lines.append("  MISSING (potential findings):")
            for h in missing:
                lines.append(f"    [{h['risk']}] {h['header']} — {h['description']}")

        if info_leak:
            lines.append("\n  INFO LEAKAGE:")
            for h in info_leak:
                lines.append(f"    {h['header']}: {h['value']}")
    lines.append("")

    # ── Tech Stack
    lines.append("[4] TECH STACK DETECTION")
    lines.append("-" * 40)
    tech = results.get("tech", {})
    if "error" in tech:
        lines.append(f"  Error: {tech['error']}")
    else:
        detected = tech.get("detected", [])
        if detected:
            lines.append(f"  Detected ({len(detected)}):")
            for t in detected:
                lines.append(f"    - {t}")
        else:
            lines.append("  No known technologies detected.")
    lines.append("")

    lines.append("=" * 60)
    lines.append("  End of Report")
    lines.append("=" * 60)

    report_text = "\n".join(lines)
    path = os.path.join("reports", f"recon_{job_id}_{target}.txt")
    os.makedirs("reports", exist_ok=True)
    with open(path, "w") as f:
        f.write(report_text)

    return path
