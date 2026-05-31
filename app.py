from flask import Flask, render_template, request, jsonify, send_file
from modules.subdomains import enumerate_subdomains
from modules.portscan import scan_ports
from modules.headers import check_headers
from modules.techstack import detect_tech
from modules.report import generate_report
import threading
import uuid
import os

app = Flask(__name__)

# Store scan jobs in memory (simple, no DB needed)
scan_jobs = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan/start", methods=["POST"])
def start_scan():
    data = request.get_json()
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    # Clean up target
    target = target.replace("https://", "").replace("http://", "").rstrip("/")

    job_id = str(uuid.uuid4())[:8]
    scan_jobs[job_id] = {
        "target": target,
        "status": "running",
        "results": {}
    }

    # Run scan in background thread
    thread = threading.Thread(target=run_scan, args=(job_id, target))
    thread.daemon = True
    thread.start()

    return jsonify({"job_id": job_id})


def run_scan(job_id, target):
    results = {}

    try:
        scan_jobs[job_id]["status"] = "Enumerating subdomains..."
        results["subdomains"] = enumerate_subdomains(target)

        scan_jobs[job_id]["status"] = "Scanning ports..."
        results["ports"] = scan_ports(target)

        scan_jobs[job_id]["status"] = "Checking security headers..."
        results["headers"] = check_headers(target)

        scan_jobs[job_id]["status"] = "Detecting tech stack..."
        results["tech"] = detect_tech(target)

        scan_jobs[job_id]["results"] = results
        scan_jobs[job_id]["status"] = "done"

    except Exception as e:
        scan_jobs[job_id]["status"] = "error"
        scan_jobs[job_id]["error"] = str(e)


@app.route("/scan/status/<job_id>")
def scan_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/report/<job_id>")
def download_report(job_id):
    job = scan_jobs.get(job_id)
    if not job or job["status"] != "done":
        return jsonify({"error": "Report not ready"}), 400

    path = generate_report(job_id, job["target"], job["results"])
    return send_file(path, as_attachment=True, download_name=f"recon_{job['target']}.txt")


if __name__ == "__main__":
    os.makedirs("reports", exist_ok=True)
    app.run(debug=True, port=5000)
