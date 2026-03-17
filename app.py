import os
import csv
import io
import email
import concurrent.futures
from flask import Flask, request, render_template_string, send_file, session
from flask_session import Session
from detector import analyze_email

app = Flask(__name__)
app.secret_key = "v0rtex_secure_gate"

# Session configuration for persistence
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(app.root_path, 'flask_session')
if not os.path.exists(app.config["SESSION_FILE_DIR"]):
    os.makedirs(app.config["SESSION_FILE_DIR"])
Session(app)

# --- Updated Name in HTML ---
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>V0RTEX // THREAT_GATE</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@500;900&display=swap" rel="stylesheet">
    <style>
        body { background-color: #050505; color: #00ff41; font-family: 'JetBrains Mono', monospace; }
        .cyber-card { background-color: #0a0a0a; border: 1px solid #00ff41; box-shadow: 0 0 20px #00ff4122; padding: 25px; border-radius: 8px; margin-top: 30px; }
        .btn-cyber { background-color: #00ff41; border: none; color: #000; font-family: 'Orbitron', sans-serif; font-weight: bold; letter-spacing: 1px; }
        .table { color: #ccc; border-color: #333; }
        .badge-spoof { border: 1px solid red; color: red; padding: 5px; font-weight: bold; }
        .badge-safe { border: 1px solid #00ff41; color: #00ff41; padding: 5px; font-weight: bold; }
        .navbar-brand { font-family: 'Orbitron', sans-serif; font-weight: 900; }
    </style>
</head>
<body>
<nav class="navbar navbar-dark bg-black border-bottom border-success">
    <div class="container-fluid"><span class="navbar-brand mx-auto">🛡️ V0RTEX // THREAT_GATE</span></div>
</nav>

<div class="container cyber-card">
    <h4>>> INITIATE_BULK_SCAN</h4>
    <p class="text-secondary small">Status: System Online // Multi-threaded Mode Active</p>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="email_files" multiple accept=".eml" class="form-control bg-black text-success border-secondary mb-3">
        <button type="submit" class="btn btn-cyber w-100">RUN ASYNCHRONOUS DIAGNOSTICS</button>
    </form>

    {% if results %}
    <h4 class="mt-5">>> SCAN_RESULTS_LOG</h4>
    <div class="table-responsive">
        <table class="table table-dark table-striped mt-3">
            <thead>
                <tr><th>FILE</th><th>SUBJECT</th><th>SCORE</th><th>STATUS</th><th>INTEL</th></tr>
            </thead>
            <tbody>
            {% for r in results %}
            <tr>
                <td>{{ r.filename }}</td>
                <td>{{ r.subject }}</td>
                <td>{{ r.score }}</td>
                <td>
                    {% if r.score >= 40 %}<span class="badge-spoof">⚠️ THREAT</span>
                    {% else %}<span class="badge-safe">✅ SECURE</span>{% endif %}
                </td>
                <td>{% for x in r.reasons %}<div>> {{ x }}</div>{% endfor %}</td>
            </tr>
            {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="row mt-5">
        <div class="col-md-6"><canvas id="resultChart"></canvas></div>
        <div class="col-md-6"><canvas id="scoreChart"></canvas></div>
    </div>
    <a href="/download_csv" class="btn btn-outline-info w-100 mt-4">📥 EXPORT_FORENSIC_REPORT.CSV</a>

    <script>
        const results = {{ results|tojson }};
        const ctx1 = document.getElementById('resultChart').getContext('2d');
        const spoofCount = results.filter(r => r.score >= 40).length;
        new Chart(ctx1, {
            type: 'doughnut',
            data: {
                labels: ['THREAT DETECTED', 'SECURE'],
                datasets: [{ data: [spoofCount, results.length - spoofCount], backgroundColor: ['#ff0000', '#00ff41'], borderColor: '#000' }]
            }
        });

        const ctx2 = document.getElementById('scoreChart').getContext('2d');
        new Chart(ctx2, {
            type: 'bar',
            data: {
                labels: results.map(r => r.filename.substring(0,10)),
                datasets: [{ label: 'Threat Score', data: results.map(r => r.score), backgroundColor: '#00d2ff' }]
            }
        });
    </script>
    {% endif %}
</div>
</body>
</html>
"""

# Helper to find IP (Mentor will like this separated logic)
def extract_sender_ip(msg):
    received = msg.get_all("Received", []) or []
    import re, ipaddress
    for h in received:
        ips = re.findall(r'[0-9]{1,3}(?:\.[0-9]{1,3}){3}', h)
        for ip in ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if not ip_obj.is_private and not ip_obj.is_loopback:
                    return str(ip_obj)
            except: continue
    return "127.0.0.1"

def get_email_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload: return payload.decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload: return payload.decode(errors="ignore")
    return ""

def process_email_task(file_data):
    filename, raw_bytes = file_data
    try:
        msg = email.message_from_bytes(raw_bytes)
        body = get_email_body(msg)
        report = analyze_email(msg, body, raw_bytes)
        return {
            "filename": filename,
            "subject": msg.get("Subject", "(No Subject)"),
            "score": int(report.get("score", 0)),
            "reasons": report.get("reasons", [])
        }
    except Exception as e:
        return {"filename": filename, "label": "ERROR", "reasons": [str(e)], "score": 0}

# --- FIXED ROUTE LOGIC ---
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded_files = request.files.getlist("email_files")
        tasks = [(f.filename, f.read()) for f in uploaded_files if f.filename != ""]

        # Bulk processing upgrade
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(process_email_task, tasks))

        session["results"] = results
        # After POST, render results
        return render_template_string(HTML, results=results)

    # For GET requests (initial load), show empty results or previous session
    return render_template_string(HTML, results=session.get("results", []))

@app.route("/download_csv")
def download_csv():
    results = session.get("results", [])
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["File", "Subject", "Score", "Reasons"])
    for r in results:
        writer.writerow([r.get("filename"), r.get("subject"), r.get("score"), "; ".join(r.get("reasons", []))])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype="text/csv", as_attachment=True, download_name="threat_report.csv")

if __name__ == "__main__":
    app.run(debug=True)