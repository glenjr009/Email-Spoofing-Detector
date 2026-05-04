import os
import csv
import io
import email
import concurrent.futures
import time
from flask import Flask, request, render_template_string, send_file, session
from flask_session import Session
from detector import analyze_email

app = Flask(__name__)
app.secret_key = "v0rtex_secure_gate"

app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(app.root_path, 'flask_session')
if not os.path.exists(app.config["SESSION_FILE_DIR"]):
    os.makedirs(app.config["SESSION_FILE_DIR"])
Session(app)

TEST_SAMPLES_DIR = "TEST_SAMPLES"
if not os.path.exists(TEST_SAMPLES_DIR):
    os.makedirs(TEST_SAMPLES_DIR)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>V0RTEX // EMAIL_THREAT_DETECTION</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Orbitron:wght@500;900&display=swap" rel="stylesheet">
    <style>
        :root { --neon-green: #00ff41; --neon-cyan: #00d2ff; --neon-red: #ff3131; --bg-deep: #050505; }
        body { background-color: var(--bg-deep); color: #e0e0e0; font-family: 'JetBrains Mono', monospace; overflow-x: hidden; }
        .navbar { border-bottom: 1px solid var(--neon-green); background: rgba(0,0,0,0.9); backdrop-filter: blur(10px); }
        .navbar-brand { font-family: 'Orbitron', sans-serif; font-weight: 900; color: var(--neon-green) !important; text-shadow: 0 0 10px var(--neon-green); }
        .cyber-card { background: rgba(15, 15, 15, 0.8); border: 1px solid #333; border-radius: 12px; padding: 2rem; transition: all 0.3s ease; }
        .cyber-card:hover { border-color: var(--neon-green); box-shadow: 0 0 15px rgba(0, 255, 65, 0.1); }
        .section-header { font-family: 'Orbitron', sans-serif; font-size: 0.8rem; color: var(--neon-cyan); letter-spacing: 2px; margin-bottom: 1.5rem; border-left: 3px solid var(--neon-cyan); padding-left: 10px; }
        .btn-cyber { font-family: 'Orbitron', sans-serif; font-weight: bold; border-radius: 4px; padding: 12px; transition: 0.3s; border: 1px solid transparent; }
        .btn-manual { background: var(--neon-green); color: black; }
        .btn-manual:hover { background: transparent; color: var(--neon-green); border-color: var(--neon-green); box-shadow: 0 0 20px var(--neon-green); }
        .btn-auto { background: transparent; color: var(--neon-cyan); border-color: var(--neon-cyan); }
        .btn-auto:hover { background: var(--neon-cyan); color: black; box-shadow: 0 0 20px var(--neon-cyan); }
        .metric-pill { background: #111; border: 1px solid #444; padding: 10px 20px; border-radius: 50px; display: inline-block; margin-right: 10px; font-size: 0.85rem; }
        .metric-value { color: var(--neon-green); font-weight: bold; }
        .threat-row { border-left: 4px solid var(--neon-red) !important; }
        .safe-row { border-left: 4px solid var(--neon-green) !important; }
        ::-webkit-scrollbar { width: 8px; }
        ::-webkit-scrollbar-track { background: #000; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: var(--neon-green); }
    </style>
</head>
<body>

<nav class="navbar sticky-top">
    <div class="container-fluid"><span class="navbar-brand">🛡️ V0RTEX // THREAT_GATE</span></div>
</nav>

<div class="container py-5">
    <div class="row g-4 mb-5">
        <div class="col-lg-7">
            <div class="cyber-card h-100">
                <div class="section-header">MANUAL_INGESTION_MODULE</div>
                <form method="POST" action="/" enctype="multipart/form-data">
                    <input type="file" name="email_files" multiple accept=".eml" class="form-control bg-black text-white border-secondary mb-4 p-3">
                    <button type="submit" class="btn btn-cyber btn-manual w-100">RUN DIAGNOSTICS [MANUAL]</button>
                </form>
            </div>
        </div>
        <div class="col-lg-5">
            <div class="cyber-card h-100 text-center d-flex flex-column justify-content-center">
                <div class="section-header text-start">AUTOMATED_PIPELINE</div>
                <p class="text-secondary small mb-4">Ingesting data from directory: <code>/TEST_SAMPLES</code></p>
                <form method="POST" action="/auto_scan">
                    <button type="submit" class="btn btn-cyber btn-auto w-100">EXECUTE AUTO-SCAN [BATCH]</button>
                </form>
            </div>
        </div>
    </div>

    {% if results %}
    
    {% if metrics %}
    <div class="row mb-4">
        <div class="col-12">
            <div class="cyber-card p-3">
                <div class="metric-pill">TOTAL_OBJECTS: <span class="metric-value">{{ metrics.count }}</span></div>
                <div class="metric-pill">LATENCY: <span class="metric-value">{{ metrics.time }}s</span></div>
                <div class="metric-pill">THROUGHPUT: <span class="metric-value">{{ (metrics.count / metrics.time)|round(2) if metrics.time > 0 else 0 }} msg/sec</span></div>
            </div>
        </div>
    </div>
    {% endif %}

    <div class="row g-4 mb-5">
        <div class="col-md-4"><div class="cyber-card"><canvas id="resultChart"></canvas></div></div>
        <div class="col-md-4"><div class="cyber-card"><canvas id="scoreChart"></canvas></div></div>
        <div class="col-md-4"><div class="cyber-card"><canvas id="performanceChart"></canvas></div></div>
    </div>

    <div class="cyber-card">
        <div class="section-header">FORENSIC_ANALYSIS_LOGS</div>
        <div class="table-responsive">
            <table class="table table-dark table-hover align-middle">
                <thead>
                    <tr><th>OBJECT_ID</th><th>IDENTITY_SUBJECT</th><th>SCORE</th><th>RISK_LEVEL</th><th>INTEL_LOGS</th></tr>
                </thead>
                <tbody>
                {% for r in results %}
                <tr class="{% if r.score >= 40 %}threat-row{% else %}safe-row{% endif %}">
                    <td class="small text-secondary">{{ r.filename }}</td>
                    <td>{{ r.subject }}</td>
                    <td class="fw-bold">{{ r.score }}</td>
                    <td>
                        {% if r.score >= 40 %}<span class="text-danger fw-bold">!! THREAT</span>
                        {% else %}<span class="text-success fw-bold">// SECURE</span>{% endif %}
                    </td>
                    <td class="small">{% for x in r.reasons %}<div>• {{ x }}</div>{% endfor %}</td>
                </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        <a href="/download_csv" class="btn btn-outline-info w-100 mt-4 font-orbitron small">DOWNLOAD_FORENSIC_REPORT.CSV</a>
    </div>

    <script>
        const results = {{ results|tojson }};
        const metrics = {{ metrics|tojson if metrics else 'null' }};
        const chartDefaults = { color: '#888', font: { family: 'JetBrains Mono' } };

        new Chart(document.getElementById('resultChart'), {
            type: 'doughnut',
            data: {
                labels: ['THREAT', 'SECURE'],
                datasets: [{ data: [results.filter(r => r.score >= 40).length, results.length - results.filter(r => r.score >= 40).length], backgroundColor: ['#ff3131', '#00ff41'], borderWidth: 0 }]
            },
            options: { plugins: { legend: { position: 'bottom', labels: chartDefaults }, title: { display: true, text: 'IDENTITY_DISTRIBUTION', color: '#00d2ff' } } }
        });

        new Chart(document.getElementById('scoreChart'), {
            type: 'bar',
            data: {
                labels: results.map(r => r.filename.substring(0,8)),
                datasets: [{ label: 'RISK_SCORE', data: results.map(r => r.score), backgroundColor: '#00d2ff' }]
            },
            options: { plugins: { legend: { display: false }, title: { display: true, text: 'ANOMALY_MAGNITUDE', color: '#00d2ff' } }, scales: { y: { grid: { color: '#222' } } } }
        });

        if (metrics) {
            new Chart(document.getElementById('performanceChart'), {
                type: 'line',
                data: {
                    labels: ['Start', 'Processing', 'End'],
                    datasets: [{ label: 'Latency (s)', data: [0, metrics.time, metrics.time], borderColor: '#ff00ff', tension: 0.4, fill: true, backgroundColor: 'rgba(255, 0, 255, 0.1)' }]
                },
                options: { plugins: { title: { display: true, text: 'PIPELINE_LATENCY', color: '#00d2ff' } } }
            });
        }
    </script>
    {% endif %}
</div>
</body>
</html>
"""

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
            "subject": str(msg.get("Subject", "(No Subject)")),
            "score": int(report.get("score", 0)),
            "reasons": report.get("reasons", [])
        }
    except Exception as e:
        return {"filename": filename, "label": "ERROR", "reasons": [str(e)], "score": 0}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        uploaded_files = request.files.getlist("email_files")
        tasks = [(f.filename, f.read()) for f in uploaded_files if f.filename != ""]
        return run_bulk_analysis(tasks)
    return render_template_string(HTML, results=session.get("results", []), metrics=session.get("metrics"))

@app.route("/auto_scan", methods=["POST"])
def auto_scan():
    tasks = []
    if os.path.exists(TEST_SAMPLES_DIR):
        for filename in os.listdir(TEST_SAMPLES_DIR):
            if filename.endswith(".eml"):
                filepath = os.path.join(TEST_SAMPLES_DIR, filename)
                with open(filepath, "rb") as f:
                    tasks.append((filename, f.read()))
    return run_bulk_analysis(tasks)

def run_bulk_analysis(tasks):
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = list(executor.map(process_email_task, tasks))
    duration = round(time.time() - start_time, 2)
    metrics = {"count": len(tasks), "time": duration}
    session["results"] = results
    session["metrics"] = metrics
    return render_template_string(HTML, results=results, metrics=metrics)

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

from waitress import serve

if __name__ == "__main__":
    print(">> IDENTI_ALIGN IS ONLINE [WAITRESS SERVER]")
    serve(app, host='127.0.0.1', port=5000)

if __name__ == "__main__":
   app.run(debug=True, use_reloader=False)