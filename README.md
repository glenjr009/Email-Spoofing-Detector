# 📧 IDENTI_ALIGN // THREAT_STREAM

## 🛡️ Asynchronous Email Forensic Gateway & Threat Intelligence Pipeline

**IDENTI_ALIGN // THREAT_STREAM** is a cybersecurity-focused academic and portfolio project designed to detect **email spoofing**, **identity impersonation**, and **phishing anomalies** at scale using raw `.eml` file analysis.

The system combines **email authentication checks**, **threat intelligence**, **heuristic phishing analysis**, and **asynchronous bulk processing** to provide a structured forensic risk score for every scanned email.

---

## 👨‍💻 Author

**Glen Fernandes**  
Cybersecurity Enthusiast | Web-Dev | Computer Science Undergraduate

---

## 📌 Project Overview

Email spoofing and phishing are among the most common techniques used by attackers to impersonate trusted identities, deceive users, and deliver malicious links or payloads.

This project acts as an **email forensic analysis gateway** that processes raw `.eml` files and evaluates multiple threat signals such as:

- 🧾 SPF authentication failures
- 🔐 DKIM signature issues
- 🛡️ DMARC identity alignment mismatches
- 🌐 Suspicious sender infrastructure
- 🚨 Phishing-related keywords
- 📡 AbuseIPDB-based IP reputation
- 📊 Weighted threat scoring

The system supports both **manual upload-based analysis** and **automated batch ingestion**, making it suitable for academic demonstrations, portfolio evaluation, and incident response-style workflows.

---

## 🎯 Objectives

The main objectives of this project are:

- 🔍 Analyze raw `.eml` files for spoofing and phishing indicators
- 🛡️ Detect identity impersonation using SPF, DKIM, and DMARC checks
- 📊 Generate a weighted threat score using multiple forensic signals
- ⚡ Process bulk emails concurrently using an asynchronous engine
- 🌐 Integrate OSINT-based reputation intelligence using AbuseIPDB
- 📁 Support both manual uploads and automated folder-based ingestion
- 📤 Export structured `.csv` reports for forensic review
- 🖥️ Provide a clean dashboard interface for real-time threat visualization

---

## ✨ Key Features

| Feature | Description |
|---|---|
| ⚡ Asynchronous Processing | Uses `ThreadPoolExecutor` with 20 parallel workers for concurrent email analysis |
| 📥 Dual Ingestion | Supports both manual `.eml` uploads and automated `/TEST_SAMPLES` folder scanning |
| 🌐 OSINT Threat Intel | Integrates AbuseIPDB for real-time IP reputation lookup |
| 🧠 L1 Cache | Uses in-memory caching to reduce repeated API calls and improve performance |
| 📊 Risk Scoring | Calculates a weighted risk score using SPF, DKIM, DMARC, OSINT, and keyword signals |
| 📈 Dashboard UI | Uses Chart.js for visual analytics and Bootstrap 5 for a clean dark interface |
| 📤 CSV Export | Generates downloadable forensic reports for all scanned emails |
| 🧪 Test Data Utility | Includes `generate_varied.py` for generating varied email failure scenarios |

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| 🐍 Backend | Python 3.13+, Flask |
| 🗂️ Session Management | Flask-Session |
| 🚀 Production Server | Waitress |
| 📧 Protocol Parsing | pyspf, dkimpy, dnspython |
| 🌐 Threat Intelligence | AbuseIPDB API using requests |
| ⚡ Concurrency | ThreadPoolExecutor |
| 🎨 Frontend | Bootstrap 5 |
| 📊 Visualization | Chart.js |
| 📁 Export | CSV |
| 🖥️ UI Style | High-contrast dark mode / cyber-noir layout |

---

## 🏗️ Architecture Highlights

### ⚡ 1. Asynchronous Core

The application uses a thread-based concurrent processing model to analyze multiple emails in parallel.

```python
ThreadPoolExecutor(max_workers=20)
```

This improves scanning speed during bulk `.eml` analysis and prevents slow sequential processing.

---

### 🚀 2. Waitress Production Deployment

Instead of depending only on Flask’s development server, the project uses **Waitress** as the production WSGI server.

Waitress is configured with multi-threaded socket handling to reduce common Windows socket conflicts such as:

```text
WinError 10038
```

---

### 🧠 3. L1 Threat Intelligence Cache

AbuseIPDB queries can be slow and rate-limited when processing large batches.

To improve performance, the project uses an in-memory **L1 cache** for previously queried IP reputation results.

Benefits:

- ⚡ Faster repeated scans
- 🌐 Reduced AbuseIPDB API calls
- 📉 Lower rate-limit usage
- 🚀 Better performance during demos
- 🧪 More reliable batch processing

---

## 🧮 Multi-Signal Risk Matrix

The engine calculates a granular risk score from `0` to `100+` points using five distinct weighted vector layers.

| # | Detection Layer | Weight | Logic |
|---|---|---:|---|
| 1 | 🧾 SPF Check Failure | `+20` | Checks whether the sending server is authorized by the sender domain DNS records |
| 2 | 🛡️ DMARC Identifier Mismatch | `+25` | Compares the visible `From` address with technical origin domains to detect identity alignment gaps |
| 3 | 🔐 Missing / Invalid DKIM Signature | `+10 to +15` | Verifies whether the email has a valid cryptographic digital signature |
| 4 | 🌐 OSINT Network Reputation | `0 to +50` | Applies half of the live Abuse Confidence Score returned by AbuseIPDB |
| 5 | 🚨 Heuristic Content Analysis | `+10 per keyword` | Scans body content for phishing keywords such as `urgent`, `verify`, `suspend`, `action required`, and `password` |

---

## 🚦 Risk Classification

| Final Score | Classification | Status | Meaning |
|---:|---|---|---|
| `< 30` | 🟢 SECURE | Low Risk | No major spoofing or phishing indicators detected |
| `30 - 59` | 🟡 CAUTION | Medium Risk | Suspicious email requiring manual review |
| `60+` | 🔴 THREAT | High Risk | Likely spoofing, impersonation, or phishing attempt |

---

## 📁 Project Directory Structure

```bash
IDENTI_ALIGN-THREAT_STREAM/
│
├── app.py
│   └── Main web router, session control, upload handling, and Waitress initialization
│
├── detector.py
│   └── Multi-signal weighted scoring matrix, protocol engines, and L1 cache
│
├── generate_varied.py
│   └── Data simulation utility for generating diverse email failure vectors
│
├── flask_session/
│   └── Filesystem-backed internal session cache data
│
├── TEST_SAMPLES/
│   └── Watched batch ingestion directory for automated .eml scanning
│
├── requirements.txt
│   └── Python dependency list
│
└── README.md
    └── Project documentation
```

---

## ⚙️ Installation Guide

Follow the steps below to set up and run the project locally.

---

## ✅ Prerequisites

Make sure the following are installed on your system:

- 🐍 Python 3.13 or above
- 🌿 Git
- 📦 pip
- 🌐 Modern web browser
- 🔑 AbuseIPDB API key

Check Python version:

```bash
python --version
```

or:

```bash
python3 --version
```

Check pip version:

```bash
pip --version
```

---

## 📥 1. Clone the Repository

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
cd Email-Spoofing-Detector
```

---

## 🧪 2. Create a Virtual Environment

Using a virtual environment is recommended to keep project dependencies isolated.

---

### 🪟 Windows PowerShell

```powershell
python -m venv venv
```

Activate the virtual environment:

```powershell
.\venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:

```powershell
.\venv\Scripts\Activate.ps1
```

---

### 🪟 Windows Command Prompt

```cmd
python -m venv venv
```

Activate the virtual environment:

```cmd
venv\Scripts\activate
```

---

### 🐧 Linux / macOS

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

---

## 📦 3. Install Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the required dependencies manually:

```bash
pip install flask flask-session waitress pyspf dkimpy dnspython requests
```

Recommended `requirements.txt`:

```txt
flask
flask-session
waitress
pyspf
dkimpy
dnspython
requests
```

---

## 🔑 4. Configure AbuseIPDB API Key

This project uses **AbuseIPDB** for OSINT-based IP reputation scoring.

Create an environment variable for your API key.

---

### 🪟 Windows PowerShell

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

### 🪟 Windows Command Prompt

```cmd
set ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE
```

---

### 🐧 Linux / macOS

```bash
export ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

## ▶️ 5. Run the Application

Run the application:

```bash
python app.py
```

or:

```bash
python3 app.py
```

If Waitress is configured inside `app.py`, the application will start using the production WSGI server.

---

## 🌐 6. Open the Web Interface

After starting the server, open your browser and visit:

```bash
http://127.0.0.1:5000/
```

---

## 🧭 How to Use

The project supports two main workflows:

1. 📤 Manual Email Upload
2. 📁 Automated Batch Ingestion

---

## 📤 Workflow 1: Manual Email Upload

Use this workflow when you want to scan individual `.eml` files through the web interface.

### Steps

1. ▶️ Start the Flask application.
2. 🌐 Open the dashboard in your browser.
3. 📤 Upload one or more `.eml` files.
4. ⚡ Wait for the asynchronous engine to process the files.
5. 📊 Review the classification result:
   - 🟢 SECURE
   - 🟡 CAUTION
   - 🔴 THREAT
6. 🧮 Check the detailed score breakdown.
7. 📥 Download the `.csv` forensic report if required.

---

## 📁 Workflow 2: Automated Batch Ingestion

Use this workflow when you want to simulate an enterprise-like email gateway pipeline.

### Steps

1. Place raw `.eml` files inside the `TEST_SAMPLES/` directory.

```bash
TEST_SAMPLES/
```

2. Start the application.

```bash
python app.py
```

3. The system scans the folder for available email samples.

4. Files are processed using the asynchronous worker pool.

5. Results are displayed on the dashboard.

6. Export the compiled forensic report as a `.csv` file.

---

## 🧪 Generating Test Samples

The project includes a simulation utility for generating varied email failure vectors.

Run:

```bash
python generate_varied.py
```

or:

```bash
python3 generate_varied.py
```

This can be used to create different test scenarios such as:

- 🧾 SPF failure
- 🔐 DKIM missing
- ❌ DKIM invalid
- 🛡️ DMARC mismatch
- 🚨 Suspicious phishing keywords
- 🌐 High-risk sender infrastructure
- ⚠️ Mixed authentication failure cases

---

## 📊 Example Risk Output

```text
Email File: sample_001.eml
Classification: THREAT
Final Score: 75

Triggered Signals:
- SPF Check Failure: +20
- DMARC Identifier Mismatch: +25
- Missing DKIM Signature: +10
- Suspicious Keyword Found: +10
- AbuseIPDB Reputation Score Applied: +10

Recommendation:
This email should be treated as malicious or highly suspicious.
Do not click links or download attachments.
Escalate for manual incident response review.
```

---

## 📤 CSV Export

The forensic export module allows analysts to download a structured report.

The exported report may include:

| Field | Description |
|---|---|
| 📄 File Name | Name of the analyzed `.eml` file |
| 👤 Sender | Parsed sender identity |
| 🔁 Return Path | Technical return path address |
| 🌐 Source IP | Extracted sending IP address |
| 🧾 SPF Result | SPF pass/fail status |
| 🔐 DKIM Result | DKIM valid/invalid/missing status |
| 🛡️ DMARC Result | DMARC alignment status |
| 📡 Abuse Score | AbuseIPDB confidence score |
| 📊 Risk Score | Final calculated threat score |
| 🚦 Classification | SECURE, CAUTION, or THREAT |

---

## 🧠 Security Logic Summary

The detection engine does not depend on a single indicator.

Instead, it uses a layered scoring model that combines:

- 🧾 Infrastructure authentication
- 🛡️ Domain alignment
- 🔐 Cryptographic verification
- 🌐 IP reputation
- 🚨 Content heuristics

This provides a more practical and explainable forensic assessment compared to simple pass/fail detection.

---

## 🚀 Future Enhancements

Planned improvements include:

- 🔗 Authenticated Received Chain support
- 🧠 Redis-based L2 caching layer
- 📩 DMARC RUA XML report parser
- 📎 Email attachment scanning
- 🔍 URL extraction and phishing domain analysis
- 🌐 VirusTotal or URLScan.io integration
- 👥 Role-based analyst dashboard
- 🗂️ Case management and investigation tagging
- 📄 PDF export for incident reports
- 🐳 Docker deployment support
- ⚙️ CI/CD workflow for automated testing
- 🧪 Unit tests for detector modules
- 📬 Real-time mailbox ingestion using IMAP

---

## 🎓 Academic Relevance

This project demonstrates practical implementation of cybersecurity and software engineering concepts including:

- 📧 Email authentication protocols
- 🧪 Digital forensics
- 🌐 Threat intelligence integration
- ⚡ Concurrent processing
- 🖥️ Web application development
- 📤 Incident response reporting
- 🛡️ Secure engineering design
- 📊 Risk-based classification systems

---

## ⚠️ Disclaimer

This project is developed strictly for **educational, academic, and defensive cybersecurity purposes**.

It should not be used for:

- Phishing
- Spamming
- Unauthorized testing
- Malicious email generation
- Attacking third-party systems
- Bypassing security controls

The purpose of this project is to help users understand, detect, and defend against email spoofing, phishing, and identity impersonation attacks.

---

## 📄 License

This project is released under the **MIT License**.

You are free to use, modify, and distribute this project for educational and research purposes, provided proper credit is given.

---

## 👨‍💻 Author

**Glen Fernandes**  
Cybersecurity Enthusiast | Web-Dev | Computer Science Undergraduate

---

## 🔗 Repository

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
```

---

## 💡 Final Note

**IDENTI_ALIGN // THREAT_STREAM** provides a practical, engineering-focused approach to email spoofing detection by combining protocol verification, threat intelligence, heuristic scoring, and asynchronous processing.

It demonstrates how modern email forensic systems can move beyond basic pass/fail checks and provide structured, explainable threat classification.
