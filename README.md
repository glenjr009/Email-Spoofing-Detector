# 📧 IDENTI_ALIGN // THREAT_STREAM

## 🛡️ Asynchronous Email Forensic Gateway with Threat Intelligence & Machine Learning

**IDENTI_ALIGN // THREAT_STREAM** is an engineering-focused cybersecurity project designed to detect **email spoofing**, **identity impersonation**, and **phishing anomalies** using raw `.eml` file analysis, deterministic email authentication checks, OSINT reputation intelligence, and machine learning-based content classification.

The system combines **SPF**, **DKIM**, **DMARC-style identity alignment**, **AbuseIPDB threat intelligence**, and a **Multinomial Naive Bayes ML classifier** to generate a structured risk score for every analyzed email.

---

## 👨‍💻 Author

**Glen Fernandes**    
Cybersecurity Enthusiast | Web-Developer | B.E CSE Undergrad

---

## 📌 Project Overview

Email spoofing and phishing attacks often abuse trust by forging sender identities, manipulating email headers, and delivering deceptive content through seemingly legitimate communication channels.

This project acts as an **email forensic gateway** that processes raw `.eml` files and evaluates each email through multiple independent threat layers.

The upgraded architecture now includes a **Machine Learning Heuristic Layer** that uses TF-IDF text feature extraction and a Multinomial Naive Bayes classifier to evaluate phishing-like language patterns probabilistically instead of relying only on static keyword matching.

---

## 🎯 Objectives

The main objectives of this project are:

- 🔍 Analyze raw `.eml` email files for spoofing and phishing indicators
- 🛡️ Validate sender infrastructure using SPF checks
- 🧾 Detect identity mismatches between visible and technical sender domains
- 🔐 Verify DKIM-based cryptographic integrity
- 🌐 Integrate AbuseIPDB for real-time network reputation scoring
- 🤖 Apply Machine Learning for probabilistic phishing content detection
- ⚡ Process multiple email samples concurrently using asynchronous workers
- 📊 Generate clear SECURE / CAUTION / THREAT classifications
- 📤 Export structured forensic reports for review and incident response

---

## ✨ Key Features

| Feature | Description |
|---|---|
| ⚡ Asynchronous Processing | Uses `ThreadPoolExecutor` with 20 parallel workers for concurrent email analysis |
| 📤 Manual Diagnostics | Supports `.eml` file uploads directly through the web interface |
| 📁 Automated Batch Ingestion | Watches the `/TEST_SAMPLES` directory for bulk email processing |
| 🤖 ML Content Classification | Uses `TfidfVectorizer` and `MultinomialNB` for phishing-like content detection |
| 🧮 Laplace Smoothing | Uses `alpha=1.0` for stable probability handling on unseen vocabulary |
| 🧾 SPF Verification | Checks sender infrastructure authorization against DNS records |
| 🔐 DKIM Verification | Validates email cryptographic signatures |
| 🛡️ Identity Alignment | Compares RFC 5322 `From` header with technical `Return-Path` domain |
| 🌐 OSINT Threat Intel | Queries AbuseIPDB for live relay IP reputation |
| 🧠 L1 Reputation Cache | Stores repeated IP lookups in memory to improve speed and reduce API usage |
| 📊 Dashboard Visualization | Uses Chart.js for real-time threat visualization |
| 🎨 Responsive UI | Uses Bootstrap 5 with a clean cyber-noir dashboard layout |
| 📤 CSV Export | Exports structured analysis reports for incident response workflows |

---

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| 🐍 Core Framework | Python 3.13+, Flask |
| 🗂️ Session Management | Flask-Session, filesystem-backed sessions |
| 🤖 Machine Learning | pandas, scikit-learn |
| 🧠 ML Vectorization | TfidfVectorizer |
| 📊 ML Classifier | MultinomialNB |
| 🚀 Production WSGI Server | Waitress |
| 📧 Protocol Verification | pyspf, dkimpy, dnspython |
| 🌐 Threat Intelligence | requests, AbuseIPDB REST API |
| ⚡ Concurrency | ThreadPoolExecutor |
| 🎨 Frontend | Bootstrap 5 |
| 📈 Visualization | Chart.js |
| 📤 Reporting | CSV Export |

---

## 🏗️ Architecture Highlights

### ⚡ 1. Asynchronous Core

The application uses a concurrent worker model powered by `ThreadPoolExecutor`.

```python
ThreadPoolExecutor(max_workers=20)
```

This allows the system to process multiple email samples in parallel instead of scanning them sequentially.

Benefits:

- Faster bulk email processing
- Better throughput during batch ingestion
- Improved responsiveness during manual diagnostics
- More realistic enterprise-style gateway behavior

---

### 🤖 2. Multinomial Naive Bayes ML Integration

The upgraded detection engine includes a machine learning-based content inspection layer.

The ML pipeline uses:

- `TfidfVectorizer` for text feature extraction
- `MultinomialNB` for probabilistic phishing classification
- `alpha=1.0` Laplace smoothing for stable classification

The model processes email body text into TF-IDF feature vectors and calculates the probability of malicious content based on learned malicious text patterns.

```python
TfidfVectorizer()
MultinomialNB(alpha=1.0)
```

This upgrade improves detection beyond static keyword checks by allowing the system to evaluate suspicious text patterns mathematically.

---

### 🧮 3. Laplace Smoothing

The classifier uses Laplace smoothing with:

```python
alpha=1.0
```

This ensures that unseen or unique vocabulary terms do not collapse probability calculations to zero.

Benefits:

- Better handling of unseen phishing vocabulary
- Improved boundary stability
- More reliable classification during testing
- Stronger robustness against varied email content

---

### 🚀 4. Waitress Production Deployment

The project uses **Waitress** as the production WSGI server instead of relying only on Flask’s development server.

Waitress is configured for multi-threaded socket binding to support higher concurrent throughput and reduce Windows socket conflicts such as:

```text
WinError 10038
```

---

### 🌐 5. OSINT Threat Intelligence with L1 Cache

The system integrates with AbuseIPDB to evaluate the reputation of extracted sender or relay IP addresses.

To improve efficiency, an in-memory **L1 cache** stores previously queried IP reputation results.

Benefits:

- Faster repeated scans
- Reduced AbuseIPDB API calls
- Better rate-limit management
- Improved demo reliability
- Stronger batch-processing performance

---

## 🧮 Multi-Signal Risk Matrix

The detection engine calculates a dynamic risk score from `0` to `100+` points using five independent threat layers.

| # | Threat Layer | Weight | Detection Logic |
|---|---|---:|---|
| 1 | 🧾 Infrastructure Protection Layer | `+20` | Performs SPF validation against domain DNS records to verify whether the sending server is authorized |
| 2 | 🛡️ Identity Verification Layer | `+25` | Compares the RFC 5322 `From` header with the `Return-Path` technical origin domain to detect identity gaps |
| 3 | 🔐 Cryptographic Integrity Layer | `+15` | Validates DKIM digital cryptographic seals to detect missing or invalid signatures |
| 4 | 🌐 Global Intelligence Layer | `0 to +50` | Applies a penalty equal to 50% of the live Abuse Confidence Score returned by AbuseIPDB |
| 5 | 🤖 Machine Learning Heuristic Layer | `0 to +30` | Applies a dynamic penalty based on the Multinomial Naive Bayes malicious classification confidence percentage |

---

## 🚦 Risk Classification Thresholds

| Final Score | Classification | Status Color | Meaning |
|---:|---|---|---|
| `< 30` | 🟢 SECURE | Green | Low-risk email with no major spoofing, phishing, or reputation indicators |
| `30 - 59` | 🟡 CAUTION | Yellow | Suspicious email requiring manual review |
| `60+` | 🔴 THREAT | Red | High-risk email likely involving spoofing, impersonation, or phishing behavior |

---

## 📁 Project Directory Structure

```bash
IDENTI_ALIGN-THREAT_STREAM/
│
├── app.py
│   └── Flask routing, file processing pipelines, session engine, and Waitress setup
│
├── detector.py
│   └── ML vectorizer initialization, multi-signal scoring matrix, and L1 reputation cache
│
├── generate_varied.py
│   └── Data generation utility mimicking 7 distinct multi-vector testing profiles
│
├── flask_session/
│   └── Internal filesystem-backed session architecture files
│
├── TEST_SAMPLES/
│   └── Watched batch ingestion path for automated .eml processing
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

Make sure the following are installed:

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

Using a virtual environment is recommended to isolate project dependencies.

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

Install the required dependencies:

```bash
pip install flask flask-session pyspf dkimpy dnspython requests waitress pandas scikit-learn
```

Or, if a `requirements.txt` file is available:

```bash
pip install -r requirements.txt
```

Recommended `requirements.txt`:

```txt
flask
flask-session
pyspf
dkimpy
dnspython
requests
waitress
pandas
scikit-learn
```

---

## 🔑 4. Configure AbuseIPDB API Key

This project uses AbuseIPDB for live OSINT-based IP reputation scoring.

Create an environment variable for your API key.

---

### 🪟 Windows PowerShell

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

### 🐧 Linux / macOS

```bash
export ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

## ▶️ 5. Run the Application

Start the application:

```bash
python app.py
```

or:

```bash
python3 app.py
```

---

## 🌐 6. Open the Web Interface

After starting the server, open your browser and visit:

```bash
http://127.0.0.1:5000/
```

---

# 🧭 Operational Modes

The project supports two primary operational workflows:

1. 📤 Manual Diagnostics
2. 📁 Automated Ingestion Pipeline

---

## 📤 Mode 1: Manual Diagnostics

Manual diagnostics allow users to upload `.eml` files directly through the web interface.

### Workflow

1. Start the application.

```bash
python app.py
```

2. Open the dashboard.

```bash
http://127.0.0.1:5000/
```

3. Upload one or more `.eml` files.

4. The system performs:

   - SPF verification
   - DKIM verification
   - Identity alignment checking
   - AbuseIPDB reputation lookup
   - ML-based content classification
   - Final weighted scoring

5. Review the result:

   - 🟢 SECURE
   - 🟡 CAUTION
   - 🔴 THREAT

6. Export the forensic `.csv` report if needed.

---

## 📁 Mode 2: Automated Ingestion Pipeline

The automated pipeline scans emails from the watched batch directory.

### Workflow

1. Place `.eml` files inside:

```bash
TEST_SAMPLES/
```

2. Start the application.

```bash
python app.py
```

3. The system ingests files from the watched directory.

4. The asynchronous worker pool processes emails concurrently.

5. Results are displayed in the dashboard.

6. Export the combined CSV report for review.

---

## 🧪 Generate Varied Test Samples

The project includes `generate_varied.py`, a utility script that generates multiple simulated email testing profiles.

Run:

```bash
python generate_varied.py
```

or:

```bash
python3 generate_varied.py
```

The generator can simulate different testing profiles such as:

- SPF failure
- DKIM missing
- DKIM invalid
- Identity mismatch
- Suspicious content
- Malicious relay reputation
- Multi-vector threat combinations

---

## 🖥️ Simulated Pipeline Telemetry Output

Example structured transaction logs during analysis:

```text
[INIT] IDENTI_ALIGN // THREAT_STREAM starting forensic gateway...
[INIT] Flask session engine loaded using filesystem-backed storage
[INIT] Waitress WSGI server initialized with multi-threaded socket binding
[INIT] ML pipeline loading TfidfVectorizer and MultinomialNB(alpha=1.0)
[INIT] Threat intelligence cache initialized: L1_MEMORY_CACHE

[INGEST] Source: TEST_SAMPLES/
[INGEST] Detected file: invoice_security_alert.eml
[QUEUE] Submitted job to ThreadPoolExecutor worker pool
[WORKER-07] Parsing RFC 5322 headers...
[WORKER-07] Extracted From: support@example-bank.com
[WORKER-07] Extracted Return-Path: relay@unknown-mailer.net
[WORKER-07] SPF result: FAIL | Penalty: +20
[WORKER-07] DKIM result: MISSING | Penalty: +15
[WORKER-07] Identity alignment: MISMATCH | Penalty: +25
[WORKER-07] AbuseIPDB lookup: 42 confidence | Penalty: +21
[WORKER-07] ML phishing probability: 73% | Penalty: +22
[WORKER-07] Final risk score: 103
[WORKER-07] Classification: THREAT

[EXPORT] CSV forensic report generated successfully
[STATUS] Dashboard telemetry updated
```

---

## 📊 Example Risk Output

```text
Email File: invoice_security_alert.eml
Classification: THREAT
Final Score: 103

Triggered Signals:
- SPF Check Failure: +20
- Identity Verification Mismatch: +25
- Missing DKIM Signature: +15
- AbuseIPDB Reputation Penalty: +21
- ML Phishing Confidence Penalty: +22

Recommendation:
This email should be treated as a high-risk phishing or spoofing attempt.
Do not click embedded links or download attachments.
Escalate the sample for manual incident response review.
```

---

## 📤 CSV Export Report

The forensic export hub generates a structured `.csv` report for scanned emails.

Possible report fields:

| Field | Description |
|---|---|
| 📄 File Name | Name of the analyzed `.eml` file |
| 👤 From Address | RFC 5322 visible sender identity |
| 🔁 Return Path | Technical return path domain |
| 🌐 Source IP | Extracted sender or relay IP address |
| 🧾 SPF Result | SPF pass/fail status |
| 🔐 DKIM Result | DKIM valid/missing/invalid status |
| 🛡️ Identity Match | Whether sender identity aligns with technical origin |
| 📡 Abuse Score | AbuseIPDB confidence score |
| 🤖 ML Confidence | ML-based phishing probability |
| 📊 Risk Score | Final calculated risk value |
| 🚦 Classification | SECURE, CAUTION, or THREAT |

---

## 🧠 Detection Logic Summary

The system does not rely on a single detection signal.

Instead, it combines deterministic verification and probabilistic ML scoring:

- 🧾 SPF validates sender infrastructure
- 🛡️ Identity alignment detects impersonation gaps
- 🔐 DKIM checks cryptographic integrity
- 🌐 AbuseIPDB evaluates network reputation
- 🤖 MultinomialNB estimates phishing content probability
- ⚡ ThreadPoolExecutor enables concurrent high-volume scanning

This layered approach provides a more explainable and practical email forensic assessment.

---

## 🚀 Future Enhancements

Planned improvements include:

- 🔗 Authenticated Received Chain support
- 🧠 Redis-based L2 reputation caching
- 📩 DMARC RUA XML report parser
- 📎 Email attachment scanning
- 🔍 Embedded URL extraction and phishing domain analysis
- 🌐 VirusTotal or URLScan.io integration
- 🗂️ Case management and investigation tagging
- 👥 Role-based analyst dashboard
- 📄 PDF incident report export
- 🐳 Docker deployment support
- ⚙️ CI/CD pipeline with automated test execution
- 🧪 Unit tests for scoring and protocol modules
- 📬 Real-time mailbox ingestion using IMAP
- 📈 Model retraining pipeline using labeled phishing datasets

---

## 🎓 Academic Relevance

This project demonstrates practical implementation of cybersecurity and software engineering concepts, including:

- Email authentication protocols
- Digital forensics
- Threat intelligence integration
- Machine learning-based text classification
- TF-IDF feature extraction
- Naive Bayes classification
- Concurrent programming
- Web application development
- Incident response reporting
- Risk-based classification systems

---

## ⚠️ Disclaimer

This project is developed strictly for **educational, academic, portfolio, and defensive cybersecurity purposes**.

It must not be used for:

- Phishing
- Spamming
- Unauthorized testing
- Malicious email generation
- Attacking third-party systems
- Bypassing security controls
- Any activity that violates law, policy, or ethical cybersecurity practice

The purpose of this project is to help users understand, detect, and defend against email spoofing, phishing, and identity impersonation attacks.

---

## 📄 License

This project is released under the **MIT License**.

You are free to use, modify, and distribute this project for educational and research purposes, provided proper credit is given.

---

---

## 🔗 Repository

Clone the project using:

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
```

If you like this project or found it useful, consider giving it a ⭐ on GitHub to support future development.

## 💡 Final Note

**IDENTI_ALIGN // THREAT_STREAM** provides a structured and explainable approach to email spoofing detection by combining protocol verification, OSINT threat intelligence, asynchronous processing, and machine learning-based phishing content analysis.

The project demonstrates how modern email forensic systems can move beyond static keyword heuristics and adopt a layered detection model that is scalable, interpretable, and practical for real-world cybersecurity workflows.
