# IDENTI_ALIGN // THREAT_STREAM

**Asynchronous Email Forensic Gateway and Threat Intelligence Pipeline**

IDENTI_ALIGN // THREAT_STREAM is an academic and portfolio-focused cybersecurity project designed to detect **email spoofing**, **identity impersonation**, and **phishing anomalies** at scale using raw `.eml` file analysis.

The system combines protocol-level authentication checks, weighted forensic scoring, OSINT-based network reputation, and concurrent batch processing to support practical email threat investigation workflows.

---

## Author

**Glen Fernandes**  
Cybersecurity Enthusiast | Full-Stack Developer | Computer Science Undergraduate

---

## Project Overview

Email spoofing and phishing remain common attack vectors used to impersonate trusted identities, bypass user awareness, and deliver malicious links or payloads.

This project acts as a forensic email analysis gateway that processes raw `.eml` files and evaluates multiple threat signals, including:

- SPF authentication failures
- DMARC identifier alignment issues
- Missing or invalid DKIM signatures
- Suspicious phishing-related content
- Network reputation using AbuseIPDB
- Sender identity inconsistencies

The platform supports both **manual email upload analysis** and **automated batch ingestion** through a watched directory, making it suitable for academic demonstrations, portfolio review, and incident response-style workflows.

---

## Objectives

The main objectives of this project are:

- Analyze raw `.eml` files for spoofing and phishing indicators
- Detect identity impersonation using SPF, DKIM, and DMARC logic
- Generate a weighted threat score using multiple forensic signals
- Process multiple emails concurrently using an asynchronous worker engine
- Integrate OSINT-based reputation intelligence using AbuseIPDB
- Provide downloadable CSV reports for incident response and review
- Deliver a clean dashboard-based interface for visual threat analysis

---

## Key Features

### Asynchronous Processing Engine

The application uses `ThreadPoolExecutor` with **20 parallel workers** to process bulk email files concurrently.

This avoids slow sequential scanning and improves performance during batch analysis.

---

### Dual Ingestion Workflow

The system supports two ingestion methods:

| Ingestion Method | Description |
|---|---|
| Manual Upload | Upload `.eml` files directly through the web interface |
| Batch Folder Watch | Automatically scan files placed inside the `/TEST_SAMPLES` directory |

This design supports both user-driven testing and enterprise-style batch processing.

---

### OSINT Threat Intelligence Layer

The platform integrates with **AbuseIPDB** using REST API requests.

To improve speed and reduce repeated API calls, the system uses an in-memory **L1 cache** for previously queried IP reputation results.

---

### Multi-Signal Risk Scoring

Each email is evaluated using a weighted scoring model that combines authentication, reputation, and heuristic content indicators.

The final score determines whether the email is classified as:

- SECURE
- CAUTION
- THREAT

---

### Forensic Export Hub

The system allows users to download a compiled `.csv` report containing structural analysis results for all scanned emails.

This is useful for:

- Incident response documentation
- Academic evaluation
- Threat hunting records
- Forensic reporting
- Dataset review

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.13+, Flask |
| Session Management | Flask-Session |
| Production WSGI Server | Waitress |
| Email Authentication | pyspf, dkimpy, dnspython |
| Threat Intelligence | AbuseIPDB API using requests |
| Concurrency | ThreadPoolExecutor |
| Frontend | Bootstrap 5, Chart.js |
| UI Theme | High-contrast dark mode / cyber-noir layout |
| Export Format | CSV |

---

## Architecture Highlights

### 1. Asynchronous Core

The system uses a thread-based concurrent execution model to handle multiple email samples at once.

```python
ThreadPoolExecutor(max_workers=20)
```

This improves throughput during large-scale `.eml` analysis.

---

### 2. Waitress Production Server

The application uses **Waitress** as the production WSGI server instead of relying only on Flask’s development server.

Waitress is configured with multi-threaded socket binding to reduce common Windows socket conflicts such as:

```text
WinError 10038
```

---

### 3. L1 Threat Intelligence Cache

Repeated AbuseIPDB checks can slow down analysis and consume API limits.

To solve this, the project uses an in-memory L1 cache that stores recently queried IP reputation results.

Benefits:

- Faster repeated scans
- Reduced API usage
- Improved batch processing performance
- Better reliability during demos

---

## Multi-Signal Risk Matrix

The engine calculates a granular risk score from `0` to `100+` points using five weighted vector layers.

| # | Detection Layer | Weight | Logic |
|---|---|---:|---|
| 1 | SPF Check Failure | +20 | Checks whether the sending server is authorized by the sender domain DNS records |
| 2 | DMARC Identifier Mismatch | +25 | Compares the visible `From` address with technical origin domains to detect identity alignment gaps |
| 3 | Missing or Invalid DKIM Signature | +10 to +15 | Verifies whether the email has a valid cryptographic domain signature |
| 4 | OSINT Network Reputation | 0 to +50 | Applies half of the live Abuse Confidence Score returned by AbuseIPDB |
| 5 | Heuristic Content Analysis | +10 per keyword | Scans email body for suspicious phishing terms such as `urgent`, `verify`, `suspend`, `action required`, and `password` |

---

## Risk Classification

| Final Score | Classification | Status Color | Meaning |
|---:|---|---|---|
| `< 30` | SECURE | Green | Low-risk email with no major spoofing or phishing indicators |
| `30 - 59` | CAUTION | Yellow | Suspicious email requiring manual review |
| `60+` | THREAT | Red | High-risk email likely involving spoofing, impersonation, or phishing |

---

## Project Directory Structure

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

## Installation Guide

Follow the steps below to set up and run the project locally.

---

## Prerequisites

Make sure the following are installed on your system:

- Python 3.13 or above
- Git
- pip
- A modern web browser
- AbuseIPDB API key

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

## 1. Clone the Repository

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
cd Email-Spoofing-Detector
```

---

## 2. Create a Virtual Environment

Using a virtual environment is recommended to isolate project dependencies.

---

### Windows PowerShell

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

### Windows Command Prompt

```cmd
python -m venv venv
```

Activate the virtual environment:

```cmd
venv\Scripts\activate
```

---

### Linux / macOS

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

---

## 3. Install Dependencies

Install all required packages:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the dependencies manually:

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

## 4. Configure AbuseIPDB API Key

This project uses AbuseIPDB for OSINT-based IP reputation scoring.

Create an environment variable for your API key.

---

### Windows PowerShell

```powershell
$env:ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

### Windows Command Prompt

```cmd
set ABUSEIPDB_API_KEY=YOUR_API_KEY_HERE
```

---

### Linux / macOS

```bash
export ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"
```

---

## 5. Run the Application

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

## 6. Open the Web Interface

After starting the server, open your browser and visit:

```bash
http://127.0.0.1:5000/
```

---

## How to Use

The project supports two main workflows:

1. Manual Email Upload
2. Automated Batch Ingestion

---

## Workflow 1: Manual Email Upload

Use this workflow when you want to scan individual `.eml` files through the web interface.

### Steps

1. Start the Flask application.
2. Open the web dashboard in your browser.
3. Upload one or more `.eml` files.
4. Wait for the asynchronous engine to process the files.
5. Review the classification result:
   - SECURE
   - CAUTION
   - THREAT
6. Check the detailed score breakdown.
7. Download the `.csv` forensic report if required.

---

## Workflow 2: Automated Batch Ingestion

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

3. The system watches or scans the folder for available email samples.

4. Files are processed using the asynchronous worker pool.

5. Results are displayed on the dashboard.

6. Export the compiled forensic report as a `.csv` file.

---

## Generating Test Samples

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

- SPF failure
- DKIM missing
- DKIM invalid
- DMARC mismatch
- Suspicious phishing keywords
- High-risk sender infrastructure
- Mixed authentication failure cases

---

## Example Risk Output

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

## CSV Export

The forensic export module allows analysts to download a structured report.

The exported report may include:

| Field | Description |
|---|---|
| File Name | Name of the analyzed `.eml` file |
| Sender | Parsed sender identity |
| Return Path | Technical return path address |
| Source IP | Extracted sending IP address |
| SPF Result | SPF pass/fail status |
| DKIM Result | DKIM valid/invalid/missing status |
| DMARC Result | DMARC alignment status |
| Abuse Score | AbuseIPDB confidence score |
| Risk Score | Final calculated threat score |
| Classification | SECURE, CAUTION, or THREAT |

---

## Security Logic Summary

The detection engine does not depend on a single indicator.

Instead, it uses a layered scoring model that combines:

- Infrastructure authentication
- Domain alignment
- Cryptographic verification
- IP reputation
- Content heuristics

This reduces false confidence and provides a more practical forensic assessment.

---

## Future Enhancements

Planned improvements include:

- Authenticated Received Chain support
- Redis-based L2 caching layer
- DMARC RUA XML report parser
- Email attachment scanning
- URL extraction and phishing domain analysis
- VirusTotal or URLScan.io integration
- Role-based analyst dashboard
- Case management and investigation tagging
- PDF export for incident reports
- Docker deployment support
- CI/CD workflow for automated testing
- Unit tests for detector modules
- Real-time mailbox ingestion using IMAP

---

## Academic Relevance

This project demonstrates practical implementation of cybersecurity concepts including:

- Email authentication protocols
- Digital forensics
- Threat intelligence integration
- Concurrent processing
- Web application development
- Incident response reporting
- Secure engineering design
- Risk-based classification systems

---

## Disclaimer

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

## License

This project is released under the MIT License.

You are free to use, modify, and distribute this project for educational and research purposes, provided proper credit is given.

---

## Author

**Glen Fernandes**  
Cybersecurity Enthusiast | Full-Stack Developer | Computer Science Undergraduate

---

## Repository

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
```

---

## Final Note

IDENTI_ALIGN // THREAT_STREAM provides a practical, engineering-focused approach to email spoofing detection by combining protocol verification, threat intelligence, heuristic scoring, and asynchronous processing.

It is built to demonstrate how modern email forensic systems can move beyond simple pass/fail checks and provide structured, explainable threat classification.
