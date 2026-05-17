# 📧 Email-Spoofing-Detector

**Email-Spoofing-Detector** is a cybersecurity-based web application designed to detect and analyze **email spoofing attacks** using email header analysis and email authentication checks.

This project helps users identify whether an email is **legitimate, suspicious, or spoofed** by analyzing important email security indicators such as:

- SPF
- DKIM
- DMARC
- Return-Path mismatch
- Reply-To mismatch
- Sender domain mismatch
- Suspicious email header patterns

---

## 🚀 Project Overview

Email spoofing is a cyberattack technique where attackers forge the sender address of an email to make it appear as if the email came from a trusted person, company, or organization.

This project allows users to analyze raw email headers and detect possible spoofing attempts in a simple and understandable way.

It is useful for:

- Cybersecurity students
- Security analysts
- Email administrators
- Digital forensics learners
- Phishing detection research
- Academic mini/major projects

---

## 🎯 Objectives

The main objectives of this project are:

- Detect spoofed emails using email header analysis
- Verify sender authenticity using SPF, DKIM, and DMARC checks
- Identify mismatches in sender information
- Detect suspicious email header patterns
- Provide a simple and understandable result to users
- Improve awareness about phishing and email spoofing attacks

---

## ✨ Features

- 📩 Email header input and analysis
- 🔍 SPF result checking
- 🔐 DKIM verification status checking
- 🛡️ DMARC validation checking
- ⚠️ Suspicious header detection
- 🌐 Sender and Return-Path mismatch detection
- 📊 Spoofing risk analysis
- 🧾 Easy-to-understand final result
- 💡 Security recommendations
- 🖥️ Simple web-based interface

---

## 🛠️ Tech Stack

This project uses the following technologies:

- Python
- Flask
- Flask-Session
- HTML
- CSS
- JavaScript
- Email Header Parsing
- Cybersecurity Authentication Checks

---

## 📁 Project Structure

```bash
Email-Spoofing-Detector/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   ├── index.html
│   ├── result.html
│   └── about.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── script.js
│
└── utils/
    └── header_analyzer.py
```

> Note: The actual file structure may vary depending on your implementation.

---

## ⚙️ Installation Guide

Follow the steps below to run this project on your local system.

---

## ✅ Prerequisites

Make sure you have the following installed:

- Python 3.8 or above
- Git
- pip

Check Python version:

```bash
python --version
```

or

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

Creating a virtual environment is recommended so that project dependencies remain separate from your system Python packages.

### For Windows

```bash
python -m venv venv
```

Activate the virtual environment:

```bash
venv\Scripts\activate
```

### For Linux / macOS

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

---

## 3. Install Required Dependencies

Install all required dependencies using:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available, install the basic dependencies manually:

```bash
pip install flask flask-session
```

Optional useful packages:

```bash
pip install dnspython email-validator tldextract
```

---

## 4. Run the Application

Run the Flask application using:

```bash
python app.py
```

or

```bash
python3 app.py
```

---

## 5. Open in Browser

After running the application, open your browser and visit:

```bash
http://127.0.0.1:5000/
```

---

## 🧾 How to Use

1. Open the application in your browser.
2. Copy the full email header from an email.
3. Paste the email header into the input box.
4. Click on the analyze button.
5. View the result.
6. Check whether the email is legitimate, suspicious, or spoofed.
7. Follow the security recommendation shown by the system.

---

## 📌 How to Get Email Headers

### Gmail

1. Open the email.
2. Click on the three dots near the reply button.
3. Select **Show original**.
4. Copy the full email header.

### Outlook

1. Open the email.
2. Click on the three dots.
3. Select **View message source**.
4. Copy the email header.

### Yahoo Mail

1. Open the email.
2. Click on **More**.
3. Select **View raw message**.
4. Copy the email header.

---

## 🔍 Email Security Checks Used

### SPF

SPF stands for **Sender Policy Framework**.

It checks whether the mail server is allowed to send emails on behalf of a particular domain.

If SPF fails, it may indicate that the email was sent from an unauthorized server.

---

### DKIM

DKIM stands for **DomainKeys Identified Mail**.

It verifies whether the email was digitally signed by the sender domain.

If DKIM is missing or failed, the email may have been modified or sent by an untrusted source.

---

### DMARC

DMARC stands for **Domain-based Message Authentication, Reporting, and Conformance**.

It helps email servers decide what to do when SPF or DKIM checks fail.

DMARC helps protect domains from being abused in phishing and spoofing attacks.

---

### Header Mismatch Detection

The system checks for mismatches between:

- From address
- Reply-To address
- Return-Path address
- Message-ID domain
- Received headers
- Authentication results

If these values do not match properly, the email may be suspicious.

---

## 📊 Sample Output

```text
Email Status: Suspicious / Spoofed

Risk Level: High

Detected Issues:
- SPF check failed
- DKIM signature missing
- DMARC validation failed
- From domain and Return-Path domain mismatch
- Suspicious sender pattern detected

Recommendation:
Do not click any links or download attachments from this email.
Verify the sender through a trusted communication channel.
```

---

## 🧪 Sample Test Header

You can test the application using this sample header:

```text
From: security@example.com
Return-Path: attacker@fake-domain.com
Reply-To: attacker@fake-domain.com
Received-SPF: fail
Authentication-Results: spf=fail dkim=none dmarc=fail
Subject: Urgent Account Verification Required
```

Expected result:

```text
Spoofed / Suspicious Email
```

---

## 🔐 Security Recommendations

To stay protected from spoofed emails:

- Do not click suspicious links
- Do not download unknown attachments
- Verify the sender before responding
- Enable SPF for your domain
- Enable DKIM signing
- Configure DMARC policy
- Use strong spam filters
- Report phishing emails
- Train users to identify suspicious emails
- Monitor DMARC reports regularly

---

## 🚀 Future Enhancements

Some future improvements for this project include:

- Machine learning-based spoofing detection
- Gmail API integration
- Real-time email scanning
- Phishing URL detection
- Attachment malware scanning
- PDF report generation
- Admin dashboard
- Threat intelligence API integration
- Email reputation scoring system
- Browser extension support

---

## 📸 Screenshots

Add your screenshots inside a `screenshots` folder and use the format below:

```markdown
![Home Page](screenshots/home.png)
![Result Page](screenshots/result.png)
```

---

## 👨‍💻 Author

**Glen Fernandes**

Cybersecurity Enthusiast | Developer | Student

---

## 📚 References

- SPF Documentation
- DKIM Documentation
- DMARC Documentation
- OWASP Email Security Guidelines
- Email Header Analysis Techniques
- Phishing and Email Spoofing Research

---

## ⚠️ Disclaimer

This project is created only for **educational and defensive cybersecurity purposes**.

Do not use this project for illegal activities, phishing, spamming, unauthorized testing, or malicious email operations.

The goal of this project is to help users understand, detect, and prevent email spoofing attacks.

---

## 📄 License

This project is licensed under the MIT License.

You are free to use, modify, and distribute this project for educational and research purposes.

---

## ⭐ Support

If you found this project useful, consider giving it a star on GitHub.

```bash
git clone https://github.com/glenjr009/Email-Spoofing-Detector.git
```

---

## 💡 Final Note

Email spoofing is one of the most common methods used in phishing attacks.

**Email-Spoofing-Detector** helps analyze email headers, authentication results, and sender information to detect suspicious emails and improve email security awareness.
