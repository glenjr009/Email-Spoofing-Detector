import re
import spf
import dkim
import dns.resolver
import ipaddress
import requests
import time
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# --- INTEL CONFIGURATION ---
# REPLACE THIS WITH YOUR ACTUAL ABUSEIPDB API KEY
ABUSE_IPDB_KEY = "5159bb61aeb70c0e382c63338f260eee9fa9a1c3aa964efece2efc5b8d22185ab542d2ae1389a66d" 
intel_cache = {}

# --- MACHINE LEARNING HEURISTIC STORAGE INTERFACE ---
print("\n[SYSTEM] Initializing Content Analytics Pipeline...")
print("[SYSTEM] Compiling Training Corpus into Feature Vectors...")

# Baseline training text to seed the ML engine immediately on compilation
training_corpus = {
    'text': [
        "Hey, are we still meeting for lunch tomorrow at 12?",
        "URGENT: Your account has been suspended! Click here to verify your password immediately.",
        "Free entry in a weekly competition to win prize cash rewards!",
        "Can you please send me the final project report by EOD?",
        "CONGRATULATIONS! You have won a gift card reward. Call now to claim your prize.",
        "Just checking in to see how your internship application went at the lab.",
        "Get cheap insurance rates today! No medical exam required. Guarantee approval.",
        "Dear student, your library books are overdue. Please return them to avoid fines.",
        "Winner! As a valued customer you have been selected to receive a cash prize reward!",
        "Are you coming to the cybersecurity bootcamp session this evening?"
    ],
    'label': [0, 1, 1, 0, 1, 0, 1, 0, 1, 0] # 0 = Ham (Legitimate), 1 = Spam (Malicious)
}

# Train the model immediately on initialization
ml_df = pd.DataFrame(training_corpus)
ml_vectorizer = TfidfVectorizer(stop_words='english', lowercase=True, ngram_range=(1, 2))
X_train_tfidf = ml_vectorizer.fit_transform(ml_df['text'])

ml_classifier = MultinomialNB(alpha=1.0) # Alpha=1.0 activates Laplace Smoothing
ml_classifier.fit(X_train_tfidf, ml_df['label'])

print("[SYSTEM] Multinomial Naive Bayes Engine Online.")

def get_ip_intel(ip):
    if not ABUSE_IPDB_KEY or ip in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return 0, "No External Intel"
    if ip in intel_cache:
        return intel_cache[ip]
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSE_IPDB_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=3)
        if res.status_code == 200:
            score = res.json()['data']['abuseConfidenceScore']
            result = (score, f"Abuse Score: {score}%")
            intel_cache[ip] = result
            return result
    except: pass
    return 0, "Intel Offline"

def analyze_email(msg, body, raw_bytes):
    start_time = time.time()
    reasons = []
    auth_score = 0
    content_score = 0
    
    from_hdr = str(msg.get("From", ""))
    return_path_hdr = str(msg.get("Return-Path", ""))

    def get_dom(addr):
        m = re.search(r"[\w\.-]+@([\w\.-]+)", addr)
        return m.group(1).lower() if m else ""

    author_domain = get_dom(from_hdr)
    return_path_domain = get_dom(return_path_hdr)

    # Cross-reference dynamic module map to prevent initialization loops
    from app import extract_sender_ip
    sender_ip = extract_sender_ip(msg)

    # --- GRANULAR MULTI-SIGNAL SCORING ENGINE ---
    
    # 1. Infrastructure Inspection Layer: SPF Check (20 pts)
    try:
        spf_res, _ = spf.check2(i=sender_ip, s="postmaster@"+author_domain, h=author_domain)
        if spf_res != 'pass':
            auth_score += 20
            reasons.append(f"Infrastructure: SPF {spf_res.upper()}")
    except:
        auth_score += 15
        reasons.append("Infrastructure: SPF Resolution Timeout")

    # 2. Identity Verification Layer: DMARC Alignment Check (25 pts)
    # Audits the identity gap between the visible From domain and technical Return-Path domain
    if author_domain and return_path_domain:
        spf_aligned = (author_domain == return_path_domain or 
                       author_domain.endswith("." + return_path_domain) or 
                       return_path_domain.endswith("." + author_domain))
    else:
        spf_aligned = False

    if not spf_aligned and author_domain:
        auth_score += 25
        reasons.append("Identity: Domain Alignment Mismatch")

    # 3. Cryptographic Integrity Layer: DKIM Check (15 pts)
    try:
        if dkim.verify(raw_bytes):
            pass
        else:
            auth_score += 15
            reasons.append("Security: DKIM Signature Invalid")
    except:
        auth_score += 10
        reasons.append("Security: Missing Digital Seal (DKIM)")

    # 4. Global Intelligence Layer: OSINT Reputation (0 to 50 pts)
    abuse_score, intel_msg = get_ip_intel(sender_ip)
    if abuse_score > 10:
        penalty = int(abuse_score / 2)
        auth_score += penalty
        reasons.append(f"Reputation: {intel_msg}")

    # 5. Heuristic Layer: Machine Learning Content Classification (0 to 30 pts)
    if body and body.strip():
        try:
            # Transform raw payload strings into vector spaces matching trained features
            body_vector = ml_vectorizer.transform([body])
            prediction = ml_classifier.predict(body_vector)[0]
            probabilities = ml_classifier.predict_proba(body_vector)[0]
            
            if prediction == 1: # Classifier maps the token map to a malicious profile
                confidence = probabilities[1]
                ml_penalty = int(confidence * 30)
                content_score += ml_penalty
                reasons.append(f"ML_Heuristic: Naive Bayes Classified Spam ({confidence * 100:.1f}% Confidence)")
        except Exception as e:
            reasons.append(f"ML_Heuristic: Vector Processing Error [{str(e)}]")

    total = auth_score + content_score
    duration = round(time.time() - start_time, 4)

    return {
        "score": int(total),
        "auth_score": int(auth_score),
        "content_score": int(content_score),
        "label": "SECURE" if total < 30 else "CAUTION" if total < 60 else "THREAT",
        "reasons": list(set(reasons)),
        "processing_time": duration
    }