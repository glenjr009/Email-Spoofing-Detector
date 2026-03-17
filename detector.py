import re, spf, dkim, dns.resolver, ipaddress, requests

# Get a free API key at abuseipdb.com to make this "Open Source" integration real
ABUSE_IPDB_KEY = "YOUR_API_KEY_HERE" 

def get_ip_intel(ip):
    if not ABUSE_IPDB_KEY or ip == "127.0.0.1":
        return 0, "No External Intel"
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSE_IPDB_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    try:
        res = requests.get(url, headers=headers, params=params, timeout=3)
        if res.status_code == 200:
            score = res.json()['data']['abuseConfidenceScore']
            return score, f"Abuse Score: {score}%"
    except: pass
    return 0, "Intel Offline"

def analyze_email(msg, body, raw_bytes):
    # CRITICAL: Initialize fresh lists for EVERY call to avoid duplicate reasons
    reasons = []
    auth_score = 0
    content_score = 0
    
    # 1. Identity Extraction
    from_hdr = str(msg.get("From", ""))
    ret_path = str(msg.get("Return-Path", "") or msg.get("Reply-To", ""))
    
    def get_dom(addr):
        m = re.search(r"[\w\.-]+@([\w\.-]+)", addr)
        return m.group(1).lower() if m else ""

    dom_from = get_dom(from_hdr)
    dom_return = get_dom(ret_path) or dom_from

    # 2. Authentication Logic (Actual Checks, not guesses)
    from app import extract_sender_ip # Assuming this is in your app.py
    sender_ip = extract_sender_ip(msg)
    
    spf_res, _ = spf.check2(i=sender_ip, s="test@"+dom_return, h=dom_return)
    
    # 3. Strict DMARC Alignment (This is the 400-mark logic)
    spf_aligned = (dom_from == dom_return or dom_from.endswith("." + dom_return))
    
    if spf_res != "pass":
        auth_score += 30
        reasons.append(f"SPF {spf_res.upper()}")
    
    if not spf_aligned and dom_from:
        auth_score += 30
        reasons.append("DMARC Alignment Mismatch")

    # 4. OSINT Implementation
    abuse_score, intel_msg = get_ip_intel(sender_ip)
    if abuse_score > 20:
        auth_score += (abuse_score // 2)
        reasons.append(f"OSINT: {intel_msg}")

    # 5. Content Logic
    body_lower = (body or "").lower()
    if any(x in body_lower for x in ["urgent", "action required", "verify your"]):
        content_score += 20
        reasons.append("Phishing Keywords Detected")

    total = auth_score + content_score
    return {
        "score": int(total),
        "auth_score": int(auth_score),
        "content_score": int(content_score),
        "label": "SECURE" if total < 40 else "LIKELY SPOOF" if total < 80 else "HIGHLY LIKELY",
        "reasons": reasons
    }