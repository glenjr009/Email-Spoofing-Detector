import re, spf, dkim, dns.resolver, ipaddress, requests, time

ABUSE_IPDB_KEY = "YOUR_API_KEY" 
intel_cache = {}

def get_ip_intel(ip):
    if not ABUSE_IPDB_KEY or ip == "127.0.0.1":
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
    def get_dom(addr):
        m = re.search(r"[\w\.-]+@([\w\.-]+)", addr)
        return m.group(1).lower() if m else ""
    author_domain = get_dom(from_hdr)

    from app import extract_sender_ip
    sender_ip = extract_sender_ip(msg)

    # --- GRANULAR SCORING ENGINE ---
    
    # 1. SPF Check (20 pts)
    spf_res, _ = spf.check2(i=sender_ip, s="postmaster@"+author_domain, h=author_domain)
    if spf_res != 'pass':
        auth_score += 20
        reasons.append(f"Infrastructure: SPF {spf_res.upper()}")

    # 2. DMARC Alignment Check (25 pts)
    # Checks if the visible domain matches the technical sender
    spf_aligned = author_domain in sender_ip or any(author_domain.endswith(x) for x in [author_domain]) 
    if not spf_aligned:
        auth_score += 25
        reasons.append("Identity: Domain Alignment Mismatch")

    # 3. DKIM Cryptographic Check (15 pts)
    try:
        if dkim.verify(raw_bytes):
            pass
        else:
            auth_score += 15
            reasons.append("Security: DKIM Signature Invalid")
    except:
        auth_score += 10
        reasons.append("Security: Missing Digital Seal (DKIM)")

    # 4. OSINT Reputation (Variable pts: 0 to 50)
    abuse_score, intel_msg = get_ip_intel(sender_ip)
    if abuse_score > 10:
        penalty = int(abuse_score / 2)
        auth_score += penalty
        reasons.append(f"Reputation: {intel_msg}")

    # 5. Content Heuristics (10 pts per keyword)
    body_lower = (body or "").lower()
    phish_terms = ["urgent", "verify", "suspend", "action required", "password"]
    for term in phish_terms:
        if term in body_lower:
            content_score += 10
            reasons.append(f"Heuristic: High-Risk Term [{term}]")

    total = auth_score + content_score
    duration = round(time.time() - start_time, 4)

    return {
        "score": int(total),
        "auth_score": int(auth_score),
        "content_score": int(content_score),
        "label": "SECURE" if total < 30 else "CAUTION" if total < 60 else "THREAT",
        "reasons": list(set(reasons)), # Remove duplicates
        "processing_time": duration
    }