#!/usr/bin/env python3
# phishing_url_checker.py - Simple heuristic checker (No API needed)

import re
from urllib.parse import urlparse

def check_url(url):
    url = url.strip()
    score = 0
    reasons = []
    
    # Clean
    if not url.startswith("http"):
        url = "http://" + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full = url.lower()
    except:
        return 100, ["Invalid URL format"]

    # Rule 1: IP address instead of domain (classic phishing)
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        score += 40
        reasons.append("Uses IP address not domain")

    # Rule 2: Too many subdomains
    if domain.count('.') > 3:
        score += 15
        reasons.append(f"Too many subdomains ({domain.count('.')})")

    # Rule 3: Suspicious keywords
    suspicious = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'free', 'gift']
    for word in suspicious:
        if word in full:
            score += 10
            reasons.append(f"Contains keyword '{word}'")
            break

    # Rule 4: URL shortener
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.me', 'is.gd']
    for s in shorteners:
        if s in domain:
            score += 20
            reasons.append(f"URL shortener {s}")

    # Rule 5: @ symbol trick
    if '@' in url:
        score += 30
        reasons.append("Contains @ symbol (redirect trick)")

    # Rule 6: Very long URL
    if len(url) > 75:
        score += 10
        reasons.append(f"Very long URL ({len(url)} chars)")

    # Rule 7: Hyphen in domain (fake paypal etc)
    if '-' in domain and domain.count('-') >= 2:
        score += 15
        reasons.append("Multiple hyphens in domain (typosquat)")

    # Cap score
    score = min(score, 100)

    if score >= 70:
        verdict = "CRITICAL - Likely Phishing"
    elif score >= 40:
        verdict = "HIGH - Suspicious"
    elif score >= 15:
        verdict = "MEDIUM - Review"
    else:
        verdict = "LOW - Likely Safe"

    return score, reasons, verdict, url

# Test mode
if __name__ == "__main__":
    print("🔍 Phishing URL Checker - iPhone SOC Toolkit")
    print("Enter URL (or 'q' to quit):")
    while True:
        u = input("URL> ").strip()
        if u.lower() in ['q','quit','exit']: break
        if not u: continue
        s, r, v, clean = check_url(u)
        print(f"\nURL: {clean}")
        print(f"Score: {s}/100 - {v}")
        if r:
            print("Flags:")
            for x in r: print(f" - {x}")
        print("")
