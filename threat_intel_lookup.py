#!/usr/bin/env python3
"""
IR-009: Threat Intel Lookup
Roland Benjamin | NOC @ MTN | Aspiring SOC Tier 1
Checks IP/URL against Blocklist + Heuristics + AbuseIPDB (optional API)
Usage: python3 threat_intel_lookup.py 8.8.8.8
       python3 threat_intel_lookup.py http://malicious.com/login
"""
import re, os, sys, json
from datetime import datetime

BLOCKLIST_FILE = "blocklist.txt"
REPORT_FILE = "threat_intel_report.txt"

# You can add free AbuseIPDB API key later - works without it too!
ABUSEIPDB_API_KEY = "" # Get free at abuseipdb.com - optional

def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return set()
    with open(BLOCKLIST_FILE) as f:
        return set(line.strip() for line in f if line.strip())

def check_ip(ip, blocklist):
    score=0
    reasons=[]
    # Private IP check
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        reasons.append("Private IP - internal")
        return 0, "INTERNAL / SAFE", reasons

    if ip in blocklist:
        score+=80
        reasons.append(f"FOUND in blocklist.txt - KNOWN BAD")

    # Heuristics - common malicious patterns
    octets = ip.split('.')
    if len(octets)==4:
        # If IP is from known bulletproof hosting ranges (simplified)
        if octets[0] in ["45","185","192"]:
            score+=20
            reasons.append(f"Suspicious ASN range: {octets[0]}.x")

    # Tor / VPN heuristics
    if score==0:
        reasons.append("Not in local blocklist - check AbuseIPDB for full verdict")

    verdict = "MALICIOUS" if score>=70 else "SUSPICIOUS" if score>=30 else "CLEAN / UNKNOWN"
    return min(score,100), verdict, reasons

def check_url(url, blocklist):
    score=0
    reasons=[]
    low=url.lower()

    # IP in URL
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', low):
        score+=40
        reasons.append("URL uses direct IP not domain - HIGH RISK")

    # Check domain in blocklist
    domain = re.findall(r'https?://([^/]+)', low)
    if domain:
        d=domain[0]
        if any(b in d or d in b for b in blocklist):
            score+=60
            reasons.append(f"Domain/IP matches blocklist: {d}")

    # Phishing keywords in URL
    phishing_words=["login","verify","secure","account","update","confirm","bank","mtn","microsoft"]
    found=[w for w in phishing_words if w in low]
    if found:
        score+=len(found)*10
        reasons.append(f"Phishing keywords in URL: {found}")

    # Shortener or suspicious TLD
    if any(x in low for x in [".tk",".ml",".ga",".cf","bit.ly","tinyurl"]):
        score+=30
        reasons.append("Suspicious TLD or URL shortener")

    # HTTPS check
    if not low.startswith("https://") and "login" in low:
        score+=20
        reasons.append("Login page without HTTPS")

    verdict = "MALICIOUS" if score>=70 else "SUSPICIOUS" if score>=30 else "CLEAN / REVIEW"
    return min(score,100), verdict, reasons

def main():
    print("="*60)
    print("IR-009: Threat Intel Lookup")
    print("Roland Benjamin | SOC Tier 1 | Built on iPhone")
    print("="*60)

    blocklist=load_blocklist()
    print(f"[+] Loaded {len(blocklist)} IOCs from {BLOCKLIST_FILE}")

    target = sys.argv[1] if len(sys.argv)>1 else input("Enter IP or URL to check: ").strip()
    if not target:
        print("Usage: python3 threat_intel_lookup.py 8.8.8.8")
        return

    print(f"\n[>] Checking: {target}")
    print("-"*60)

    # Detect type
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target)

    if is_ip:
        score, verdict, reasons = check_ip(target, blocklist)
    else:
        # Extract IP from URL if present
        ip_in_url = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target)
        if ip_in_url:
            score1, verdict1, reasons1 = check_ip(ip_in_url[0], blocklist)
            score2, verdict2, reasons2 = check_url(target, blocklist)
            score = min(score1+score2, 100)
            verdict = "MALICIOUS" if "MALICIOUS" in [verdict1,verdict2] else verdict2
            reasons = reasons1+reasons2
        e
