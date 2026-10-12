#!/usr/bin/env python3
"""
IR-008: Phishing & IOC Triage Analyzer
Built by Roland Benjamin | NOC Engineer @ MTN | Aspiring SOC Analyst Tier 1
Lagos, Nigeria - Built on iPhone iSH
Usage: python3 phishing_analyzer.py
"""
import re, os
from datetime import datetime

BLOCKLIST_FILE = "blocklist.txt"
REPORT_FILE = "phishing_report.txt"
SUSPICIOUS_KEYWORDS = ["login", "verify", "urgent", "suspended", "security", "update", "confirm", "bank", "payment", "invoice", "click here", "password expired"]
BRAND_KEYWORDS = ["microsoft", "google", "mtn", "paypal", "facebook", "apple", "amazon"]

def load_blocklist():
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    with open(BLOCKLIST_FILE) as f:
        return [line.strip().lower() for line in f if line.strip()]

def extract_iocs(text):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text, re.IGNORECASE)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
    return ips, urls, emails, hashes

def analyze(text, blocklist):
    ips, urls, emails, hashes = extract_iocs(text)
    tl = text.lower()
    score=0
    reasons=[]
    hits=[b for b in blocklist if b in tl]
    if hits:
        score+=50
        reasons.append(f"Blocklist hit: {', '.join(hits[:3])}")
    kw=[k for k in SUSPICIOUS_KEYWORDS if k in tl]
    if kw:
        score+=len(kw)*10
        reasons.append(f"Suspicious keywords: {', '.join(kw)}")
    brand=[b for b in BRAND_KEYWORDS if b in tl]
    if brand and ("login" in tl or "verify" in tl):
        score+=25
        reasons.append(f"Possible brand impersonation: {', '.join(brand)}")
    if any(re.match(r'https?://\d+\.\d+\.\d+\.\d+', u) for u in urls):
        score+=30
        reasons.append("URL uses direct IP - highly suspicious")
    if len(urls)>=3:
        score+=10
        reasons.append(f"Multiple URLs ({len(urls)})")
    if "urgent" in tl or "immediately" in tl or "24 hours" in tl:
        score+=15
        reasons.append("Urgency language")
    score=min(score,100)
    verdict="MALICIOUS" if score>=75 else "SUSPICIOUS" if score>=40 else "SAFE / LOW RISK"
    return score, verdict, reasons, (ips, urls, emails, hashes)

def main():
    print("="*60)
    print("IR-008: Phishing & IOC Triage Analyzer")
    print("Roland Benjamin | SOC Tier 1 Toolkit")
    print("="*60)
    blocklist=load_blocklist()
    print(f"[+] Loaded {len(blocklist)} IPs from blocklist.txt")
    print("\nPaste email / URL (type END to finish):")
    lines=[]
    while True:
        try:
            line=input()
            if line.strip().upper()=="END":
                break
            lines.append(line)
        except EOFError:
            break
    text="\n".join(lines)
    if not text.strip():
        print("[-] No input")
        return
    score, verdict, reasons, (ips, urls, emails, hashes) = analyze(text, blocklist)
    print("\n"+"-"*60)
    print(f"VERDICT: {verdict} | SCORE: {score}/100")
    print("-"*60)
    print(f"IPs: {ips}\nURLs: {urls}\nEmails: {emails}\nHashes: {hashes}")
    print("\nReasons:")
    for r in reasons:
        print(f"  - {r}")
    with open(REPORT_FILE,"a") as out:
        out.write(f"\n[{datetime.now()}] IR-008 {verdict} {score}/100\nIOCs: {ips} {urls}\nReasons: {reasons}\n")
    print(f"\n[+] Saved to {REPORT_FILE}")
    if verdict=="MALICIOUS":
        print("Action: BLOCK, Isolate, Escalate to Tier 2")
    elif verdict=="SUSPICIOUS":
        print("Action: Quarantine, Warn user")
    else:
        print("Action: Allow, Document FP")

if __name__=="__main__":
    main()
