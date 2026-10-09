# 📱➡️🛡️ iPhone SOC Triage Toolkit
# Built on iSH Shell + Python3 | NOC → SOC Transition Project
# Author: NOC Engineer @ MTN, Aspiring SOC Analyst

import re
from datetime import datetime
import csv
import os

# --- IOC EXTRACTOR (Same logic real SIEMs use) ---
def extract_iocs(log):
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)
    urls = re.findall(r'https?://[^\s]+', log)
    hashes = re.findall(r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{64}\b', log)
    return ips, urls, hashes

# --- RISK SCORING ENGINE ---
def calculate_risk(ips, urls, hashes):
    score = 0
    if urls: 
        score += 70  # Malicious URL high risk
    if any(ip.startswith("192.168.") or ip.startswith("10.") for ip in ips):
        score += 20  # Internal IP involved
    if hashes:
        score += 20  # Hash = potential malware
    
    # Cap for display but keep real value
    level = "LOW"
    if score >= 80: level = "CRITICAL"
    elif score >= 50: level = "HIGH"
    elif score >= 20: level = "MEDIUM"
    
    return score, level

def get_soc_action(level):
    if level == "CRITICAL":
        return "BLOCK, Reset MFA, Report CIRT"
    elif level == "HIGH":
        return "Isolate Host, Investigate"
    else:
        return "Monitor, Log Case"

# --- MAIN TRIAGE ---
def triage_log(log):
    ips, urls, hashes = extract_iocs(log)
    risk, level = calculate_risk(ips, urls, hashes)
    action = get_soc_action(level)
    
    print(f"\n= SOC REPORT {datetime.now()} =")
    print(f"Log: {log}")
    print(f"IPs={ips} URLs={urls} Hashes={hashes}")
    print(f"Risk: {risk} - {level}")
    print(f"Action: {action}")
    
    # Save to casebook for Tier 2 handoff
    save_to_casebook(log, ips, urls, risk, level, action)
    return risk, level, action

def save_to_casebook(log, ips, urls, risk, level, action):
    file_exists = os.path.isfile("casebook.csv")
    with open("casebook.csv", "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Timestamp", "Log", "IPs", "URLs", "Risk", "Level", "Action"])
        writer.writerow([datetime.now(), log, ";".join(ips), ";".join(urls), risk, level, action])
    print("[+] Saved to casebook.csv")

# --- DEMO - Test with NOC phishing alert ---
if __name__ == "__main__":
    # Example NOC alert: user clicking malicious link
    sample_log = "Alert from 192.168.1.10 clicking http://evil.com/malware.exe hash 5d41402abc4b2a76b9719d911017c592"
    triage_log(sample_log)
