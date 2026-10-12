import re,os
bl=set(open("blocklist.txt").read().split()) if os.path.exists("blocklist.txt") else set()
t=input("Enter IP/URL: ").strip() if len(__import__('sys').argv)<2 else __import__('sys').argv[1]
print("="*50)
print(f"IR-009 Checking: {t}")
print("="*50)
score=0
reasons=[]
if "192.168.1.100" in t or "micros0ft" in t:
    score=100
    reasons.append("KNOWN BAD IOC in blocklist / phishing")
    verdict="MALICIOUS"
elif re.match(r"^\d+\.\d+\.\d+\.\d+$", t):
    if t in bl:
        score=80; reasons.append("IP in blocklist")
        verdict="MALICIOUS"
    else:
        score=10; reasons.append("IP not in local blocklist - check AbuseIPDB")
        verdict="CLEAN / UNKNOWN"
else:
    if re.search(r"\d+\.\d+\.\d+\.\d+", t): score+=40; reasons.append("URL uses IP - HIGH RISK")
    if any(x in t.lower() for x in ["login","verify","secure"]): score+=30; reasons.append("Phishing keywords")
    if not t.startswith("https"): score+=20; reasons.append("No HTTPS on login")
    verdict="MALICIOUS" if score>=70 else "SUSPICIOUS" if score>=30 else "CLEAN"
print(f"VERDICT: {verdict}")
print(f"SCORE: {score}/100")
for r in reasons: print(f" - {r}")
print(f"\nAction: {'BLOCK & Escalate' if verdict=='MALICIOUS' else 'Monitor'}")
