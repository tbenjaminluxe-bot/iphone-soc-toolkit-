#!/usr/bin/env python3
import re,os,sys
from collections import Counter

def ir007():
 print("\n[IR-007] BRUTE FORCE")
 ips=["192.168.1.100"]*8+["8.8.8.8"]*2
 c=Counter(ips)
 for ip,n in c.most_common():
  print(f"{'🚨 ATTACKER' if n>=5 else '✅ OK'} {ip} -> {n} fails")
def ir008(t):
 print("\n[IR-008] PHISHING")
 s=0
 if "micros0ft" in t.lower(): s+=50
 if "192.168.1.100" in t: s+=40
 if "verify" in t.lower(): s+=20
 print(f"Target: {t}")
 print(f"VERDICT: {'MALICIOUS' if s>=70 else 'SUSPICIOUS' if s>=30 else 'CLEAN'} - {s}/100")
 return s
def ir009(t):
 print("\n[IR-009] THREAT INTEL")
 s=100 if "192.168.1.100" in t or "micros0ft" in t else 10
 print(f"IOC: {t}")
 print(f"VERDICT: {'MALICIOUS' if s>=70 else 'CLEAN'} - {s}/100")
 return s

t=sys.argv[-1] if len(sys.argv)>1 else "http://192.168.1.100/login"
print("="*60)
print("🛡️  SOC SUITE v1.0 - MASTER TRIAGE")
print(f"🔍 TRIAGING: {t}")
print("="*60)
ir007()
s1=ir008(t)
s2=ir009(t)
print("\n"+"="*60)
print(f"FINAL VERDICT: {'MALICIOUS' if max(s1,s2)>=70 else 'CLEAN'} - {max(s1,s2)}/100")
print(f"Action: {'🔴 BLOCK & Escalate' if max(s1,s2)>=70 else '🟡 Monitor'}")
print("="*60)
