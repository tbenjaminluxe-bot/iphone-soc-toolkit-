#!/usr/bin/env python3
import re, sys, ipaddress

def extract_ips(raw):
    print("\n[+] Hunting IPs...\n")
    ips = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', raw)
    ips = list(dict.fromkeys(ips))
    if not ips:
        print("[-] No IP found - Gmail hides origin IP")
        return
    for i, ip in enumerate(ips, 1):
        try:
            is_priv = ipaddress.ip_address(ip).is_private
            typ = "PRIVATE" if is_priv else "PUBLIC <- INVESTIGATE!"
            print(f"{i}. {ip} -> {typ}")
        except:
            print(f"{i}. {ip}")
    print("\n[+] Headers:")
    for f in ["Return-Path:", "From:", "X-Originating-IP:"]:
        m = re.search(rf'{f}.*', raw, re.I)
        if m: print(m.group(0)[:120])

data = open(sys.argv[1]).read() if len(sys.argv)>1 else sys.stdin.read()
extract_ips(data)

