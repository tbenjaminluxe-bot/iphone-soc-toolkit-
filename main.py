#!/usr/bin/env python3
# main.py - iPhone SOC Toolkit Control Center
import os

def banner():
    print("""
╔════════════════════════════════════╗
║  iPhone SOC Toolkit - iSH Edition  ║
║  100% Running on iPhone            ║
╚════════════════════════════════════╝
""")

while True:
    banner()
    print("1) SOC Triage - Analyze log/alert")
    print("2) Email IP Hunter - Parse email header")
    print("3) IP Reputation - Check IP")
    print("4) View casebook.csv")
    print("5) List all files")
    print("6) Exit")
    c = input("\nSelect [1-6]: ").strip()

    if c == "1":
        log = input("Paste alert text: ")
        os.system(f'python3 soc_toolkit.py "{log}"')
    elif c == "2":
        print("Make sure header.txt exists")
        os.system('python3 email_ip_hunter.py header.txt')
    elif c == "3":
        ip = input("Enter IP(s): ")
        os.system(f'python3 ip_reputation.py {ip}')
    elif c == "4":
        os.system('cat casebook.csv')
    elif c == "5":
        os.system('ls -lh')
    elif c == "6":
        break
    input("\n[Press return for menu]")
