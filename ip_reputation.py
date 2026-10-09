#!/usr/bin/env python3
# ip_reputation.py - SOC IP Reputation Checker for iPhone
import sys, ipaddress, re

def check_ip(ip_str):
    ip_str = ip_str.strip()
    print(f"\n= IP REPUTATION REPORT = {ip_str} =")
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private:
            print(f"Type: PRIVATE - Internal {ip_str}")
            print("Risk: LOW - Internal asset")
            print("Action: Investigate internal host")
        elif ip.is_loopback:
            print("Type: LOOPBACK")
            print("Risk: INFO")
        elif ip.is_multicast or ip.is_reserved:
            print(f"Type: SPECIAL - {ip}")
            print("Risk: INFO")
        else:
            print(f"Type: PUBLIC - Internet routable")
            print("Risk: Check external intel")
            print(f"\n[+] Check manually:")
            print(f"  AbuseIPDB: https://www.abuseipdb.com/check/{ip_str}")
            print(f"  VirusTotal: https://www.virustotal.com/gui/ip-address/{ip_str}")
            print(f"  Shodan: https://www.shodan.io/host/{ip_str}")
            print(f"  GreyNoise: https://viz.greynoise.io/ip/{ip_str}")
            print("\nAction: BLOCK if malicious, Add to watchlist")
        print(f"Version: IPv{ip.version}")
    except ValueError:
        print(f"ERROR: '{ip_str}' is not a valid IP")
        # try extract IPs from text
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip_str)
        if ips:
            print(f"Found IPs in text: {ips}")
            for i in ips:
                check_ip(i)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            check_ip(arg)
    else:
        print("Usage: python3 ip_reputation.py 8.8.8.8")
        print("   or: python3 ip_reputation.py 1.1.1.1 8.8.8.8 192.168.1.10")
        inp = input("Enter IP to check: ")
        check_ip(inp)
