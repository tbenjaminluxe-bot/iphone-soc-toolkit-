import time, datetime
blockfile="blocklist.txt"
print("WATCH DOG STARTED - monitoring...")
while True:
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Example: read blocklist and add timestamp if new IP appears
    try:
        with open(blockfile) as f:
            lines=f.readlines()
        print(f"[{now}] Active threats: {len(lines)} IPs in blocklist")
        for l in lines:
            if "185.220.101.5" in l:
                print(f" -> ALERT TOR NODE DE: {l.strip()} at {now}")
    except:
        pass
    time.sleep(30)
