import csv
import re
from collections import defaultdict
from datetime import datetime

INPUT_FILE = "signups.csv"
BLOCK_THRESHOLD = 7

# Disposable email domain patterns
DISPOSABLE_PATTERNS = [
    r"(mailinator|sharklasers|tempmail|10minutemail|yopmail|trashmail)\.com",
    r"(guerrillamail|dispostable|fakeinbox)\.com",
    r"(.*\d{2,}@.*\.xyz)"  # heuristic: numeric junk + weird TLD
]

# Suspicious user-agent patterns
UA_PATTERNS = [
    r"(curl|httpclient|python-requests|wget)",
    r"(tor|onion)",
    r"(selenium|puppeteer|playwright|phantomjs)",
    r"(headlesschrome)",
    r"^$"  # empty user-agent
]

ip_scores = defaultdict(int)
ip_timestamps = defaultdict(list)
blacklisted_ips = set()

def is_disposable(email):
    return any(re.search(pat, email.lower()) for pat in DISPOSABLE_PATTERNS)

def is_suspicious_ua(ua):
    return any(re.search(pat, ua.lower()) for pat in UA_PATTERNS)

def process_log():
    with open(INPUT_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row["ip"]
            email = row["email"]
            timestamp = datetime.strptime(row["timestamp"], "%Y-%m-%dT%H:%M:%S")
            user_agent = row.get("user_agent", "")

            ip_timestamps[ip].append(timestamp)

            # Score disposable email
            if is_disposable(email):
                ip_scores[ip] += 3

            # Score sketchy user-agent
            if is_suspicious_ua(user_agent):
                ip_scores[ip] += 4

            # Signup velocity (3+ in 60 sec)
            recent = [t for t in ip_timestamps[ip] if (timestamp - t).seconds < 60]
            if len(recent) > 2:
                ip_scores[ip] += 3

            # Final check
            if ip_scores[ip] >= BLOCK_THRESHOLD and ip not in blacklisted_ips:
                print(f"[!] Flagged: {ip} – Score: {ip_scores[ip]}")
                blacklisted_ips.add(ip)

    with open("akamai_blocklist.txt", "w") as out:
        for ip in sorted(blacklisted_ips):
            out.write(ip + "\n")

    print(f"\n[+] Saved Akamai IP blocklist → akamai_blocklist.txt")

if __name__ == "__main__":
    process_log()
