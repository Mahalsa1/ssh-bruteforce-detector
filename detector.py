import re
from collections import defaultdict

LOG_FILE = "auth.log"
FAILED_LIMIT = 5

failed_attempts = defaultdict(int)

ip_pattern = r"Failed password.*from (\d+\.\d+\.\d+\.\d+)"

try:
    with open(LOG_FILE, "r") as file:
        logs = file.readlines()

    for line in logs:
        match = re.search(ip_pattern, line)

        if match:
            ip_address = match.group(1)
            failed_attempts[ip_address] += 1

    print("\nSSH Brute Force Detection Report")
    print("--------------------------------")

    alerts_found = False

    for ip, count in failed_attempts.items():
        print(f"IP Address: {ip} | Failed Attempts: {count}")

        if count >= FAILED_LIMIT:
            alerts_found = True
            print(f"ALERT: Possible brute-force attack detected from {ip}")

    if not alerts_found:
        print("\nNo brute-force attack detected.")

except FileNotFoundError:
    print(f"Error: {LOG_FILE} not found.")