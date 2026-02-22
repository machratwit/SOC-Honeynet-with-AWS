import boto3
import requests
import re
from collections import defaultdict
from datetime import datetime, timezone, timedelta
import os
from dotenv import load_dotenv
load_dotenv()


LOG_GROUP_NAME = "linux-auth-logs"
SECURITY_GROUP_ID = os.getenv("SECURITY_GROUP_ID")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
AWS_REGION = os.getenv("AWS_REGION")
NACL_ID = os.getenv("NACL_ID")
BRUTE_FORCE_THRESHOLD = 5
LOOKBACK_MINUTES = 30240


# ==============================
# Pull logs from CloudWatch
# ==============================
def get_failed_logins():
    client = boto3.client("logs", region_name=AWS_REGION)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

    start_ms = int(start_time.timestamp() * 1000)
    end_ms = int(end_time.timestamp() * 1000)

    events = []
    next_token = None

    while True:
        kwargs = {
            "logGroupName": LOG_GROUP_NAME,
            "startTime": start_ms,
            "endTime": end_ms,
            "filterPattern": "Failed password"
        }

        if next_token:
            kwargs["nextToken"] = next_token

        response = client.filter_log_events(**kwargs)
        events.extend(response.get("events", []))

        next_token = response.get("nextToken")
        if not next_token:
            break

    return events


# ==============================
# Parse IPs from log lines
# ==============================
def parse_ips(log_events):
    ip_counts = defaultdict(int)

    ip_pattern = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")

    for event in log_events:
        match = ip_pattern.search(event["message"])
        if match:
            ip = match.group(1)
            ip_counts[ip] += 1

    return ip_counts


# ==============================
# Block IP in security group
# ==============================

def get_already_blocked_ips(nacl_id):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = response["NetworkAcls"][0]["Entries"]

    blocked_ip = set()
    for entry in entries:
        if (not entry["Egress"]
            and entry["RuleAction"] == "deny"
                and entry["RuleNumber"] >= 101):
            cidr = entry.get("CidrBlock", "")
            ip = cidr.replace("/32", "")
            blocked_ip.add(ip)
    return blocked_ip


def get_next_rule_number(nacl_id):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)

    response = ec2.describe_network_acls(NetworkAclIds=[nacl_id])
    entries = response["NetworkAcls"][0]["Entries"]

    used_numbers = {
        entry["RuleNumber"]
        for entry in entries
        if not entry["Egress"]
    }

    rule = 101
    while rule in used_numbers:
        rule += 1

    return rule


def block_ip(ip_address):
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    rule_number = get_next_rule_number(NACL_ID)
    try:
        ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=rule_number,
            Protocol="6",
            RuleAction="deny",
            Egress=False,
            CidrBlock=f"{ip_address}/32",
            PortRange={"From": 22, "To": 22}
        )
        print(
            f"[BLOCKED] {ip_address} → NACL deny rule #{rule_number} created")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to block {ip_address}: {e}")
        return False


# ==============================
# Send Slack alert
# ==============================
def send_slack_alert(ip_address, count, blocked):
    action_text = "Blocked via NACL" if blocked else "Block attempt failed — check logs"
    message = {
        "text": (
            f":rotating_light: *Brute Force Detected!*\n"
            f"*IP Address:* `{ip_address}`\n"
            f"*Failed Attempts:* {count} in last {LOOKBACK_MINUTES} minutes\n"
            f"*Action Taken:* {action_text}\n"
            f"*Time:* {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
    }

    if not SLACK_WEBHOOK_URL:
        print("[WARN] No Slack webhook configured, skipping alert")
        return
    response = requests.post(SLACK_WEBHOOK_URL, json=message)

    if response.status_code == 200:
        print(f"[ALERT] Slack notification sent for {ip_address}")
    else:
        print(
            f"[ERROR] Slack alert failed with status {response.status_code}: {response.text}")

def main():
    print("=" * 40)
    print("Honeynet Automated Response Monitor")
    print("=" * 40)

    if not NACL_ID or not SLACK_WEBHOOK_URL:
        print(
            "[ERROR] Missing required environment variables. Check NACL_ID and SLACK_WEBHOOK_URL.")
        return

    print("\n" + "-" * 40)
    print("  Pulling CloudWatch Logs")
    print("-" * 40)
    events = get_failed_logins()
    print(f"Found {len(events)} failed login events")

    if not events:
        print("No failed logins found. All clear.")
        return

    ip_counts = parse_ips(events)
    print(f"Unique IPs seen: {list(ip_counts.keys())}")

    print("\n" + "-" * 40)
    print("  Already Blocked IPs in NACL")
    print("-" * 40)
    already_blocked = get_already_blocked_ips(NACL_ID)
    if already_blocked:
        for blocked_ip in sorted(already_blocked):
            print(f"[!] {blocked_ip}")
    else:
        print("  (none)")

    print("\n" + "-" * 40)
    print("  Evaluating IPs Against Threshold")
    print("-" * 40)
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"\n  IP: {ip}")
        print(f"  Attempts: {count}")

        if count >= BRUTE_FORCE_THRESHOLD:
            if ip in already_blocked:
                print(f"  Status: Already blocked — skipping")
                continue
            print(
                f"  Status:  Threshold hit ({BRUTE_FORCE_THRESHOLD}+) — taking action")
            blocked = block_ip(ip)
            send_slack_alert(ip, count, blocked)

        else:
            print(f"  Status: Below threshold — monitoring")

    print("\n" + "=" * 40)
    print("  Scan Complete")
    print("=" * 40)


if __name__ == "__main__":
    main()

