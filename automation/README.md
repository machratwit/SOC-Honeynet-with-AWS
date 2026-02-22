# Honeynet Automated Threat Response

This folder extends the [SOC Honeynet with AWS](../README.md) project with a Python automation script that detects brute force attacks in real time, blocks attacker IPs at the network level, and sends Slack alerts — completing the full detection-to-response loop.

---

## What This Does

Without automation, a SOC analyst has to manually review CloudWatch logs, identify malicious IPs, and block them by hand. This script automates that entire workflow:

```
CloudWatch Logs
      ↓
  Parse failed SSH login attempts
      ↓
  Count attempts per IP
      ↓
  Threshold hit (5+ attempts)?
      ↓
  Block IP via AWS Network ACL
      ↓
  Send Slack alert with details
```

---

## Architecture

| Component | Purpose |
|---|---|
| AWS CloudWatch Logs | Source of SSH authentication logs from EC2 honeypot |
| Python + boto3 | Pulls and parses logs, calls AWS APIs |
| AWS Network ACL (NACL) | Blocks attacker IPs at the subnet level (true deny) |
| Slack Webhook | Sends real-time alert with IP, attempt count, and action taken |

---

## Why NACL Instead of Security Group?

Security groups in AWS are **allow-only** — you can permit traffic but you cannot explicitly deny it. Network ACLs support true **DENY rules**, which means a blocked IP is completely cut off at the subnet level regardless of any security group rules. This is the correct layer to enforce IP blocking.

---

## Prerequisites

- Python 3.8+
- AWS CLI configured with credentials
- An IAM user or role with the following permissions:
  - `logs:FilterLogEvents`
  - `ec2:DescribeNetworkAcls`
  - `ec2:CreateNetworkAclEntry`
- A Slack incoming webhook URL
- Your honeynet CloudWatch log group collecting SSH auth logs

---

## Setup

**1. Clone the repo and navigate to the automation folder**

```bash
git clone https://github.com/machratwit/SOC-Honeynet-with-AWS.git
cd SOC-Honeynet-with-AWS/automation
```

**2. Create a virtual environment and install dependencies**

```bash
python3 -m venv venv
source venv/bin/activate        # Mac/Linux
venv\Scripts\activate           # Windows

pip install boto3 requests
```

**3. Set your environment variables**

Never hardcode secrets in your script. Set these in your terminal before running:

```bash
export LOG_GROUP_NAME="linux-auth-logs"
export SECURITY_GROUP_ID="sg-xxxxxxxxxx"
export NACL_ID="acl-xxxxxxxxxx"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export AWS_REGION="us-east-1"
```

---

## Running the Script

```bash
python automation.py
```

---

## Screenshots

### CloudWatch Log Group — SSH Authentication Failures
<img width="1178" height="615" alt="image" src="https://github.com/user-attachments/assets/52fa4550-9fb8-4730-baf3-eb33af3cf8b8" />

### NACL Before Running the Script
<img width="1631" height="286" alt="image" src="https://github.com/user-attachments/assets/0774cb02-ebab-4db9-b7a8-17a18398d824" />

### Script Running in Terminal
<img width="1107" height="727" alt="image" src="https://github.com/user-attachments/assets/c8e89851-6581-49a2-b351-c96c3737df25" />
<img width="402" height="373" alt="image" src="https://github.com/user-attachments/assets/372a49b4-3937-444b-9902-30f6a8360657" />

### Skipping over already blocked IPs
<img width="317" height="840" alt="image" src="https://github.com/user-attachments/assets/93143ebb-3362-40c9-a13d-3e32172d282d" />

### NACL After Running the Script
<img width="1450" height="406" alt="image" src="https://github.com/user-attachments/assets/cf53bfa4-0f68-4d3d-87ba-ea0ed8181b6b" />

### Slack Alert Received
<img width="359" height="637" alt="image" src="https://github.com/user-attachments/assets/b430985f-b5bd-4162-8098-1818690914e9" />

---

## Key Python Concepts Used

| Concept | Where It's Used |
|---|---|
| `boto3` AWS SDK | Connecting to CloudWatch and EC2 |
| `defaultdict` | Counting failed attempts per IP |
| `regex` | Parsing IP addresses from raw log lines |
| Pagination | Handling large CloudWatch log responses |
| Environment variables | Keeping secrets out of code |
| Deduplication via `set()` | Preventing duplicate NACL rules and double-counting events |

---

## Potential Improvements

- Schedule the script to run automatically using AWS Lambda + EventBridge (cron)
- Export blocked IPs to an S3 bucket as a running threat log
- Add IP enrichment using AbuseIPDB or VirusTotal API to include threat intel in the Slack alert
- Build a simple dashboard using CloudWatch metrics to visualize attack trends over time


