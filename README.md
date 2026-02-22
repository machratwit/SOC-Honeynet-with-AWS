# SOC-Honeynet-with-AWS

**Overview**

This project demonstrates how I designed and deployed a small-scale Security Operations Center environment inside AWS using a deliberately exposed honeynet. The purpose was to simulate real-world attacker activity, collect telemetry, detect threats, and perform investigations using native cloud security tooling.

This lab mirrors real SOC workflows including monitoring, detection engineering, incident investigation, and environment hardening.

## Objectives

- Deploy intentionally exposed infrastructure to attract malicious traffic

- Centralize logs for analysis

- Detect suspicious behavior using native threat detection

- Investigate findings like a SOC analyst

- Demonstrate blue team skills using real attack data

## Architecture

<img width="989" height="681" alt="Architecture Diagram drawio(2)" src="https://github.com/user-attachments/assets/6023efd7-e86a-429b-b822-5e96f50b6427" />

Components:

- VPC with public subnet

- Internet Gateway for external exposure

- Two EC2 honeypot instances

- VPC Flow Logs

- CloudWatch Logs

- GuardDuty threat detection

## VPC Configuration

<img width="1490" height="381" alt="image" src="https://github.com/user-attachments/assets/525d860d-7e7a-43c0-9db4-0b29ba6d9837" />
<img width="1610" height="361" alt="image" src="https://github.com/user-attachments/assets/80f8f4ce-1ac4-40cb-9862-37569d7f110c" />


Created isolated network environment with public routing.

Configuration:

- CIDR range: 10.0.0.0/16

- Public subnet: 10.0.1.0/24

- Internet Gateway attached

- Route table allowing 0.0.0.0/0

## Security Group Configuration

<img width="1536" height="230" alt="image" src="https://github.com/user-attachments/assets/c9e9e7f7-3876-4a7a-9059-d1ebd880769e" />
<img width="1626" height="288" alt="image" src="https://github.com/user-attachments/assets/8952ddb5-e83b-4118-a075-329b371999c0" />

Inbound rules:

- Port 22 is open to the world

- Port 3389 is open to the world

Outbound:

- Allow all

## Honeypot Instances

**Windows Server Honeypot**

<img width="1593" height="433" alt="image" src="https://github.com/user-attachments/assets/52487aca-fb43-43c4-90a6-e7ac06d043b7" />

Purpose:

- Capture RDP brute force attempts

- Generate authentication logs

Configuration:

- Public IP enabled

- Weak administrator credentials intentionally used

- Security logging enabled

**Linux Honeypot**

<img width="1586" height="439" alt="image" src="https://github.com/user-attachments/assets/fe4099ca-627f-4694-a1cd-5bd7b82c4ca5" />

Purpose:

- Capture SSH brute force attempts

- Record login attempts and scanning activity

Configuration:

- Password authentication enabled

- Auth logs forwarded to CloudWatch


## Logging and Monitoring

<img width="1008" height="234" alt="image" src="https://github.com/user-attachments/assets/475cec50-55fc-433b-8f72-ef17b894c69b" />

**VPC Flow Logs**

Captured network traffic metadata.

Used to detect:

- Port scanning

- Repeated connection attempts

- Suspicious source IPs

**CloudWatch Logs****

<img width="905" height="446" alt="image" src="https://github.com/user-attachments/assets/6f19cd7d-fe5b-4c0d-9f6b-a9a572d42c7f" />

Centralized log repository.

Collected:

- Windows security logs

- Linux authentication logs

- Flow logs

**Linux authentication logs**
<img width="1201" height="552" alt="image" src="https://github.com/user-attachments/assets/e8abe6eb-dbc4-4a29-9e35-abac463c356c" />
**Windows security logs**
<img width="1397" height="661" alt="image" src="https://github.com/user-attachments/assets/0c207b03-3843-46d4-8177-43cd0b913318" />


## Threat Detection

**Guard Duty**

<img width="1408" height="362" alt="image" src="https://github.com/user-attachments/assets/08514806-0456-4365-83dc-91c186023b7e" />
Findings observed:

- SSH brute force attempts

- RDP brute force attempts

- Reconnaissance activity

- Suspicious IP reputation alerts

## Detection Engineering
**Custom Log Queries**
Windows Logs
<img width="1265" height="735" alt="image" src="https://github.com/user-attachments/assets/2600ba09-6ca1-4d1b-ae52-3a723646ffc1" />
<img width="1243" height="535" alt="image" src="https://github.com/user-attachments/assets/8b673d92-5269-453c-8093-9ca36478251f" />
Linux Logs
<img width="1092" height="676" alt="image" src="https://github.com/user-attachments/assets/11e64fec-9aad-4ac4-b881-071fcb459c19" />
<img width="1099" height="478" alt="image" src="https://github.com/user-attachments/assets/23e57ee5-444d-4ddc-88ae-8f11ac362a4b" />

Created manual detection queries using Logs Insights.

Example detection logic:

- Identify more than five failed logins from one IP

- Detect repeated authentication failures across instances

## Honeynet Automated Threat Response
Here is the folder that has the [automated blocking ip](/automation/README.md)

<img width="1107" height="727" alt="image" src="https://github.com/user-attachments/assets/c8e89851-6581-49a2-b351-c96c3737df25" />

## Incident Investigation Process

When a finding appeared:

1. Reviewed GuardDuty alert details

2. Identified attacker IP

3. Pivoted into VPC Flow Logs

4. Correlated timestamps with host logs

5. Determined attack type

6. Documented timeline

## Hardening Phase

After collecting attack data, security controls were implemented.

Changes:

- Restricted inbound rules

- Disabled password authentication

- Limited management access

## Skills Demonstrated

- Cloud security architecture

- Threat detection

- Log analysis

- Incident response

- Network monitoring

- Security hardening

- SOC workflow simulation
