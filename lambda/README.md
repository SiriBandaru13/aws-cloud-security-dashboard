# Lambda Auto-Remediation Function

## What it does
Automatically responds to security threats detected by CloudWatch alarms.

## Trigger
EventBridge rule monitors CloudWatch alarm state changes and 
triggers this function when alarms enter ALARM state.

## Security events handled

| Event | Severity | Action |
|---|---|---|
| Root account usage | Critical | Alert + log full context |
| Unauthorized API call | High | Alert + log source details |
| IAM policy change | High | Alert + generate credential report |
| Failed authentication | Medium | Alert + log source IP |

## Core remediation capability
The disable_compromised_access_keys function can automatically 
disable all access keys for a compromised IAM user — limiting 
attacker access within seconds of detection.

## How to deploy
1. Go to AWS Lambda → Create function
2. Runtime: Python 3.11
3. Paste auto_remediate.py code
4. Set timeout to 30 seconds
5. Attach SecurityAuditorRole IAM role
6. Create EventBridge trigger

## Environment variables
None required — all configuration is handled through IAM roles.
