# AWS Cloud Security Monitoring Dashboard

> A production-grade cloud security monitoring system built on AWS that detects threats in real time, enforces compliance, and automates remediation across cloud infrastructure — built from scratch using custom detection logic rather than relying purely on managed services.

![AWS](https://img.shields.io/badge/AWS-Cloud-orange?logo=amazonaws)
![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)
![Security](https://img.shields.io/badge/Security-CIS%20Benchmark-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Technologies Used](#technologies-used)
- [Project Phases](#project-phases)
- [Threat Detection](#threat-detection)
- [Lambda Remediation](#lambda-remediation)
- [Key Security Decisions](#key-security-decisions)
- [Compliance Coverage](#compliance-coverage)
- [Screenshots](#screenshots)
- [Future Improvements](#future-improvements)
- [Author](#author)

---

## Project Overview

This project implements a complete cloud security monitoring system on AWS that:

- Records every API action across all AWS regions using CloudTrail
- Stores encrypted, tamper-evident audit logs in S3 with versioning enabled
- Detects threats in real time using custom CloudWatch metric filters built on CloudTrail logs
- Sends instant email alerts via SNS when security threats are detected
- Automatically remediates security incidents using a Python Lambda function
- Visualizes the complete security posture on a live CloudWatch dashboard with 6 widgets

The project intentionally builds custom threat detection logic using CloudWatch metric filters rather than relying purely on managed services like GuardDuty — demonstrating a deeper understanding of the underlying security mechanisms and giving full control over detection rules.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        AWS Account                           │
│                                                              │
│  ┌───────────┐     ┌─────────────┐     ┌─────────────────┐  │
│  │    IAM    │     │ CloudTrail  │────▶│   S3 Bucket     │  │
│  │           │     │ (all        │     │ (encrypted logs │  │
│  │ Users     │     │  regions)   │     │  + versioning)  │  │
│  │ Roles     │     └──────┬──────┘     └─────────────────┘  │
│  │ Policies  │            │                                  │
│  └───────────┘            ▼                                  │
│                   ┌───────────────┐                          │
│                   │  CloudWatch   │                          │
│                   │     Logs      │                          │
│                   └───────┬───────┘                          │
│                           │                                  │
│                           ▼                                  │
│                   ┌───────────────┐                          │
│                   │ Metric Filter │                          │
│                   │  (4 custom    │                          │
│                   │   patterns)   │                          │
│                   └───────┬───────┘                          │
│                           │                                  │
│                           ▼                                  │
│                   ┌───────────────┐                          │
│                   │  CloudWatch   │                          │
│                   │    Alarms     │                          │
│                   └───┬───────┬───┘                          │
│                       │       │                              │
│                       ▼       ▼                              │
│                  ┌─────────┐ ┌─────────────┐                │
│                  │   SNS   │ │ EventBridge │                │
│                  │  Email  │ │    Rule     │                │
│                  │ Alerts  │ └──────┬──────┘                │
│                  └─────────┘        │                        │
│                                     ▼                        │
│                             ┌───────────────┐                │
│                             │    Lambda     │                │
│                             │ (Python auto  │                │
│                             │ remediation)  │                │
│                             └───────────────┘                │
│                                                              │
│                   ┌───────────────────────┐                  │
│                   │  CloudWatch Dashboard │                  │
│                   │  (6 security widgets) │                  │
│                   └───────────────────────┘                  │
└──────────────────────────────────────────────────────────────┘
```

![Architecture Diagram](screenshots/architecture-diagram.png)

---

## Technologies Used

| Service | Purpose |
|---|---|
| AWS IAM | Identity management and least privilege access control |
| AWS CloudTrail | API audit logging across all regions |
| AWS S3 | Encrypted and versioned log storage |
| AWS CloudWatch Logs | Real time log ingestion and analysis |
| AWS CloudWatch Metrics | Custom security metric tracking |
| AWS CloudWatch Alarms | Threshold based threat alerting |
| AWS CloudWatch Dashboard | Unified real time security visibility |
| AWS SNS | Email alerting on threat detection |
| AWS EventBridge | Event driven Lambda triggering |
| AWS Lambda | Automated security remediation |
| Python 3.11 | Lambda function development |

---

## Project Phases

### Phase 1 — IAM Foundation ✅

Established the identity and access management security baseline following CIS AWS Foundations Benchmark standards.

**What was built:**

- Secured root account with MFA — root credentials locked away and never used for daily operations
- Created IAM admin user `siri-admin` with MFA enabled for all day-to-day work
- Designed and implemented a custom least privilege `SecurityAuditorRole` with a hand-written JSON policy granting read-only access to security services
- Configured account password policy requiring 12+ characters, uppercase, lowercase, numbers, symbols, 90 day expiry, and prevention of last 5 password reuse
- Set up billing alerts at $1 and $5 thresholds to prevent unexpected charges

**Custom IAM policy written:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrailStatus",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "securityhub:GetFindings",
        "cloudwatch:GetMetricData",
        "cloudwatch:DescribeAlarms",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListUsers",
        "iam:ListAccessKeys"
      ],
      "Resource": "*"
    }
  ]
}
```

This policy grants visibility into security services without any write or delete permissions — demonstrating the principle of least privilege.

---

### Phase 2 — Audit Logging ✅

Deployed a secure, tamper-evident audit logging pipeline that captures every API action in the AWS account.

**What was built:**

- Created S3 bucket with SSE-S3 encryption, versioning enabled, all public access blocked, and ACLs disabled
- Applied a bucket policy restricting writes exclusively to the CloudTrail service — no other user or service can upload to this bucket
- Configured CloudTrail trail covering all regions — prevents attackers hiding activity in unused regions
- Enabled log file validation — CloudTrail generates a cryptographic digest for every log file so tampering can be detected forensically
- Integrated CloudTrail with CloudWatch Logs for real time log streaming and analysis
- Enabled both Read and Write management events — excluded KMS and RDS Data API events to reduce noise and focus on security-relevant activity

**Key architectural decision:** Enabling all-region CloudTrail ensures that even if an attacker attempts to operate in an unexpected region to avoid detection, all activity is still captured and logged.

---

### Phase 3 — Custom Threat Detection ✅

Built four custom threat detection rules using CloudWatch metric filters on CloudTrail logs — providing SIEM-like detection capabilities with full control over detection logic.

**What was built:**

- 4 custom CloudWatch metric filters with hand-written filter patterns in the SecurityMetrics namespace
- 4 CloudWatch alarms with appropriate thresholds for each threat type
- SNS topic `SecurityAlerts` delivering email notifications on alarm trigger
- All alarms live tested and verified working end to end

See [Threat Detection](#threat-detection) section for full filter pattern details.

---

### Phase 4 — Lambda Automation ✅

Deployed a Python Lambda function that automatically responds to security threats detected by CloudWatch alarms.

**What was built:**

- Python 3.11 Lambda function with handlers for 4 distinct security event types
- EventBridge rule `SecurityAlarmTrigger` connecting CloudWatch alarm state changes to Lambda
- IAM trust policy updated to allow `lambda.amazonaws.com` service principal to assume SecurityAuditorRole
- Function tested and verified with successful execution result

See [Lambda Remediation](#lambda-remediation) section for full details.

---

### Phase 5 — Security Dashboard ✅

Built a live CloudWatch dashboard providing unified visibility across all security metrics and alarm states in one view.

**What was built:**

- Alarm status widget showing all 4 alarms at a glance in green/red state
- Line graph widgets for failed logins and unauthorized API calls over time
- Number widgets for IAM policy changes and root account usage counts
- Logs Insights widget querying CloudTrail logs directly — showing last 20 API calls in real time
- Bar chart widget showing top 10 most frequent API calls by volume

---

## Threat Detection

Four custom CloudWatch metric filters built on CloudTrail logs in the `SecurityMetrics` namespace:

### 1. Root Account Usage

```
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
```

| Setting | Value |
|---|---|
| Metric | RootAccountUsageCount |
| Threshold | Greater than 0 |
| Period | 5 minutes |
| Severity | Critical |

Root account should never be used for normal operations. Any usage indicates either a security policy violation or potential account compromise. Zero tolerance threshold — every occurrence triggers an alert immediately.

---

### 2. Failed Console Logins

```
{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication" }
```

| Setting | Value |
|---|---|
| Metric | FailedLoginCount |
| Threshold | Greater than 3 |
| Period | 5 minutes |
| Severity | Medium |

Multiple failed logins in a short period indicate a potential brute force attack on the AWS console. Threshold of 3 balances detection sensitivity with false positive reduction.

**Live tested and verified:** This alarm was deliberately triggered during development by entering incorrect passwords — the alarm entered ALARM state and an SNS email alert was received successfully, confirming the complete detection pipeline works end to end.

---

### 3. Unauthorized API Calls

```
{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }
```

| Setting | Value |
|---|---|
| Metric | UnauthorizedAPICount |
| Threshold | Greater than 5 |
| Period | 5 minutes |
| Severity | High |

Spikes in unauthorized API calls indicate an attacker probing account permissions or a compromised credential attempting to access restricted resources. Threshold of 5 accounts for occasional legitimate access denied events.

---

### 4. IAM Policy Changes

```
{ ($.eventName = "DeleteGroupPolicy") || ($.eventName = "DeleteRolePolicy") || ($.eventName = "DeleteUserPolicy") || ($.eventName = "PutGroupPolicy") || ($.eventName = "PutRolePolicy") || ($.eventName = "PutUserPolicy") || ($.eventName = "AttachGroupPolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "AttachUserPolicy") }
```

| Setting | Value |
|---|---|
| Metric | IAMPolicyChangeCount |
| Threshold | Greater than 0 |
| Period | 5 minutes |
| Severity | High |

Any IAM policy modification could indicate privilege escalation — an attacker granting themselves additional permissions. Zero tolerance threshold means every change triggers an immediate alert for review.

---

## Lambda Remediation

The `SecurityAutoRemediation` Lambda function automatically responds to security threats triggered by CloudWatch alarms via EventBridge.

### Event routing logic

```python
def lambda_handler(event, context):
    event_type = identify_event_type(event)

    if event_type == "ROOT_ACCOUNT_USAGE":
        return handle_root_usage(event)
    elif event_type == "UNAUTHORIZED_API_CALL":
        return handle_unauthorized_api(event)
    elif event_type == "IAM_POLICY_CHANGE":
        return handle_iam_change(event)
    elif event_type == "FAILED_AUTH":
        return handle_failed_auth(event)
```

### Core remediation — automatic access key deactivation

```python
def disable_compromised_access_keys(username):
    iam = boto3.client("iam")
    response = iam.list_access_keys(UserName=username)
    for key in response["AccessKeyMetadata"]:
        if key["Status"] == "Active":
            iam.update_access_key(
                UserName=username,
                AccessKeyId=key["AccessKeyId"],
                Status="Inactive"
            )
```

When a confirmed compromise is detected, this function disables all access keys for the affected IAM user — limiting attacker access within seconds of detection.

### Complete trigger pipeline

```
Threat occurs in AWS account
         │
         ▼
CloudTrail records the API call
         │
         ▼
CloudWatch metric filter detects the pattern
         │
         ▼
CloudWatch alarm enters ALARM state
         │
         ├──▶ SNS sends email alert immediately
         │
         └──▶ EventBridge rule triggers Lambda
                       │
                       ▼
              Remediation action executed
                       │
                       ▼
              Execution logged in CloudWatch
```

---

## Key Security Decisions

| Decision | Reason | Production consideration |
|---|---|---|
| MFA on root and IAM user | Prevent account takeover even if password is stolen | Hardware MFA keys for highest security |
| All-region CloudTrail | Prevent attackers hiding activity in unused regions | Enable CloudTrail Insights for ML anomaly detection |
| S3 versioning enabled | Recover logs if attacker attempts deletion | Add S3 Object Lock in Compliance mode for WORM |
| Log file validation | Detect log tampering during forensic investigation | Required for chain of custody evidence |
| Least privilege IAM role | Limit blast radius if security auditor credentials are compromised | Implement permission boundaries for additional guardrails |
| Excluded KMS events | KMS generates thousands of automatic decrypt events — reduces noise | Re-enable specifically when auditing encryption key access |
| Excluded RDS Data API | No RDS in project — reduces irrelevant log volume | Enable when RDS databases are added |
| Custom metric filters over GuardDuty | Full control over detection rules — demonstrates deeper security understanding | Use both in production for layered detection coverage |
| Block all S3 public access | Prevents accidental data exposure — cause of many real-world breaches | Enable S3 access logging for additional audit trail |
| Bucket policy restricts to CloudTrail only | Prevents log contamination from other services or users | Add MFA delete requirement for production environments |

---

## Compliance Coverage

| Framework | Controls Covered |
|---|---|
| CIS AWS Foundations Benchmark | MFA on root account, IAM password policy, CloudTrail enabled in all regions, log file validation enabled, S3 public access blocked |
| NIST SP 800-53 | Audit and accountability (AU), Access control (AC), Incident response (IR), Configuration management (CM) |
| AWS Foundational Security Best Practices | IAM least privilege, S3 encryption at rest, CloudTrail enabled, CloudWatch alarms on security events |

**Note on cost-conscious architecture:** CloudTrail Insights, Security Hub, and GuardDuty were evaluated and documented but intentionally excluded from this implementation to manage costs during development. In a production environment all three would be enabled to achieve full compliance benchmark coverage. This reflects real-world cloud engineering judgment — balancing security coverage with operational cost.

---

## Screenshots

### Architecture Diagram
![Architecture](screenshots/architecture-diagram.png)

### Security Dashboard — 6 widgets live
![Dashboard](screenshots/dashboard.png)

### CloudWatch Alarms — All 4 active
![Alarms](screenshots/alarms.png)

### Failed Login Detection — Alarm triggered during live test
![Failed Login Alarm](screenshots/failed-login-alarm.png)

### Failed Login Alarm Graph — Metric spike clearly visible
![Failed Login Alarm Graph](screenshots/alarm-graph.png)

### SNS Email Alert — Received during live test
![Alarm Email](screenshots/alarm-email.png)

### Lambda Function — Test execution succeeded
![Lambda Test](screenshots/lambda-test.png)

### IAM Security Setup
![IAM Setup](screenshots/iam-setup.png)

### S3 Secure Log Storage — Encryption and versioning enabled
![S3 Bucket](screenshots/s3-bucket.png)

---

## Future Improvements

| Improvement | Reason |
|---|---|
| Enable GuardDuty | ML-based threat detection layered on top of custom metric filters |
| Enable Security Hub | Centralised compliance scoring against CIS, NIST, and AWS best practices |
| Enable CloudTrail Insights | Anomaly detection for unusual API call volume and error rate spikes |
| Add VPC Flow Logs | Network traffic monitoring to detect lateral movement and port scanning |
| Enable CloudTrail Network Activity Events | Monitor VPC endpoint traffic for unauthorized internal network access |
| Upgrade to SSE-KMS encryption | Stricter key management and granular access control on log files |
| Add S3 Object Lock in Compliance mode | WORM storage preventing log deletion — required for PCI-DSS compliance |
| Add MFA delete on S3 bucket | Extra protection requiring MFA to permanently delete log files |
| Implement AWS Config Rules | Continuous compliance checking on resource configurations in real time |
| Add CloudTrail Lake | Long term log retention with advanced SQL querying for forensic investigation |

---

## Repository Structure

```
aws-cloud-security-dashboard/
├── README.md
├── policies/
│   ├── security-auditor-policy.json
│   └── s3-cloudtrail-bucket-policy.json
├── lambda/
│   ├── auto_remediate.py
│   ├── requirements.txt
│   └── README.md
├── cloudwatch/
│   └── metric-filters.md
└── screenshots/
    ├── architecture-diagram.png
    ├── dashboard.png
    ├── alarms.png
    ├── failed-login-alarm.png
    ├── alarm-graph.png
    ├── alarm-email.png
    ├── lambda-test.png
    ├── iam-setup.png
    └── s3-bucket.png
```

---

## Author

**Siri Bandaru**
[![LinkedIn](https://img.shields.io/badge/LinkedIn-SiriBandaru-blue?logo=linkedin)](https://linkedin.com/in/SiriBandaru)
[![GitHub](https://img.shields.io/badge/GitHub-SiriBandaru13-black?logo=github)](https://github.com/SiriBandaru13)


---

*Built as part of a hands-on cloud security learning project targeting real-world security engineering skills aligned with industry roles in cloud security engineering.*
