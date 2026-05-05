# CloudWatch Metric Filters

## Overview
Custom metric filters built on CloudTrail logs for threat detection
without relying on managed services like GuardDuty.

## Filter 1 — Root account usage
```
{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }
```
Alarm threshold: Greater than 0 in 5 minutes
Severity: Critical

## Filter 2 — Failed console logins
```
{ $.eventName = "ConsoleLogin" && $.errorMessage = "Failed authentication" }
```
Alarm threshold: Greater than 3 in 5 minutes
Severity: Medium

## Filter 3 — Unauthorized API calls
```
{ ($.errorCode = "AccessDenied") || ($.errorCode = "UnauthorizedOperation") }
```
Alarm threshold: Greater than 5 in 5 minutes
Severity: High

## Filter 4 — IAM policy changes
```
{ ($.eventName = "DeleteGroupPolicy") || ($.eventName = "DeleteRolePolicy") || ($.eventName = "DeleteUserPolicy") || ($.eventName = "PutGroupPolicy") || ($.eventName = "PutRolePolicy") || ($.eventName = "PutUserPolicy") || ($.eventName = "AttachGroupPolicy") || ($.eventName = "AttachRolePolicy") || ($.eventName = "AttachUserPolicy") }
```
Alarm threshold: Greater than 0 in 5 minutes
Severity: High
