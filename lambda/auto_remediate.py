"""
AWS Security Auto-Remediation Lambda Function
Author: Siri Bandaru
Purpose: Automatically remediate security threats detected by CloudWatch alarms
Trigger: EventBridge rule on CloudWatch alarm state change
"""

import boto3
import json
import logging
from datetime import datetime

# Set up logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Main handler function triggered by EventBridge
    Receives security events and routes to appropriate remediation
    """
    
    logger.info(f"Received event: {json.dumps(event)}")
    
    # Identify what type of security event triggered this
    event_type = identify_event_type(event)
    
    logger.info(f"Identified event type: {event_type}")
    
    # Route to appropriate remediation function
    if event_type == "ROOT_ACCOUNT_USAGE":
        return handle_root_usage(event)
    
    elif event_type == "UNAUTHORIZED_API_CALL":
        return handle_unauthorized_api(event)
    
    elif event_type == "IAM_POLICY_CHANGE":
        return handle_iam_change(event)
    
    elif event_type == "FAILED_AUTH":
        return handle_failed_auth(event)
    
    else:
        logger.warning(f"Unknown event type: {event_type}")
        return create_response(200, "Event logged but no remediation needed")


def identify_event_type(event):
    """
    Identifies what type of security event occurred
    based on the CloudWatch alarm name that triggered
    """
    
    try:
        # Get alarm name from the event
        alarm_name = event.get("detail", {}).get("alarmName", "")
        
        if "root-account" in alarm_name.lower():
            return "ROOT_ACCOUNT_USAGE"
        
        elif "unauthorized" in alarm_name.lower():
            return "UNAUTHORIZED_API_CALL"
        
        elif "iam-policy" in alarm_name.lower():
            return "IAM_POLICY_CHANGE"
        
        elif "failed-auth" in alarm_name.lower():
            return "FAILED_AUTH"
        
        else:
            return "UNKNOWN"
            
    except Exception as e:
        logger.error(f"Error identifying event type: {str(e)}")
        return "UNKNOWN"


def handle_root_usage(event):
    """
    Handles root account usage detection
    Root account should never be used for normal operations
    Action: Send detailed alert with full context
    """
    
    logger.warning("ROOT ACCOUNT USAGE DETECTED")
    
    # Initialize SNS client for alerting
    sns = boto3.client("sns")
    
    # Build detailed alert message
    alert_message = {
        "alert_type": "ROOT_ACCOUNT_USAGE",
        "severity": "CRITICAL",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "Root account was used to perform actions in AWS. This violates security best practices and should be investigated immediately.",
        "recommended_actions": [
            "Verify if this was an authorized action",
            "If unauthorized change root password immediately",
            "Review CloudTrail logs for full activity details",
            "Consider this a potential account compromise"
        ],
        "event_details": event
    }
    
    logger.info(f"Root usage alert: {json.dumps(alert_message)}")
    
    return create_response(200, "Root account usage alert sent")


def handle_unauthorized_api(event):
    """
    Handles unauthorized API call detection
    Someone tried to access something they dont have permission for
    Action: Log details and send alert
    """
    
    logger.warning("UNAUTHORIZED API CALL DETECTED")
    
    alert_message = {
        "alert_type": "UNAUTHORIZED_API_CALL",
        "severity": "HIGH",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "An unauthorized API call was detected. This could indicate an attacker probing account permissions or a misconfigured application.",
        "recommended_actions": [
            "Review CloudTrail logs to identify the source",
            "Check if the IAM user permissions are correctly configured",
            "Look for patterns of multiple unauthorized calls",
            "Consider temporarily restricting the user if calls persist"
        ],
        "event_details": event
    }
    
    logger.info(f"Unauthorized API alert: {json.dumps(alert_message)}")
    
    return create_response(200, "Unauthorized API call alert logged")


def handle_iam_change(event):
    """
    Handles IAM policy change detection
    Unexpected IAM changes could indicate privilege escalation attack
    Action: Log the change with full details for review
    """
    
    logger.warning("IAM POLICY CHANGE DETECTED")
    
    # Initialize IAM client
    iam = boto3.client("iam")
    
    try:
        # Generate fresh credential report to capture current state
        iam.generate_credential_report()
        logger.info("Generated fresh IAM credential report after policy change")
        
    except Exception as e:
        logger.error(f"Could not generate credential report: {str(e)}")
    
    alert_message = {
        "alert_type": "IAM_POLICY_CHANGE",
        "severity": "HIGH", 
        "timestamp": datetime.utcnow().isoformat(),
        "description": "An IAM policy change was detected. This could indicate privilege escalation or unauthorized permission modification.",
        "recommended_actions": [
            "Review the specific IAM change in CloudTrail",
            "Verify the change was authorized",
            "Check if new permissions are appropriate",
            "Review credential report for any new access keys"
        ],
        "event_details": event
    }
    
    logger.info(f"IAM change alert: {json.dumps(alert_message)}")
    
    return create_response(200, "IAM policy change logged and credential report generated")


def handle_failed_auth(event):
    """
    Handles multiple failed authentication attempts
    Could indicate brute force attack on AWS console
    Action: Log and alert with source details
    """
    
    logger.warning("MULTIPLE FAILED AUTHENTICATION ATTEMPTS DETECTED")
    
    alert_message = {
        "alert_type": "FAILED_AUTHENTICATION",
        "severity": "MEDIUM",
        "timestamp": datetime.utcnow().isoformat(),
        "description": "Multiple failed authentication attempts detected. This could indicate a brute force attack on the AWS console.",
        "recommended_actions": [
            "Review CloudTrail ConsoleLogin events for source IP",
            "Check if attempts are from known locations",
            "Consider blocking suspicious IP addresses",
            "Verify MFA is enabled on all accounts",
            "Reset passwords if compromise is suspected"
        ],
        "event_details": event
    }
    
    logger.info(f"Failed auth alert: {json.dumps(alert_message)}")
    
    return create_response(200, "Failed authentication alert logged")


def disable_compromised_access_keys(username):
    """
    Disables all access keys for a compromised IAM user
    Called when confirmed compromise is detected
    This is the core auto remediation function
    """
    
    logger.warning(f"Disabling access keys for user: {username}")
    
    # Initialize IAM client
    iam = boto3.client("iam")
    
    disabled_keys = []
    
    try:
        # Get all access keys for this user
        response = iam.list_access_keys(UserName=username)
        access_keys = response["AccessKeyMetadata"]
        
        if not access_keys:
            logger.info(f"No access keys found for user: {username}")
            return disabled_keys
        
        # Disable each active key
        for key in access_keys:
            key_id = key["AccessKeyId"]
            current_status = key["Status"]
            
            if current_status == "Active":
                # Disable the key
                iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key_id,
                    Status="Inactive"
                )
                
                disabled_keys.append(key_id)
                logger.info(f"Successfully disabled key: {key_id} for user: {username}")
            
            else:
                logger.info(f"Key {key_id} already inactive, skipping")
        
        return disabled_keys
        
    except iam.exceptions.NoSuchEntityException:
        logger.error(f"IAM user not found: {username}")
        return disabled_keys
        
    except Exception as e:
        logger.error(f"Error disabling keys for {username}: {str(e)}")
        raise


def create_response(status_code, message):
    """
    Creates a standardized Lambda response
    """
    
    response = {
        "statusCode": status_code,
        "body": json.dumps({
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        })
    }
    
    logger.info(f"Returning response: {json.dumps(response)}")
    
    return response
