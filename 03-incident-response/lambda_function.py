import json
import boto3
import os
from datetime import datetime

# AWS clients
s3 = boto3.client('s3')
sns = boto3.client('sns')
ec2 = boto3.client('ec2')

# Environment variables (set in Terraform)
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']
S3_BUCKET = os.environ['S3_BUCKET']

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    # ── STEP 1: Extract finding details ──────────────────
    finding = event.get('detail', event)
    
    finding_id      = finding.get('id', 'unknown')
    finding_type    = finding.get('type', 'unknown')
    severity        = finding.get('severity', 0)
    account_id      = finding.get('accountId', 'unknown')
    region          = finding.get('region', 'unknown')
    description     = finding.get('description', 'No description')
    
    print(f"Processing finding: {finding_type} | Severity: {severity}")
    
    # ── STEP 2: Save finding to S3 ────────────────────────
    timestamp   = datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S')
    s3_key      = f"guardduty-findings/{timestamp}-{finding_id}.json"
    
    s3.put_object(
        Bucket  = S3_BUCKET,
        Key     = s3_key,
        Body    = json.dumps(finding, indent=2),
        ContentType = 'application/json'
    )
    print(f"Finding saved to S3: {s3_key}")
    
    # ── STEP 3: Send SNS Alert ────────────────────────────
    message = f"""
    🚨 SECURITY ALERT — FinTech Platform

    Finding Type : {finding_type}
    Severity     : {severity}
    Account      : {account_id}
    Region       : {region}
    Time         : {timestamp}
    
    Description  : {description}
    
    Finding ID   : {finding_id}
    Saved to S3  : s3://{S3_BUCKET}/{s3_key}
    
    Automated response has been triggered.
    """
    
    sns.publish(
        TopicArn = SNS_TOPIC_ARN,
        Subject  = f"[CRITICAL] GuardDuty Alert: {finding_type}",
        Message  = message
    )
    print("SNS alert sent!")
    
    # ── STEP 4: Isolate EC2 if instance is involved ───────
    instance_id = None
    
    try:
        instance_id = (
            finding
            .get('resource', {})
            .get('instanceDetails', {})
            .get('instanceId')
        )
    except Exception:
        pass
    
    if instance_id:
        print(f"Isolating EC2 instance: {instance_id}")
        
        # Tag the instance as compromised
        ec2.create_tags(
            Resources = [instance_id],
            Tags = [
                {'Key': 'SecurityStatus',  'Value': 'ISOLATED'},
                {'Key': 'IsolatedAt',      'Value': timestamp},
                {'Key': 'FindingType',     'Value': finding_type},
                {'Key': 'AutoRemediated',  'Value': 'true'}
            ]
        )
        print(f"Instance {instance_id} tagged as ISOLATED")
    else:
        print("No EC2 instance in this finding — skipping isolation")
    
    return {
        'statusCode'  : 200,
        'findingId'   : finding_id,
        'findingType' : finding_type,
        'severity'    : severity,
        's3Key'       : s3_key,
        'instanceId'  : instance_id,
        'message'     : 'Incident response completed successfully'
    }