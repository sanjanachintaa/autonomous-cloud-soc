import boto3
import requests
import json
from datetime import datetime

# Connect to fake local AWS
s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

BUCKET_NAME = 'vulnerable-soc-bucket'
SLACK_WEBHOOK = 'https://hooks.slack.com/services/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'  # Paste your Slack URL here

def fix_public_bucket(bucket_name):
    print(f"🔧 Auto-remediating {bucket_name}...")
    
    try:
        s3_client.put_bucket_acl(
            Bucket=bucket_name,
            ACL='private'
        )
        print(f"✅ Bucket {bucket_name} is now PRIVATE!")
        return True
    except Exception as e:
        print(f"❌ Failed to remediate: {e}")
        return False

def send_slack_alert(threat_log, ai_analysis, fixed):
    status = "✅ AUTO-FIXED" if fixed else "❌ FIX FAILED"
    
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "🚨 SOC ALERT: Threat Detected & Remediated"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Bucket:*\n{threat_log['bucket']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{threat_log['severity']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat:*\n{threat_log['threat']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*AI Analysis:*\n{ai_analysis[:500]}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🕐 {str(datetime.now())}"
                    }
                ]
            }
        ]
    }
    
    response = requests.post(SLACK_WEBHOOK, json=message)
    if response.status_code == 200:
        print("📨 Slack alert sent!")
    else:
        print(f"❌ Slack alert failed: {response.status_code}")

def respond_to_threat(threat_log, ai_analysis):
    print("\n🚨 THREAT CONFIRMED - Starting auto-remediation...")
    fixed = fix_public_bucket(threat_log['bucket'])
    send_slack_alert(threat_log, ai_analysis, fixed)
    return fixed

# Test it
test_threat = {
    "timestamp": str(datetime.now()),
    "bucket": BUCKET_NAME,
    "threat": "PUBLIC_BUCKET_DETECTED",
    "severity": "CRITICAL",
    "detail": "S3 bucket is publicly accessible!"
}

test_analysis = "AI confirmed critical threat. Public S3 bucket violates CIS AWS Benchmark rule 2.1.5."

respond_to_threat(test_threat, test_analysis)