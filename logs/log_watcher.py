import boto3
import json
import time
from datetime import datetime

# Connect to our fake local AWS
s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

BUCKET_NAME = 'vulnerable-soc-bucket'

def check_bucket_security():
    print(f"[{datetime.now()}] Checking bucket security...")
    
    try:
        # Check if bucket is public
        acl = s3_client.get_bucket_acl(Bucket=BUCKET_NAME)
        
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            # This URI means the bucket is public
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                log_event = {
                    "timestamp": str(datetime.now()),
                    "bucket": BUCKET_NAME,
                    "threat": "PUBLIC_BUCKET_DETECTED",
                    "severity": "CRITICAL",
                    "detail": "S3 bucket is publicly accessible!"
                }
                print(f"🚨 THREAT DETECTED: {json.dumps(log_event, indent=2)}")
                return log_event
                
        print("✅ Bucket looks secure.")
        return None
        
    except Exception as e:
        print(f"Error checking bucket: {e}")
        return None

# Keep watching every 10 seconds
while True:
    threat = check_bucket_security()
    time.sleep(10)