from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
import boto3
import json
import os
import asyncio
from datetime import datetime
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import ollama
import requests
from dotenv import load_dotenv
from siem import correlate_threats, assess_overall_risk, build_attack_timeline, get_threat_score

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BUCKET_NAME = 'vulnerable-soc-bucket'
SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK')

s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

ec2_client = boto3.client(
    'ec2',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

threat_history = []
alert_queue = []

def load_knowledge_base():
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    if os.path.exists("./ai_agent/chroma_db"):
        return Chroma(persist_directory="./ai_agent/chroma_db", embedding_function=embeddings)
    return None

db = load_knowledge_base()

# ─── THREAT DETECTORS ─────────────────────────────────

def check_public_bucket():
    try:
        acl = s3_client.get_bucket_acl(Bucket=BUCKET_NAME)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                return {
                    "id": len(threat_history) + 1,
                    "timestamp": str(datetime.now()),
                    "bucket": BUCKET_NAME,
                    "threat": "PUBLIC_BUCKET_DETECTED",
                    "severity": "CRITICAL",
                    "detail": "S3 bucket is publicly accessible!",
                    "fixed": False,
                    "analysis": "",
                    "cis_rule": "CIS AWS 2.1.5",
                    "score": get_threat_score("PUBLIC_BUCKET_DETECTED")
                }
        return None
    except Exception as e:
        print(f"DEBUG public bucket error: {e}")
        return None

def check_versioning():
    try:
        result = s3_client.get_bucket_versioning(Bucket=BUCKET_NAME)
        status = result.get('Status', '')
        if status != 'Enabled':
            return {
                "id": len(threat_history) + 1,
                "timestamp": str(datetime.now()),
                "bucket": BUCKET_NAME,
                "threat": "VERSIONING_DISABLED",
                "severity": "HIGH",
                "detail": "S3 bucket versioning is disabled — data loss risk!",
                "fixed": False,
                "analysis": "",
                "cis_rule": "CIS AWS 2.1.3",
                "score": get_threat_score("VERSIONING_DISABLED")
            }
        return None
    except Exception as e:
        print(f"DEBUG versioning error: {e}")
        return None

def check_open_security_group():
    try:
        sgs = ec2_client.describe_security_groups(GroupNames=['wide-open-sg'])
        for sg in sgs['SecurityGroups']:
            for perm in sg.get('IpPermissions', []):
                if perm.get('FromPort') == 22:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            return {
                                "id": len(threat_history) + 1,
                                "timestamp": str(datetime.now()),
                                "bucket": "wide-open-sg",
                                "threat": "OPEN_SECURITY_GROUP_SSH",
                                "severity": "CRITICAL",
                                "detail": "Port 22 (SSH) is open to the entire internet!",
                                "fixed": False,
                                "analysis": "",
                                "cis_rule": "CIS AWS 5.2",
                                "score": get_threat_score("OPEN_SECURITY_GROUP_SSH")
                            }
        return None
    except Exception as e:
        print(f"DEBUG sg error: {e}")
        return None

# ─── AI ANALYSIS ──────────────────────────────────────

def analyze_threat_with_ai(threat):
    if not db:
        return "Knowledge base not loaded"
    try:
        rules = db.similarity_search(f"{threat['threat']} security rule", k=2)
        rules_text = "\n".join([doc.page_content for doc in rules])
        prompt = f"""
        Analyze this cloud security threat and respond in JSON only.
        THREAT: {json.dumps(threat)}
        RULES: {rules_text[:300]}
        Respond: {{"severity": "{threat['severity']}", "threat_confirmed": true, "explanation": "brief explanation", "recommended_action": "action", "cis_rule": "{threat.get('cis_rule', 'Unknown')}"}}
        """
        response = ollama.chat(model='tinyllama', messages=[{'role': 'user', 'content': prompt}])
        return response['message']['content']
    except Exception as e:
        return f"AI analysis error: {e}"

# ─── REMEDIATION ──────────────────────────────────────

def remediate_threat(threat):
    try:
        if threat['threat'] == 'PUBLIC_BUCKET_DETECTED':
            s3_client.put_bucket_acl(Bucket=BUCKET_NAME, ACL='private')
            return True
        elif threat['threat'] == 'VERSIONING_DISABLED':
            s3_client.put_bucket_versioning(
                Bucket=BUCKET_NAME,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            return True
        elif threat['threat'] == 'OPEN_SECURITY_GROUP_SSH':
            ec2_client.revoke_security_group_ingress(
                GroupName='wide-open-sg',
                IpPermissions=[{
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            return True
    except Exception as e:
        print(f"Remediation error: {e}")
        return False

# ─── API ROUTES ───────────────────────────────────────

@app.get("/")
def root():
    return {"status": "CloudSentinel API running"}

@app.get("/api/status")
def get_status():
    return {"status": "running", "timestamp": str(datetime.now()), "bucket": BUCKET_NAME}

@app.get("/api/threats")
def get_threats():
    return {"threats": threat_history}

@app.get("/api/threats/{threat_id}")
def get_threat_detail(threat_id: int):
    threat = next((t for t in threat_history if t['id'] == threat_id), None)
    if not threat:
        return {"error": "Threat not found"}
    correlations = correlate_threats(threat_history)
    related = [c for c in correlations if threat['threat'] in c.get('threats_involved', [])]
    return {"threat": threat, "related_correlations": related}

@app.get("/api/metrics")
def get_metrics():
    total = len(threat_history)
    fixed = len([t for t in threat_history if t.get("fixed")])
    critical = len([t for t in threat_history if t.get("severity") == "CRITICAL"])
    return {
        "total_threats": total,
        "auto_fixed": fixed,
        "critical": critical,
        "rules_active": 8
    }

@app.get("/api/alerts/stream")
async def stream_alerts():
    async def event_generator():
        last_count = 0
        while True:
            if len(alert_queue) > last_count:
                new_alerts = alert_queue[last_count:]
                for alert in new_alerts:
                    yield f"data: {json.dumps(alert)}\n\n"
                last_count = len(alert_queue)
            await asyncio.sleep(1)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/api/scan")
def run_scan():
    detected_threats = []

    public_threat = check_public_bucket()
    if public_threat:
        detected_threats.append(public_threat)

    versioning_threat = check_versioning()
    if versioning_threat:
        detected_threats.append(versioning_threat)

    sg_threat = check_open_security_group()
    if sg_threat:
        detected_threats.append(sg_threat)

    if not detected_threats:
        return {"detected": False, "message": "All clear — no threats found"}

    for threat in detected_threats:
        threat["analysis"] = analyze_threat_with_ai(threat)
        threat["fixed"] = remediate_threat(threat)
        threat_history.append(threat)
        alert_queue.append(threat)

        if SLACK_WEBHOOK:
            requests.post(SLACK_WEBHOOK, json={
                "text": f"🚨 *CloudSentinel Alert*\nThreat: {threat['threat']}\nSeverity: {threat['severity']}\nCIS Rule: {threat.get('cis_rule', 'N/A')}\nStatus: {'✅ AUTO-FIXED' if threat['fixed'] else '❌ FIX FAILED'}\nTime: {threat['timestamp']}"
            })

    return {"detected": True, "threats": detected_threats}

@app.post("/api/reset-bucket")
def reset_bucket():
    try:
        s3_client.put_bucket_acl(Bucket=BUCKET_NAME, ACL='public-read')
        return {"message": "Bucket reset to public"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/reset-versioning")
def reset_versioning():
    try:
        s3_client.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={'Status': 'Suspended'}
        )
        return {"message": "Versioning suspended"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/reset-security-group")
def reset_security_group():
    try:
        ec2_client.authorize_security_group_ingress(
            GroupName='wide-open-sg',
            IpPermissions=[{
                'IpProtocol': 'tcp',
                'FromPort': 22,
                'ToPort': 22,
                'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
            }]
        )
        return {"message": "Security group reset to vulnerable"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/siem/risk")
def get_risk_assessment():
    correlations = correlate_threats(threat_history)
    risk = assess_overall_risk(threat_history, correlations)
    return {"risk": risk, "correlations": correlations}

@app.get("/api/siem/timeline")
def get_timeline():
    timeline = build_attack_timeline(threat_history)
    return {"timeline": timeline}

@app.get("/api/siem/correlations")
def get_correlations():
    correlations = correlate_threats(threat_history)
    return {"correlations": correlations}