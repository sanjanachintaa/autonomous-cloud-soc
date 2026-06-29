from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import boto3
import json
import os
from datetime import datetime
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import ollama
import requests

app = FastAPI()

# Allow React to talk to this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BUCKET_NAME = 'vulnerable-soc-bucket'
SLACK_WEBHOOK = 'https://hooks.slack.com/services/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'

s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

# In memory threat log
threat_history = []

def load_knowledge_base():
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    if os.path.exists("./ai_agent/chroma_db"):
        return Chroma(persist_directory="./ai_agent/chroma_db", embedding_function=embeddings)
    return None

db = load_knowledge_base()

# ─── API ROUTES ───────────────────────────────────────

@app.get("/")
def root():
    return {"status": "CloudSentinel API running"}

@app.get("/api/status")
def get_status():
    return {
        "status": "running",
        "timestamp": str(datetime.now()),
        "bucket": BUCKET_NAME
    }

@app.get("/api/threats")
def get_threats():
    return {"threats": threat_history}

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

@app.post("/api/scan")
def run_scan():
    try:
        acl = s3_client.get_bucket_acl(Bucket=BUCKET_NAME)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                threat = {
                    "id": len(threat_history) + 1,
                    "timestamp": str(datetime.now()),
                    "bucket": BUCKET_NAME,
                    "threat": "PUBLIC_BUCKET_DETECTED",
                    "severity": "CRITICAL",
                    "detail": "S3 bucket is publicly accessible!",
                    "fixed": False,
                    "analysis": ""
                }

                # AI Analysis
                if db:
                    rules = db.similarity_search("S3 public bucket security rule", k=2)
                    rules_text = "\n".join([doc.page_content for doc in rules])
                    prompt = f"""
                    Analyze this cloud security threat and respond in JSON only.
                    THREAT: {json.dumps(threat)}
                    RULES: {rules_text[:300]}
                    Respond: {{"severity": "CRITICAL", "threat_confirmed": true, "explanation": "brief explanation", "recommended_action": "action"}}
                    """
                    response = ollama.chat(model='tinyllama', messages=[{'role': 'user', 'content': prompt}])
                    threat["analysis"] = response['message']['content']

                # Auto remediate
                s3_client.put_bucket_acl(Bucket=BUCKET_NAME, ACL='private')
                threat["fixed"] = True

                threat_history.append(threat)

                # Slack alert
                requests.post(SLACK_WEBHOOK, json={
                    "text": f"🚨 *CloudSentinel Alert*\nThreat: {threat['threat']}\nStatus: ✅ AUTO-FIXED\nTime: {threat['timestamp']}"
                })

                return {"detected": True, "threat": threat}

        return {"detected": False, "message": "All clear — no threats found"}

    except Exception as e:
        return {"error": str(e)}

@app.post("/api/reset-bucket")
def reset_bucket():
    try:
        s3_client.put_bucket_acl(Bucket=BUCKET_NAME, ACL='public-read')
        return {"message": "Bucket reset to public (vulnerable) for testing"}
    except Exception as e:
        return {"error": str(e)}