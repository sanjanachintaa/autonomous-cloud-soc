import boto3
import json
import time
import ollama
import os
from datetime import datetime
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import requests
from dotenv import load_dotenv
import os
load_dotenv()

SLACK_WEBHOOK = os.getenv('SLACK_WEBHOOK')

# ─── CONFIG ───────────────────────────────────────────
BUCKET_NAME = 'vulnerable-soc-bucket'

s3_client = boto3.client(
    's3',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='fake',
    aws_secret_access_key='fake',
    region_name='us-east-1'
)

# ─── STEP 1: LOAD AI KNOWLEDGE BASE ───────────────────
def load_knowledge_base():
    embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    
    # Check if database already exists
    if os.path.exists("./ai_agent/chroma_db"):
        print("✅ Knowledge base already exists, loading...")
        db = Chroma(persist_directory="./ai_agent/chroma_db", embedding_function=embeddings)
        return db
    
    # Only builds from PDF if database doesn't exist yet
    print("📚 First time setup — loading CIS rulebook...")
    loader = PyPDFLoader("ai_agent/security_rules.pdf")
    pages = loader.load()
    splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
    chunks = splitter.split_documents(pages)
    db = Chroma.from_documents(chunks, embeddings, persist_directory="./ai_agent/chroma_db")
    print("✅ Knowledge base ready!")
    return db

# ─── STEP 2: DETECT THREATS ───────────────────────────
def detect_threats():
    threats = []
    try:
        acl = s3_client.get_bucket_acl(Bucket=BUCKET_NAME)
        for grant in acl['Grants']:
            grantee = grant.get('Grantee', {})
            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                threats.append({
                    "timestamp": str(datetime.now()),
                    "bucket": BUCKET_NAME,
                    "threat": "PUBLIC_BUCKET_DETECTED",
                    "severity": "CRITICAL",
                    "detail": "S3 bucket is publicly accessible!"
                })
    except Exception as e:
        print(f"Detection error: {e}")
    return threats

# ─── STEP 3: ANALYZE WITH AI ──────────────────────────
def analyze_threat(threat, db):
    query = f"S3 bucket public access security rule {threat['threat']}"
    relevant_rules = db.similarity_search(query, k=3)
    rules_text = "\n".join([doc.page_content for doc in relevant_rules])

    prompt = f"""
    You are a cloud security analyst. Analyze this threat and respond in JSON only.

    THREAT: {json.dumps(threat)}
    RULES: {rules_text[:500]}

    Respond with this JSON:
    {{"severity": "CRITICAL/HIGH/MEDIUM/LOW", "threat_confirmed": true/false, "explanation": "brief", "recommended_action": "action", "cis_rule_violated": "rule"}}
    """

    response = ollama.chat(
        model='tinyllama',
        messages=[{'role': 'user', 'content': prompt}]
    )
    return response['message']['content']

# ─── STEP 4: AUTO REMEDIATE ───────────────────────────
def remediate(threat):
    try:
        s3_client.put_bucket_acl(Bucket=threat['bucket'], ACL='private')
        print(f"✅ {threat['bucket']} locked down!")
        return True
    except Exception as e:
        print(f"❌ Remediation failed: {e}")
        return False

# ─── STEP 5: SEND SLACK ALERT ─────────────────────────
def send_slack_alert(threat, analysis, fixed):
    status = "✅ AUTO-FIXED" if fixed else "❌ FIX FAILED"
    message = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 CloudSentinel Alert"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Threat:*\n{threat['threat']}"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{threat['severity']}"},
                    {"type": "mrkdwn", "text": f"*Bucket:*\n{threat['bucket']}"},
                    {"type": "mrkdwn", "text": f"*Status:*\n{status}"}
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*AI Analysis:*\n{analysis[:300]}"}
            }
        ]
    }
    response = requests.post(SLACK_WEBHOOK, json=message)
    if response.status_code == 200:
        print("📨 Slack alert sent!")

# ─── MAIN PIPELINE ────────────────────────────────────
def run_pipeline():
    db = load_knowledge_base()
    print("\n🛡️  CloudSentinel is running...\n")

    alerted_threats = set()  # Track so we don't spam Slack

    while True:
        threats = detect_threats()

        for threat in threats:
            threat_key = f"{threat['bucket']}:{threat['threat']}"

            if threat_key not in alerted_threats:
                print(f"🚨 THREAT DETECTED: {threat['threat']}")

                # Analyze with AI
                print("🤖 Analyzing with AI...")
                analysis = analyze_threat(threat, db)
                print(f"AI says: {analysis}")

                # Auto remediate
                fixed = remediate(threat)

                # Send Slack alert
                send_slack_alert(threat, analysis, fixed)

                alerted_threats.add(threat_key)
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] ✅ All clear")

        time.sleep(10)

if __name__ == "__main__":
    run_pipeline()