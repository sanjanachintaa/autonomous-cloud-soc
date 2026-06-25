import ollama
import chromadb
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import json

# Step 1: Load the security rulebook PDF
print("📚 Loading security rulebook...")
loader = PyPDFLoader("security_rules.pdf")
pages = loader.load()

# Step 2: Split into chunks
splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=50
)
chunks = splitter.split_documents(pages)
print(f"✅ Split into {len(chunks)} chunks")

# Step 3: Store in ChromaDB using local sentence transformer
# Why: Instead of Ollama embeddings we use a lightweight local model
# that works reliably on Windows without extra config
print("🧠 Building vector database...")
embeddings = HuggingFaceEmbeddings(
    model_name="all-MiniLM-L6-v2"
)
db = Chroma.from_documents(chunks, embeddings, persist_directory="./chroma_db")
print("✅ Vector database ready!")

def analyze_threat(threat_log):
    # Step 4: Find the relevant security rule for this threat
    query = f"S3 bucket public access security rule {threat_log['threat']}"
    relevant_rules = db.similarity_search(query, k=3)
    rules_text = "\n".join([doc.page_content for doc in relevant_rules])
    
    # Step 5: Feed the threat + rules to Llama 3
    # Why: We give the AI both the evidence (log) and the law (rules) so it can make a smart decision
    prompt = f"""
You are a security analyst. Analyze this threat and respond in JSON only.

THREAT: {json.dumps(threat_log)}

RULES: {rules_text[:500]}

Respond with this JSON:
{{"severity": "CRITICAL/HIGH/MEDIUM/LOW", "threat_confirmed": true/false, "explanation": "brief", "recommended_action": "action", "cis_rule_violated": "rule"}}
"""
    
    response = ollama.chat(
        model='tinyllama',
        messages=[{'role': 'user', 'content': prompt}]
    )
    
    return response['message']['content']

# Test it with a fake threat
test_threat = {
    "timestamp": "2026-06-26 01:00:00",
    "bucket": "vulnerable-soc-bucket",
    "threat": "PUBLIC_BUCKET_DETECTED",
    "severity": "CRITICAL",
    "detail": "S3 bucket is publicly accessible!"
}

print("\n🔍 Analyzing threat with AI...")
result = analyze_threat(test_threat)
print(f"\n🤖 AI Analysis:\n{result}")