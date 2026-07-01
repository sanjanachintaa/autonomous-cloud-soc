from datetime import datetime, timedelta

# ─── THREAT SCORING ───────────────────────────────────
THREAT_SCORES = {
    "PUBLIC_BUCKET_DETECTED": 85,
    "VERSIONING_DISABLED": 60,
    "OPEN_SECURITY_GROUP_SSH": 90,
}

SEVERITY_LEVELS = {
    (0, 50): "LOW",
    (50, 70): "MEDIUM", 
    (70, 90): "HIGH",
    (90, 101): "CRITICAL"
}

def get_threat_score(threat_type):
    return THREAT_SCORES.get(threat_type, 50)

def get_severity_from_score(score):
    for (low, high), severity in SEVERITY_LEVELS.items():
        if low <= score < high:
            return severity
    return "CRITICAL"

# ─── THREAT CORRELATION ───────────────────────────────
CORRELATION_RULES = [
    {
        "name": "DATA_EXFILTRATION_RISK",
        "description": "Public bucket + versioning disabled = high data exfiltration risk",
        "threats_required": ["PUBLIC_BUCKET_DETECTED", "VERSIONING_DISABLED"],
        "severity": "CRITICAL",
        "score_multiplier": 1.5,
        "recommendation": "Immediate lockdown required — attacker could steal and delete data undetected"
    },
    {
        "name": "FULL_BREACH_SCENARIO",
        "description": "All three misconfigurations active — full breach scenario detected",
        "threats_required": ["PUBLIC_BUCKET_DETECTED", "VERSIONING_DISABLED", "OPEN_SECURITY_GROUP_SSH"],
        "severity": "CRITICAL",
        "score_multiplier": 2.0,
        "recommendation": "EMERGENCY: Complete infrastructure compromise possible. Isolate immediately."
    },
    {
        "name": "LATERAL_MOVEMENT_RISK",
        "description": "Open SSH + public bucket = attacker can move laterally",
        "threats_required": ["PUBLIC_BUCKET_DETECTED", "OPEN_SECURITY_GROUP_SSH"],
        "severity": "CRITICAL",
        "score_multiplier": 1.7,
        "recommendation": "Attacker could use SSH access to exfiltrate data from public bucket"
    }
]

def correlate_threats(active_threats):
    threat_types = [t['threat'] for t in active_threats]
    correlations = []

    for rule in CORRELATION_RULES:
        if all(t in threat_types for t in rule['threats_required']):
            base_score = max([get_threat_score(t) for t in rule['threats_required']])
            final_score = min(100, int(base_score * rule['score_multiplier']))
            correlations.append({
                "name": rule['name'],
                "description": rule['description'],
                "severity": rule['severity'],
                "score": final_score,
                "recommendation": rule['recommendation'],
                "timestamp": str(datetime.now()),
                "threats_involved": rule['threats_required']
            })

    return correlations

# ─── RISK ASSESSMENT ──────────────────────────────────
def assess_overall_risk(active_threats, correlations):
    if not active_threats:
        return {"level": "LOW", "score": 0, "summary": "No active threats detected"}

    individual_score = sum([get_threat_score(t['threat']) for t in active_threats]) / len(active_threats)
    correlation_bonus = len(correlations) * 15
    final_score = min(100, int(individual_score + correlation_bonus))
    level = get_severity_from_score(final_score)

    summaries = {
        "LOW": "Environment looks mostly secure",
        "MEDIUM": "Some misconfigurations detected — review recommended",
        "HIGH": "Multiple vulnerabilities detected — immediate action required",
        "CRITICAL": "CRITICAL RISK — active threat scenario in progress"
    }

    return {
        "level": level,
        "score": final_score,
        "summary": summaries[level],
        "individual_threats": len(active_threats),
        "correlations_found": len(correlations)
    }

# ─── ATTACK TIMELINE ──────────────────────────────────
def build_attack_timeline(threat_history):
    timeline = []
    
    for threat in threat_history:
        timeline.append({
            "timestamp": threat['timestamp'],
            "event": threat['threat'].replace('_', ' '),
            "severity": threat['severity'],
            "score": get_threat_score(threat['threat']),
            "fixed": threat['fixed'],
            "bucket": threat['bucket']
        })

    # Sort by timestamp
    timeline.sort(key=lambda x: x['timestamp'])
    return timeline