from flask import Flask, request, jsonify
from detection_engine import calculate_risk_score, classify_severity
from flask import Flask, request, jsonify, render_template
app = Flask(__name__)

sample_incidents = [
    {"id": 1, "timestamp": "2026-09-29 10:03:21", "source_ip": "192.168.1.50", "domain": "8ga0aozrtozsz9ps9f9acawkdunqfc9ep2b.datax-relay.io", "query_type": "TXT", "entropy": 3.81, "query_frequency": 12, "score": 90, "severity": "CRITICAL", "reasons": ["High Entropy", "Long Query", "High query frequency", "Many Unique Subdomains"]},
    {"id": 2, "timestamp": "2026-09-29 10:03:45", "source_ip": "192.168.1.51", "domain": "g86wnfkwfbjxtj2pf7ig51.c2server.net", "query_type": "NULL", "entropy": 3.65, "query_frequency": 8, "score": 70, "severity": "HIGH", "reasons": ["High Entropy", "High query frequency"]},
    {"id": 3, "timestamp": "2026-09-29 10:04:02", "source_ip": "192.168.1.117", "domain": "www.wikipedia.org", "query_type": "A", "entropy": 3.33, "query_frequency": 1, "score": 25, "severity": "LOW", "reasons": ["High Entropy"]},
    {"id": 4, "timestamp": "2026-09-29 10:04:18", "source_ip": "192.168.1.22", "domain": "mail.google.com", "query_type": "A", "entropy": 2.65, "query_frequency": 2, "score": 0, "severity": "LOW", "reasons": []},
]

def get_dashboard_stats():
    total = len(sample_incidents)
    normal = sum(1 for i in sample_incidents if i["severity"] == "LOW")
    suspicious = sum(1 for i in sample_incidents if i["severity"] in ("MEDIUM", "HIGH", "CRITICAL"))
    critical = sum(1 for i in sample_incidents if i["severity"] == "CRITICAL")
    high = sum(1 for i in sample_incidents if i["severity"] == "HIGH")
    medium = sum(1 for i in sample_incidents if i["severity"] == "MEDIUM")
    low = sum(1 for i in sample_incidents if i["severity"] == "LOW")
    return {
        "total": total, "normal": normal, "suspicious": suspicious, "critical": critical,
        "critical_pct": round(critical / total * 100) if total else 0,
        "high_pct": round(high / total * 100) if total else 0,
        "medium_pct": round(medium / total * 100) if total else 0,
        "low_pct": round(low / total * 100) if total else 0,
    }

@app.route("/dashboard")
def dashboard():
    stats = get_dashboard_stats()
    return render_template("dashboard.html", incidents=sample_incidents, stats=stats)

@app.route("/score", methods=["POST"])
def score_query():
    data = request.get_json()
    
    entropy = data.get("entropy", 0)
    query_length = data.get("query_length", 0)
    query_frequency = data.get("query_frequency", 0)
    unique_subdomain = data.get("unique_subdomain", 0)
    
    score, reasons = calculate_risk_score(entropy, query_length, query_frequency, unique_subdomain)
    severity = classify_severity(score)
    
    return jsonify({
        "score": score,
        "severity": severity,
        "reasons": reasons
    })

if __name__ == "__main__":
    app.run(debug=True)