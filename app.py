from flask import Flask, request, jsonify
from detection_engine import calculate_risk_score, classify_severity, get_recommended_action
from flask import Flask, request, jsonify, render_template
from database import init_db, insert_incident, get_all_incidents
from datetime import datetime
import csv
import io
from flask import Response

app = Flask(__name__)
init_db()

def get_dashboard_stats(incidents):
    total = len(incidents)
    normal = sum(1 for i in incidents if i["severity"] == "LOW")
    suspicious = sum(1 for i in incidents if i["severity"] in ("MEDIUM", "HIGH", "CRITICAL"))
    critical = sum(1 for i in incidents if i["severity"] == "CRITICAL")
    high = sum(1 for i in incidents if i["severity"] == "HIGH")
    medium = sum(1 for i in incidents if i["severity"] == "MEDIUM")
    low = sum(1 for i in incidents if i["severity"] == "LOW")
    return {
        "total": total, "normal": normal, "suspicious": suspicious, "critical": critical,
        "critical_pct": round(critical / total * 100) if total else 0,
        "high_pct": round(high / total * 100) if total else 0,
        "medium_pct": round(medium / total * 100) if total else 0,
        "low_pct": round(low / total * 100) if total else 0,
    }

@app.route("/dashboard")
def dashboard():
    incidents = get_all_incidents()
    stats = get_dashboard_stats(incidents)
    return render_template("dashboard.html", incidents=incidents, stats=stats)

@app.route("/score", methods=["POST"])
def score_query():
    data = request.get_json()
    
    entropy = data.get("entropy", 0)
    query_length = data.get("query_length", 0)
    query_frequency = data.get("query_frequency", 0)
    unique_subdomain = data.get("unique_subdomain", 0)
    source_ip = data.get("source_ip", "unknown")
    domain = data.get("domain", "unknown")
    query_type = data.get("query_type", "A")
    
    score, reasons = calculate_risk_score(entropy, query_length, query_frequency, unique_subdomain)
    severity = classify_severity(score)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    insert_incident(timestamp, source_ip, domain, query_type, entropy, query_frequency, score, severity, reasons)
    
    return jsonify({
        "score": score,
        "severity": severity,
        "reasons": reasons
    })

@app.route("/api/incidents")
def api_incidents():
    incidents = get_all_incidents()
    stats = get_dashboard_stats(incidents)
    return jsonify({"incidents": incidents, "stats": stats})

@app.route("/export/csv")
def export_csv():
    incidents = get_all_incidents()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    writer.writerow([
        "Incident ID", "Timestamp", "Source IP", "Domain", "Query Type",
        "Entropy", "Query Frequency", "Risk Score", "Severity",
        "Detection Reasons", "Recommended Action"
    ])
    
    for incident in incidents:
        writer.writerow([
            incident["incident_id"],
            incident["timestamp"],
            incident["source_ip"],
            incident["domain"],
            incident["query_type"],
            round(incident["entropy"], 3),
            incident["query_frequency"],
            incident["score"],
            incident["severity"],
            incident["reasons"],
            get_recommended_action(incident["severity"])
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=dnsentinel_incident_report.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)