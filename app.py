from flask import Flask, request, jsonify
from detection_engine import calculate_risk_score, classify_severity

app = Flask(__name__)

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