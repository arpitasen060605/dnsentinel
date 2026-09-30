def calculate_risk_score(entropy, query_length, query_frequency, unique_subdomain):
    score= 0
    reasons= []
    if entropy> 3.0:
        score+=25
        reasons.append("High Entropy")
    if query_length> 25:
        score+=20
        reasons.append("Long Query")
    if query_frequency> 5:
        score+= 25
        reasons.append("High query frequency")
    if unique_subdomain> 5:
        score+= 20
        reasons.append("Many Unique Subdomains")
    return score, reasons
def classify_severity(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    else:
        return "LOW"

if __name__ == "__main__":
    score, reasons = calculate_risk_score(entropy=3.6, query_length=28, query_frequency=12, unique_subdomain=10)
    severity = classify_severity(score)
    print(f"Score: {score}, Severity: {severity}, Reasons: {reasons}")

    score2, reasons2 = calculate_risk_score(entropy=2.0, query_length=10, query_frequency=2, unique_subdomain=2)
    severity2 = classify_severity(score2)
    print(f"Normal-like: Score={score2}, Severity={severity2}, Reasons={reasons2}")