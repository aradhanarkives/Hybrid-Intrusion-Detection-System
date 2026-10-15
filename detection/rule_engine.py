def detect_rules(data):
    alerts = []
    risk_score = 0

    failed_attempts = data.get("failed_attempts", 0)
    connection_count = data.get("connection_count", 0)
    unique_ports = data.get("unique_ports", 0)

    if failed_attempts >= 5:
        alerts.append("Multiple failed connection/login attempts")
        risk_score += 30

    if unique_ports >= 10:
        alerts.append("Possible port scanning behavior")
        risk_score += 40

    if connection_count >= 50:
        alerts.append("Abnormally high connection frequency")
        risk_score += 30

    detected = len(alerts) > 0

    return {
        "detected": detected,
        "risk_score": min(risk_score, 100),
        "evidence": alerts
    }