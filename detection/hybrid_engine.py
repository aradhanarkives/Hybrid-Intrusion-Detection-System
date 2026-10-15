from detection.rule_engine import detect_rules
from detection.ml_engine import predict_ml


def analyze_event(data):

    rule_result = detect_rules(data)
    ml_result = predict_ml(data)

    rule_score = rule_result["risk_score"]
    ml_score = ml_result["confidence"] if ml_result["detected"] else 0

    if rule_result["detected"] and ml_result["detected"]:
        risk_score = (rule_score + ml_score) / 2

    elif rule_result["detected"]:
        risk_score = rule_score

    elif ml_result["detected"]:
        risk_score = ml_score

    else:
        risk_score = 0

    if risk_score >= 70:
        risk_level = "HIGH"
    elif risk_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if rule_result["detected"]:
        attack_type = "Rule-Based Threat"
    elif ml_result["detected"]:
        attack_type = "ML Detected Threat"
    else:
        attack_type = "Normal"

    return {
        "rule_detection": rule_result["detected"],
        "ml_detection": ml_result["detected"],
        "confidence": round(ml_result["confidence"], 2),
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "attack_type": attack_type,
        "evidence": "; ".join(rule_result["evidence"])
    }