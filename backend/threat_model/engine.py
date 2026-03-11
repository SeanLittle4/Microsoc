from .rules import RISK_RULES
from .scoring import compute_risk_score

def generate_threat_model(responses: dict) -> dict:
    findings = []

    for rule in RISK_RULES:
        if rule["condition"](responses):
            findings.append({
                "id":               rule["id"],
                "name":             rule["name"],
                "pasta_stage":      rule["pasta_stage"],
                "attack_tactic":    rule["attack_tactic"],
                "attack_technique": rule["attack_technique"],
                "severity":         rule["severity"],
                "business_impact":  rule["business_impact"],
                "likelihood":       rule["likelihood"],
                "recommendation":   rule["recommendation"],
                "references":       rule.get("references", []),
            })

    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}[f["severity"]])

    return {
        "summary": {
            "total_findings":    len(findings),
            "critical":          sum(1 for f in findings if f["severity"] == "critical"),
            "high":              sum(1 for f in findings if f["severity"] == "high"),
            "medium":            sum(1 for f in findings if f["severity"] == "medium"),
            "overall_risk_score": compute_risk_score(findings),
        },
        "business_context": {
            "industry":      responses.get("industry"),
            "crown_jewel":   responses.get("crown_jewel"),
            "compliance":    responses.get("compliance"),
            "downtime_tolerance": responses.get("downtime_tolerance"),
        },
        "findings": findings,
    }