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
                # CVSS v3.1 exploitability attributes — used by the frontend
                # to compute a structured breach probability (v) in the
                # Gordon-Loeb economic model, replacing the flat likelihood weight.
                "cvss_av":          rule.get("cvss_av"),
                "cvss_ac":          rule.get("cvss_ac"),
                "cvss_pr":          rule.get("cvss_pr"),
                "cvss_ui":          rule.get("cvss_ui"),
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