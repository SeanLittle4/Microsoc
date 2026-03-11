SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}

def compute_risk_score(findings: list) -> int:
    """Returns a 0–100 risk score based on findings."""
    if not findings:
        return 0
    raw = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    # Normalize: max realistic score ~70 (7 critical findings) → cap at 100
    return min(100, int((raw / 70) * 100))