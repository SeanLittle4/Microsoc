# CVSS v3.1 exploitability weights
# Source: https://www.first.org/cvss/specification-document
AV_W  = {"network": 0.85, "adjacent": 0.62, "local": 0.55, "physical": 0.2}
AC_W  = {"low": 0.77, "high": 0.44}
PR_W  = {"none": 0.85, "low": 0.62, "high": 0.27}
UI_W  = {"none": 0.85, "required": 0.62}

MAX_EXPLOIT = 0.85 * 0.77 * 0.85 * 0.85  # ≈ 0.4729

# Based off CVSS v3.1 definition of high/medium/low. Critical added independently.
SEV_W  = {"critical": 0.15, "high": 0.10, "medium": 0.05, "low": 0.02}
# Used if there is no CVSS data 
LIKE_M = {"high": 1.0, "medium": 0.75, "low": 0.5}


def cvss_exploitability(finding: dict):
    """Returns normalised CVSS exploitability score [0, 1], or None if no CVSS data."""
    av = AV_W.get(finding.get("cvss_av"))
    ac = AC_W.get(finding.get("cvss_ac"))
    pr = PR_W.get(finding.get("cvss_pr"))
    ui = UI_W.get(finding.get("cvss_ui"))
    if None in (av, ac, pr, ui):
        return None
    return (av * ac * pr * ui) / MAX_EXPLOIT


def finding_contribution(finding: dict) -> float:
    """CVSS-weighted contribution of a single finding to the vulnerability score."""
    impact  = SEV_W.get(finding.get("severity"), 0)
    exploit = cvss_exploitability(finding)
    if exploit is not None:
        return impact * exploit
    # Fallback for findings without CVSS attributes
    return impact * LIKE_M.get(finding.get("likelihood"), 0.5)


def compute_risk_score(findings: list) -> int:
    """
    Returns a 0–100 risk score using CVSS v3.1 exploitability weights.
    Raw vulnerability score v is capped at 0.95, then scaled to 0–100.
    """
    if not findings:
        return 0
    raw_v = sum(finding_contribution(f) for f in findings)
    v = min(raw_v, 0.95)
    return int((v / 0.95) * 100)