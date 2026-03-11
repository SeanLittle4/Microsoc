RISK_RULES = [
    {
        "id": "bec_wire_fraud",
        "name": "Business Email Compromise — Wire Transfer Fraud",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1566 Phishing / T1534 Internal Spearphishing",
        "severity": "critical",
        "likelihood": "high",
        "business_impact": (
            "Attacker impersonates an executive or vendor over email and tricks "
            "an employee into wiring funds to a fraudulent account. Average SME "
            "loss exceeds $50,000 per incident with minimal recovery."
        ),
        "recommendation": (
            "Require out-of-band verification (phone call to a known number) for "
            "ALL payment changes or wire transfers, regardless of how urgent the "
            "email appears. No exceptions."
        ),
        "references": ["https://www.ic3.gov/Media/Y2023/PSA230609"],
        "condition": lambda r: (
            r.get("wire_transfer_risk") in [
                "Yes — financial decisions are routinely made via email",
                "Yes — occasionally, with limited verification steps",
            ] and r.get("phishing_posture") in [
                "Not confident — we haven't had formal phishing training",
                "We've already had an incident involving a phishing email",
                "Possibly — employees might comply without formal verification",
            ]
        ),
    },
    {
        "id": "ransomware_no_backup",
        "name": "Ransomware with No Recovery Path",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0040 Impact",
        "attack_technique": "T1486 Data Encrypted for Impact",
        "severity": "critical",
        "likelihood": "medium",
        "business_impact": (
            "Ransomware encrypts all business files and systems. Without tested "
            "offline backups, the only options are paying the ransom or permanent "
            "data loss. For businesses with low downtime tolerance, this is existential."
        ),
        "recommendation": (
            "Implement the 3-2-1 backup rule: 3 copies, 2 different media types, "
            "1 stored offline or air-gapped. Test restoration monthly. Cloud sync "
            "alone (OneDrive, Google Drive) is NOT a backup — ransomware can encrypt "
            "synced files too."
        ),
        "references": ["https://www.cisa.gov/stopransomware"],
        "condition": lambda r: (
            r.get("backups") in [
                "We rely on cloud sync (e.g., OneDrive, Google Drive) as our only backup",
                "We don't have a formal backup process",
                "I'm not sure what our backup situation is",
                "Occasional, informal backups — no consistent schedule or testing",
            ] and r.get("downtime_tolerance") in [
                "We would lose significant revenue and might not recover",
                "Serious disruption — we'd lose customers and face real financial harm",
            ]
        ),
    },
    {
        "id": "credential_stuffing_no_mfa",
        "name": "Credential Stuffing — Account Takeover",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0006 Credential Access",
        "attack_technique": "T1110.004 Credential Stuffing",
        "severity": "high",
        "likelihood": "high",
        "business_impact": (
            "Attackers use leaked password databases to automatically try credentials "
            "against your email and cloud accounts. Without MFA, a single reused password "
            "from any data breach gives full account access."
        ),
        "recommendation": (
            "Enable MFA on all accounts immediately — prioritize email, admin accounts, "
            "and financial systems. Use an authenticator app (not SMS where possible). "
            "Deploy a password manager so employees stop reusing passwords."
        ),
        "references": ["https://attack.mitre.org/techniques/T1110/004/"],
        "condition": lambda r: (
            r.get("mfa") in [
                "It's available but optional — employees decide whether to use it",
                "No — we rely on passwords only",
                "I'm not sure",
            ] and r.get("credential_reuse") in [
                "Probably — we haven't enforced a password policy",
                "Yes — password reuse is common here",
                "We have a password policy but can't verify compliance",
            ]
        ),
    },
    {
        "id": "ghost_access_stale_accounts",
        "name": "Unauthorized Access via Stale Accounts",
        "pasta_stage": "Stage 3: Application Decomposition",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1078 Valid Accounts",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "Former employees or contractors retain active credentials after leaving. "
            "A disgruntled ex-employee or an attacker who purchases stolen credentials "
            "can silently access systems for months without detection."
        ),
        "recommendation": (
            "Create an offboarding checklist that disables ALL accounts on the last day "
            "of employment. Run a quarterly audit of active accounts against current "
            "employee/contractor roster. Automate where possible via your identity provider."
        ),
        "references": ["https://attack.mitre.org/techniques/T1078/"],
        "condition": lambda r: r.get("offboarding") in [
            "We try to remember, but it varies and isn't tracked",
            "We don't have a formal process for revoking access",
            "I'm not sure if past employees still have access",
        ],
    },
    {
        "id": "hidden_email_forwarding",
        "name": "Silent Email Exfiltration via Forwarding Rules",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0010 Exfiltration",
        "attack_technique": "T1114.003 Email Forwarding Rule",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "After compromising an email account, attackers plant hidden forwarding rules "
            "that silently copy every inbound and outbound email to an external address. "
            "The account owner sees nothing abnormal. Sensitive data leaks continuously."
        ),
        "recommendation": (
            "Audit all mailbox forwarding rules now. In Microsoft 365: Exchange Admin "
            "Center → Mail Flow → Rules. Disable automatic external forwarding at the "
            "tenant level. Set an alert for any new forwarding rules being created."
        ),
        "references": ["https://attack.mitre.org/techniques/T1114/003/"],
        "condition": lambda r: r.get("email_forwarding") in [
            "No — I've never checked for forwarding rules",
            "I'm not sure how to check this",
            "There are some forwarding rules but I'm not certain they're all approved",
        ],
    },
    {
        "id": "uncontrolled_vendor_access",
        "name": "Supply Chain / Vendor Compromise",
        "pasta_stage": "Stage 3: Application Decomposition",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1199 Trusted Relationship",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "Vendors with shared or uncontrolled access become a secondary attack surface. "
            "An attacker who compromises your IT provider or accountant gains direct access "
            "to your systems under trusted credentials."
        ),
        "recommendation": (
            "Create dedicated, named accounts for each vendor with the minimum access "
            "required. Never share employee credentials with vendors. Review and revoke "
            "vendor access after each engagement ends."
        ),
        "references": ["https://attack.mitre.org/techniques/T1199/"],
        "condition": lambda r: r.get("vendor_controls") in [
            "Vendors use a shared account we gave them",
            "Vendors use an employee's account when they need access",
            "We don't have a formal process — it varies",
        ],
    },
    {
        "id": "no_detection_capability",
        "name": "No Visibility — Breach Goes Undetected",
        "pasta_stage": "Stage 7: Risk & Impact Analysis",
        "attack_tactic": "TA0005 Defense Evasion",
        "attack_technique": "T1562 Impair Defenses",
        "severity": "medium",
        "likelihood": "high",
        "business_impact": (
            "Without login logging or anomaly alerts, attackers operate undetected for "
            "an average of 197 days. The longer they're in, the more data they steal and "
            "the more damage they can cause before discovery."
        ),
        "recommendation": (
            "Enable login audit logging in your identity platform (Microsoft Entra or "
            "Google Workspace). Configure alerts for logins from new countries, impossible "
            "travel, or outside business hours. Review logs monthly at minimum."
        ),
        "references": ["https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"],
        "condition": lambda r: (
            r.get("logging") in [
                "No — we don't have login logging in place",
                "I'm not sure",
            ] or r.get("anomaly_alerts") in [
                "No — we would have no automatic warning",
                "I'm not sure",
            ]
        ),
    },
]