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
    {
        "id": "iot_default_credentials",
        "name": "IoT Device Compromise via Default Credentials",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1078.001 Valid Accounts: Default Accounts",
        "severity": "high",
        "likelihood": "high",
        "business_impact": (
            "Printers, cameras, smart TVs, and other internet-connected devices "
            "shipped with default passwords are trivially compromised. Once inside, "
            "attackers use the device as a foothold to move laterally across the network. "
            "CISA has documented cases where printers with default credentials and loaded "
            "domain accounts allowed attackers to compromise entire Active Directory environments."
        ),
        "recommendation": (
            "Immediately change default passwords on ALL network-connected devices. "
            "Maintain an inventory of every IoT device. Isolate IoT devices on a "
            "separate network segment away from business systems. Enable automatic "
            "firmware updates where available."
        ),
        "references": [
            "https://www.cisa.gov/news-events/news/2023/09/28/cisa-shares-lessons-learned-printer-compromise",
            "https://www.cisa.gov/news-events/news/2024/05/14/cisa-shares-lessons-learned-printer-compromise-part-2",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a",
        ],
        "condition": lambda r: r.get("iot_devices") in [
            "Yes — but we haven't changed default passwords or checked for updates",
            "I'm not sure what counts or what we have",
        ],
    },
    {
        "id": "physical_access_risk",
        "name": "Unauthorized Physical Access to Systems",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1052 Exfiltration Over Physical Medium / T1091 Replication Through Removable Media",
        "severity": "medium",
        "likelihood": "medium",
        "business_impact": (
            "An open office environment allows any visitor — delivery drivers, contractors, "
            "former employees — to physically access computers, plug in a USB device, "
            "photograph screens, or steal hardware. Physical access bypasses every "
            "digital security control you have in place."
        ),
        "recommendation": (
            "Lock server rooms and IT equipment at all times. Require employees to "
            "lock screens when leaving desks. Escort all non-employee visitors. "
            "Log visitor entry and exit. Consider cable locks for laptops in shared spaces."
        ),
        "references": [
            "https://www.cisa.gov/news-events/news/2023/10/19/cisa-shares-lessons-learned-physical-security-breach",
            "https://www.cisa.gov/topics/physical-security/insider-threat-mitigation",
        ],
        "condition": lambda r: r.get("physical_security") in [
            "Open environment — physical access to computers is not restricted",
        ], 
        
    },
    {
        "id": "admin_daily_use_risk",
        "name": "Elevated Blast Radius from Admin Account Misuse",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0004 Privilege Escalation",
        "attack_technique": "T1078.003 Valid Accounts: Local Accounts",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "When administrators use their privileged account for everyday tasks like "
            "browsing and email, a single phishing click can give attackers immediate "
            "admin-level access to the entire environment. CISA identifies this as one "
            "of the top ten systemic misconfigurations found across assessed networks."
        ),
        "recommendation": (
            "Admins must have two separate accounts: a standard account for daily work "
            "and a dedicated admin account used only for administrative tasks. "
            "Never browse the web or read email while logged into an admin account. "
            "This is called Privileged Access Workstation (PAW) hygiene."
        ),
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a",
        ],
        "condition": lambda r: r.get("admin_daily_use") in [
            "Admins use their admin account for everything including daily work",
            "We only have one account per person regardless of access level",
            "I'm not sure",
        ],
    },
    {
        "id": "shared_guest_wifi",
        "name": "Lateral Movement via Unsegmented Guest Wi-Fi",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0008 Lateral Movement",
        "attack_technique": "T1016 System Network Configuration Discovery / T1049 System Network Connections Discovery",
        "severity": "medium",
        "likelihood": "medium",
        "business_impact": (
            "When customers or visitors share the same Wi-Fi network as business devices, "
            "a compromised or malicious visitor device can scan and attack internal systems "
            "directly. This completely negates firewall protections designed to block "
            "external attackers, since the threat is already inside the network perimeter."
        ),
        "recommendation": (
            "Create a separate, isolated guest Wi-Fi network with no access to business "
            "systems. Most modern routers support this natively. Business devices should "
            "be on a completely separate SSID. Verify the networks cannot communicate "
            "with each other."
        ),
        "references": [
            "https://www.cisa.gov/news-events/news/understanding-firewalls-home-and-small-office-use",
        ],
        "condition": lambda r: (
            r.get("guest_wifi") in [
                "No — customers and business devices share the same Wi-Fi network",
            ]
            and r.get("infra_model") not in [
                "Everything is in the cloud — no on-site servers (e.g., Microsoft 365, Google Workspace)",
            ]
        ),
    },
    {
        "id": "no_cyber_insurance",
        "name": "No Financial Safety Net — Uninsured Breach Exposure",
        "pasta_stage": "Stage 7: Risk & Impact Analysis",
        "attack_tactic": "TA0040 Impact",
        "attack_technique": "T1486 Data Encrypted for Impact",
        "severity": "medium",
        "likelihood": "high",
        "business_impact": (
            "Without cyber insurance, the full cost of a breach — legal fees, customer "
            "notification, regulatory fines, system restoration, and lost revenue — falls "
            "entirely on the business. For SMEs with low financial resilience, a single "
            "incident can be fatal. Only 28% of small business owners in the US report "
            "having cyber insurance."
        ),
        "recommendation": (
            "Obtain a cyber liability insurance policy. At minimum, look for coverage "
            "that includes: breach response costs, business interruption, ransomware "
            "payments, and regulatory defense. Premiums for small businesses typically "
            "range from $500–$3,000/year depending on industry and revenue."
        ),
        "references": [
            "https://www.ftc.gov/business-guidance/small-businesses/cybersecurity/cyber-insurance",
        ],
        "condition": lambda r: (
            r.get("cyber_insurance") in [
                "No — we don't have cyber insurance",
                "I'm not sure",
            ]
            and r.get("breach_cost") in [
                "Less than $10,000 — even a small incident could be catastrophic",
                "$10,000 – $50,000 — significant but we might survive",
            ]
        ),
    },
    {
        "id": "pii_no_notification_plan",
        "name": "Regulatory Breach Notification Failure — Customer PII at Risk",
        "pasta_stage": "Stage 7: Risk & Impact Analysis",
        "attack_tactic": "TA0010 Exfiltration",
        "attack_technique": "T1530 Data from Cloud Storage",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "Businesses that collect customer PII are legally required to notify affected "
            "individuals and regulators within strict timeframes after a breach — as short "
            "as 72 hours under GDPR or 30 days under many US state laws. Failure to notify "
            "compounds the original breach with regulatory fines, class action exposure, "
            "and reputational damage that often exceeds the direct cost of the incident."
        ),
        "recommendation": (
            "Document a breach notification procedure today — before an incident occurs. "
            "Identify: which states and regulations apply to your customers, who internally "
            "is responsible for making notification decisions, and which law firm or "
            "attorney you would call. Review your state's specific data breach notification "
            "law at ncsl.org/technology-and-communication/security-breach-notification-laws."
        ),
        "references": [
            "https://csrc.nist.gov/Topics/Security-and-Privacy/risk-management/threats/ransomware",
        ],
        "condition": lambda r: (
            r.get("customer_pii") in [
                "Yes — but we don't have a formal process for managing or protecting it",
            ]
            and r.get("customer_breach_notification") in [
                "No — we don't have a notification process in place",
                "I'm not sure what our obligations would be",
            ]
        ),
    },
    {
        "id": "unencrypted_data_at_rest",
        "name": "Unencrypted Data — Readable on Stolen or Lost Devices",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0006 Credential Access",
        "attack_technique": "T1552.001 Credentials In Files",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "A stolen or lost laptop without full disk encryption gives an attacker "
            "complete access to every file, email, saved password, and credential on "
            "that device — no password required. They simply boot from a USB drive or "
            "remove the disk. For businesses handling customer PII or financial data, "
            "this triggers mandatory breach notification regardless of whether the "
            "data was actually accessed."
        ),
        "recommendation": (
            "Enable BitLocker on all Windows devices and FileVault on all Macs. "
            "Both are built into the operating system at no additional cost. "
            "For Microsoft 365 environments, Intune can enforce and verify encryption "
            "across all managed devices. Encryption is the single most effective control "
            "against physical device loss."
        ),
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ],
        "condition": lambda r: r.get("data_encryption") in [
            "No — we don't use encryption for stored or transmitted data",
            "I'm not sure",
        ],
    },
    {
        "id": "ransomware_double_extortion",
        "name": "Ransomware — Double Extortion via Data Theft Before Encryption",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0040 Impact",
        "attack_technique": "T1486 Data Encrypted for Impact / T1537 Transfer Data to Cloud Account",
        "severity": "critical",
        "likelihood": "medium",
        "business_impact": (
            "Modern ransomware groups no longer just encrypt files — they first steal "
            "copies of sensitive data, then threaten to publish it publicly if the ransom "
            "is not paid. This double extortion eliminates the fallback of restoring from "
            "backups, since the attacker can still cause harm by leaking customer data, "
            "financial records, or business secrets. NIST IR 8374 identifies this as the "
            "primary evolution of ransomware risk requiring a data-centric response."
        ),
        "recommendation": (
            "Backups alone are no longer sufficient protection against ransomware. "
            "Combine tested backups with: data classification (know what's sensitive), "
            "DLP controls to detect bulk data movement before exfiltration, and network "
            "monitoring to detect unusual outbound transfers. Review NIST IR 8374 "
            "Ransomware Risk Management profile for a complete control checklist."
        ),
        "references": [
            "https://csrc.nist.gov/pubs/ir/8374/final",
        ],
        "condition": lambda r: (
            r.get("data_exfil_controls") in [
                "Yes — employees can freely move files wherever they want",
                "I'm not sure",
            ]
            and r.get("logging") in [
                "No — we don't have login logging in place",
                "I'm not sure",
            ]
            and r.get("crown_jewel") in [
                "Theft of customer data — lawsuits, lost trust, regulatory fines",
                "Exposure of confidential contracts, pricing, or business strategies",
            ]
        ),
    },
    {
        "id": "tech_support_impersonation",
        "name": "Tech Support Impersonation Fraud",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1566.004 Phishing: Spearphishing Voice",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "Attackers call employees posing as Microsoft support, IT vendors, or the "
            "business owner's IT provider and convince them to install remote access tools "
            "or reveal credentials. The FBI IC3 2023 report recorded tech support scams "
            "as the third-costliest cybercrime category with over $924 million in reported "
            "losses. SMEs with informal IT arrangements are disproportionately targeted "
            "because employees cannot verify who their real IT contact is."
        ),
        "recommendation": (
            "Establish a written IT contact protocol: employees should have one verified "
            "phone number and email for IT support, and should never act on unsolicited "
            "calls claiming to be IT or Microsoft. Legitimate IT providers never cold-call "
            "to install software. Run a tabletop exercise simulating a tech support call."
        ),
        "references": [
            "https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"    
        ],
        "condition": lambda r: (
            r.get("social_engineering") in [
                "Possibly — employees might comply without formal verification",
                "Very likely — we haven't trained employees on this risk",
            ]
            and r.get("it_support") not in [
                "An in-house IT person or team",
            ]
        ),
    },
    {
        "id": "end_of_life_software",
        "name": "Exploitation of End-of-Life Software",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1190 Exploit Public-Facing Application / T1203 Exploitation for Client Execution",
        "severity": "high",
        "likelihood": "high",
        "business_impact": (
            "End-of-life software no longer receives security patches, meaning every "
            "newly discovered vulnerability is permanently exploitable. NIST recommends "
            "maintaining hardware and software inventories as a foundational ransomware "
            "prevention step because unpatched systems are among the most common "
            "ransomware entry points. Attackers actively scan the internet for known "
            "vulnerable software versions."
        ),
        "recommendation": (
            "Immediately inventory all software and identify end-of-life versions. "
            "Windows 10 reaches end-of-life in October 2025 — plan upgrades now. "
            "If legacy software cannot be replaced, isolate the device from the internet "
            "and other network segments. Prioritize replacing or upgrading within 90 days."
        ),
        "references": [
            "https://csrc.nist.gov/files/pubs/other/2022/02/24/getting-started-with-cybersecurity-risk-management/final/docs/quick-start-guide--ransomware.pdf",
        ],
        "condition": lambda r: r.get("unsupported_software") in [
            "Yes — some systems are running end-of-life software",
            "I'm not sure whether all our software is still supported",
        ],
    },
    {
        "id": "weak_firewall",
        "name": "Inadequate Network Perimeter — Firewall Misconfiguration",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1133 External Remote Services",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "A firewall running on factory default settings — or no firewall at all — "
            "exposes all internal services directly to the internet. CISA and NSA "
            "assessments of over 1,000 networks found default configurations are among "
            "the top ten systemic weaknesses. Attackers routinely scan for default "
            "router credentials and exposed admin interfaces as their first move."
        ),
        "recommendation": (
            "Change all firewall and router admin passwords from defaults immediately. "
            "Disable remote management over the internet unless absolutely necessary. "
            "Block all inbound connections except those explicitly required. Enable "
            "automatic firmware updates on your router. If you use an MSP, ask them "
            "to confirm your firewall configuration in writing."
        ),
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ],
        "condition": lambda r: r.get("firewall") in [
            "Yes — we have a firewall but it's running on default settings",
            "We rely on our internet provider's router with no additional configuration",
            "I'm not sure if we have a firewall or what its settings are",
        ],
    },
    {
        "id": "no_asset_inventory",
        "name": "Unknown Attack Surface — No Asset Inventory",
        "pasta_stage": "Stage 2: Technical Scope",
        "attack_tactic": "TA0043 Reconnaissance",
        "attack_technique": "T1592 Gather Victim Host Information",
        "severity": "medium",
        "likelihood": "high",
        "business_impact": (
            "You cannot protect what you do not know exists. Without an asset inventory, "
            "forgotten devices — old laptops, decommissioned servers, personal phones "
            "with work email — remain connected to your network indefinitely, unpatched "
            "and unmonitored. NIST's ransomware guidance explicitly lists maintaining "
            "a hardware and software inventory as a foundational first step because "
            "untracked assets are among the most common ransomware entry points."
        ),
        "recommendation": (
            "Create a simple spreadsheet listing every device used for work: device type, "
            "user, operating system, and what data it accesses. Update it whenever a "
            "device is added or removed. Free tools like Angry IP Scanner (for on-prem) "
            "or Microsoft Intune (for cloud-managed devices) can automate discovery."
        ),
        "references": [
            "https://csrc.nist.gov/files/pubs/other/2022/02/24/getting-started-with-cybersecurity-risk-management/final/docs/quick-start-guide--ransomware.pdf",
        ],
        "condition": lambda r: r.get("asset_inventory") in [
            "No — we don't have a formal inventory",
            "I'm not sure",
        ],
    },
    {
        "id": "no_business_continuity",
        "name": "No Business Continuity Plan — Extended Outage Risk",
        "pasta_stage": "Stage 7: Risk & Impact Analysis",
        "attack_tactic": "TA0040 Impact",
        "attack_technique": "T1485 Data Destruction / T1486 Data Encrypted for Impact",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "Without a business continuity plan, a ransomware attack or major outage "
            "leaves employees with no guidance on how to operate, who to contact, or "
            "how to communicate with customers. NIST SP 1800-26 identifies the absence "
            "of recovery planning as a multiplier of incident impact. For SMEs with "
            "low downtime tolerance, unplanned outages lasting more than 48 hours "
            "frequently result in permanent customer loss."
        ),
        "recommendation": (
            "Draft a one-page business continuity plan covering: how to operate without "
            "email and computers for 72 hours, emergency contacts for IT support and "
            "legal counsel, how to notify customers of an outage, and who has authority "
            "to make decisions during an incident. Store a printed copy off-site."
        ),
        "references": [
            "https://www.nccoe.nist.gov/data-integrity-detecting-and-responding-ransomware-and-other-destructive-events",
        ],
        "condition": lambda r: (
            r.get("business_continuity") in [
                "No — we haven't thought through how we'd operate without our systems",
                "I'm not sure",
            ]
            and r.get("downtime_tolerance") in [
                "We would lose significant revenue and might not recover",
                "Serious disruption — we'd lose customers and face real financial harm",
            ]
        ),
    },
    {
        "id": "cloud_account_takeover",
        "name": "Cloud Account Takeover via Credential Stuffing",
        "pasta_stage": "Stage 5: Vulnerability Analysis",
        "attack_tactic": "TA0006 Credential Access",
        "attack_technique": "T1110.004 Credential Stuffing",
        "severity": "critical",
        "likelihood": "high",
        "business_impact": (
            "Attackers purchase leaked credential databases from past breaches and "
            "automatically test them against Microsoft 365, Google Workspace, and "
            "cloud services. A 2024 CyberArk study found 49% of employees reuse "
            "the same credentials across multiple work-related applications. Without "
            "MFA on cloud services, a single reused password from any unrelated "
            "data breach grants full access to email, files, and admin portals."
        ),
        "recommendation": (
            "Enable MFA on all cloud services immediately — especially Microsoft 365 "
            "and Google Workspace. This single control blocks over 99% of automated "
            "credential attacks even when passwords are already compromised. Use an "
            "authenticator app (Microsoft Authenticator, Google Authenticator) rather "
            "than SMS where possible. Deploy Conditional Access policies to block "
            "logins from unexpected countries."
        ),
        "references": [
            "https://www.cisa.gov/MFA",
            
        ],
        "condition": lambda r: (
            r.get("mfa") in [
                "No — we rely on passwords only",
                "It's available but optional — employees decide whether to use it",
                "I'm not sure",
            ]
            and r.get("platforms") is not None
            and any(p in (r.get("platforms") or []) for p in [
                "Microsoft 365 (Outlook, Teams, SharePoint, OneDrive)",
                "Google Workspace (Gmail, Drive, Meet)",
            ])
        ),
    },
    {
        "id": "insider_threat_overprivileged",
        "name": "Insider Threat — Disgruntled or Departing Employee Data Theft",
        "pasta_stage": "Stage 3: Application Decomposition",
        "attack_tactic": "TA0009 Collection",
        "attack_technique": "T1078 Valid Accounts / T1213 Data from Information Repositories",
        "severity": "high",
        "likelihood": "medium",
        "business_impact": (
            "CISA defines insider threat as any person with authorized access who "
            "intentionally or unintentionally causes harm. For SMEs with no formal "
            "offboarding and broad access controls, a departing employee can exfiltrate "
            "customer lists, financial data, or trade secrets in the days before leaving — "
            "often without detection. Insider threats are particularly difficult to detect "
            "because the access used is legitimate."
        ),
        "recommendation": (
            "Combine two controls: (1) Least privilege — employees should only ever "
            "have access to what their current role requires. (2) Immediate offboarding "
            "— accounts disabled on the last day, no exceptions. CISA's insider threat "
            "guidance recommends establishing a formal offboarding checklist that includes "
            "account revocation, device return, and access log review."
        ),
        "references": [
            "https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats",
        ],
        "condition": lambda r: (
            r.get("least_privilege") in [
                "No — most employees can access most company systems and data",
                "I'm not sure what level of access employees have",
            ]
            and r.get("offboarding") in [
                "We try to remember, but it varies and isn't tracked",
                "We don't have a formal process for revoking access",
                "I'm not sure if past employees still have access",
            ]
        ),
    },
    {
        "id": "email_domain_spoofing",
        "name": "Email Domain Spoofing — No DMARC Protection",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1566.002 Phishing: Spearphishing Link / T1598 Phishing for Information",
        "severity": "high",
        "likelihood": "high",
        "business_impact": (
            "Without DMARC, attackers can send emails that appear to come from your "
            "exact domain — your customers, partners, and employees will see your "
            "real email address as the sender. This enables highly convincing invoice "
            "fraud, supplier impersonation, and BEC attacks. The FBI IC3 2023 report "
            "recorded 21,489 BEC complaints with over $2.9 billion in adjusted losses, "
            "with phishing and spoofing representing over 298,000 complaints — the "
            "most frequently reported crime category."
        ),
        "recommendation": (
            "Configure SPF, DKIM, and DMARC DNS records for your email domain. "
            "SPF and DKIM specify which servers are authorized to send mail from your "
            "domain; DMARC tells receiving servers what to do with mail that fails those "
            "checks. The FBI's Cyber Division specifically recommends configuring all "
            "three to prevent spoofing. Free tools like MXToolbox can check your "
            "current configuration."
        ),
        "references": [
            " https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf",
        ],
        "condition": lambda r: r.get("email_domain_auth") in [
            "We have an IT provider but I'm not sure if they've set this up",
            "No — we manage our own email and haven't configured these protections",
            "I'm not sure what this is or whether it's in place",
        ],
    },
    {
        "id": "improper_data_disposal",
        "name": "Data Recovery from Improperly Disposed Devices",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0009 Collection",
        "attack_technique": "T1530 Data from Cloud Storage / T1005 Data from Local System",
        "severity": "medium",
        "likelihood": "medium",
        "business_impact": (
            "Standard factory resets and quick formats do not securely erase data — "
            "commercial recovery tools can reconstruct files, emails, and credentials "
            "from drives that appear wiped. Disposed devices sold, donated, or thrown "
            "away without secure erasure are a documented source of PII exposure and "
            "credential recovery. For businesses handling customer financial or health "
            "data, this can trigger breach notification obligations even without a "
            "network-based attack."
        ),
        "recommendation": (
            "Use NIST-approved secure erasure methods before disposing of any device: "
            "DBAN for hard drives, or physical destruction for drives containing "
            "highly sensitive data. For SSDs and flash storage, use manufacturer-provided "
            "secure erase tools or full disk encryption before disposal (encrypted data "
            "on a wiped drive is unrecoverable). Document all disposals."
        ),
        "references": [
            "https://csrc.nist.gov/pubs/sp/800/88/r1/final",
        ],
        "condition": lambda r: (
            r.get("data_disposal") in [
                "We do a standard factory reset or format",
                "We dispose of devices without specifically wiping them first",
                "We don't have a formal process for this",
            ]
            and r.get("customer_pii") in [
                "Yes — and we have a clear privacy policy and process for handling it",
                "Yes — but we don't have a formal process for managing or protecting it",
            ]
        ),
    },
    {
        "id": "phishing_spearphishing",
        "name": "Phishing and Spearphishing — Human-Layer Initial Access",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1566.001 Spearphishing Attachment / T1566.002 Spearphishing Link",
        "severity": "critical",
        "likelihood": "high",
        "business_impact": (
            "Phishing is the most frequently reported cybercrime in the FBI IC3 2023 "
            "report with over 298,000 complaints — accounting for approximately 34% of "
            "all reported incidents. Spearphishing is a targeted variant where the "
            "attacker researches the business first and crafts a convincing, personalized "
            "message impersonating a known contact, vendor, or executive. A single "
            "successful click can deliver ransomware, steal credentials, or initiate "
            "a fraudulent wire transfer. Businesses with untrained employees and no "
            "email filtering have no technical layer to compensate for human error."
        ),
        "recommendation": (
            "Layer three controls together: (1) Technical — enable email filtering that "
            "scans attachments and flags suspicious links before they reach the inbox. "
            "In Microsoft 365 this is Defender for Office 365 Safe Links and Safe "
            "Attachments. (2) Human — run annual phishing simulation training so "
            "employees experience what a phishing attempt looks and feels like before "
            "a real one arrives. Free tools include GoPhish (self-hosted) and Microsoft "
            "Attack Simulator (included in M365 E5). (3) Process — establish a one-click "
            "reporting mechanism so employees can flag suspicious emails without friction."
        ),
        "references": [
            "https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf",
            "https://attack.mitre.org/techniques/T1566/",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a",
        ],
        "condition": lambda r: (
            r.get("phishing_posture") in [
                "Not confident — we haven't had formal phishing training",
                "We've already had an incident involving a phishing email",
                "I'm not sure",
            ]
            and r.get("email_filtering") in [
                "No — emails arrive with no automated scanning",
                "Partially — we have some filtering but it's not comprehensive",
                "I'm not sure what protections our email has",
            ]
        ),
    },
    {
        "id": "exposed_remote_desktop",
        "name": "Exposed Remote Desktop — Direct Internet Attack Surface",
        "pasta_stage": "Stage 2: Technical Scope",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1133 External Remote Services / T1110 Brute Force",
        "severity": "critical",
        "likelihood": "high",
        "business_impact": (
            "Remote Desktop Protocol (RDP) exposed directly to the internet is one of "
            "the most commonly exploited entry points for ransomware. Attackers "
            "continuously scan the internet for open RDP ports and use automated "
            "brute force tools to guess weak passwords — no phishing or social "
            "engineering required. CISA Advisory AA22-137A identifies exposed remote "
            "services as a top initial access vector across assessed networks."
        ),
        "recommendation": (
            "Never expose RDP directly to the internet. Place it behind a VPN so that "
            "only authenticated users can reach it at all. If a VPN is not feasible, "
            "restrict RDP access by IP allowlist, enable Network Level Authentication "
            "(NLA), and enforce MFA. Change the default RDP port (3389) as an "
            "additional deterrent, though not a substitute for the above."
        ),
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a",
            "https://attack.mitre.org/techniques/T1133/",
        ],
        "condition": lambda r: (
            r.get("internet_exposed") is not None
            and "Remote desktop — employees connect to office computers from home"
            in (r.get("internet_exposed") or [])
            and r.get("mfa") in [
                "No — we rely on passwords only",
                "It's available but optional — employees decide whether to use it",
                "I'm not sure",
            ]
        ),
    },
    {
        "id": "exposed_services_no_firewall",
        "name": "Multiple Internet-Exposed Services with Weak Perimeter Controls",
        "pasta_stage": "Stage 2: Technical Scope",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1190 Exploit Public-Facing Application",
        "severity": "high",
        "likelihood": "high",
        "business_impact": (
            "Every service exposed to the internet is a potential entry point. "
            "Businesses exposing three or more services — website, email, file sharing, "
            "client portal, remote desktop — with a misconfigured or default firewall "
            "have a large, unmonitored attack surface. Attackers use automated scanners "
            "to continuously probe all exposed services for known vulnerabilities, "
            "default credentials, and unpatched software."
        ),
        "recommendation": (
            "Audit every internet-exposed service and ask: does this need to be publicly "
            "reachable, or can it be placed behind a VPN? For services that must remain "
            "public, ensure they are patched, use MFA, and are monitored for suspicious "
            "activity. Confirm your firewall blocks all ports and services not explicitly "
            "required. Run a free external scan using Shodan or nmap to see what "
            "attackers can see from the outside."
        ),
        "references": [
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a",
            "https://attack.mitre.org/techniques/T1190/",
        ],
        "condition": lambda r: (
            r.get("internet_exposed") is not None
            and len([
                x for x in (r.get("internet_exposed") or [])
                if x not in [
                    "None — everything requires being on-site",
                    "I'm not sure what's exposed",
                ]
            ]) >= 3
            and r.get("firewall") in [
                "Yes — we have a firewall but it's running on default settings",
                "We rely on our internet provider's router with no additional configuration",
                "I'm not sure if we have a firewall or what its settings are",
            ]
        ),
    },
]