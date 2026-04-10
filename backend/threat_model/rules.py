RISK_RULES = [
    {
        "id": "bec_wire_fraud",
        "name": "Business Email Compromise — Wire Transfer Fraud",
        "pasta_stage": "Stage 4: Threat Analysis",
        "attack_tactic": "TA0001 Initial Access",
        "attack_technique": "T1566 Phishing / T1534 Internal Spearphishing",
        "severity": "critical",
        "likelihood": "high",
        # CVSS v3.1 exploitability attributes
        # Email-based social engineering: reaches victim over network, no
        # privileges required, but victim must be deceived into acting.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "Business Email Compromise (BEC) is a scam where an attacker sends a carefully "
            "crafted email impersonating someone the victim trusts, typically an executive, "
            "a vendor, or an IT provider, and uses that trust to request an urgent wire "
            "transfer or payment to a bank account the attacker controls. The emails are "
            "convincing because the attacker has often researched the business in advance: "
            "they know the names of executives, vendors, and ongoing projects. The request "
            "usually comes with a reason the normal verification steps should be skipped; "
            "an emergency, a deadline, or a claimed technical issue. "
            "Learn more: https://www.ic3.gov/Media/Y2023/PSA230609"
        ),
        "business_impact": (
            "BEC is the costliest cybercrime category tracked by the FBI. The FBI Internet "
            "Crime Complaint Center (IC3) 2023 report recorded 21,489 BEC complaints with "
            "over $2.9 billion in adjusted losses; an average loss of approximately $137,000 "
            "per incident. For small businesses, losses frequently exceed $50,000 and recovery "
            "is rare: wire transfers are typically processed within hours and routed through "
            "overseas accounts before the fraud is detected. Even when law enforcement is "
            "notified immediately, fewer than 25% of wire fraud losses are recovered. In "
            "addition to the direct financial loss, the business may face legal liability if "
            "client funds were involved and reputational harm from disclosed fraud. "
            "Real-world example: In 2020, a small US real estate firm lost $503,000 in a "
            "single BEC transaction after an attacker impersonated a title company by email. "
            "Source: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
        ),
        "recommendation": (
            "Require out-of-band verification (phone call to a known number) for "
            "ALL payment changes or wire transfers, regardless of how urgent the "
            "email appears. No exceptions. Enforce MFA and ensure authentications are logged."
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
            ] and r.get("mfa") in [
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
        "id": "ransomware_no_backup",
        "name": "Ransomware with No Recovery Path",
        "pasta_stage": "Stage 6: Attack Modeling",
        "attack_tactic": "TA0040 Impact",
        "attack_technique": "T1486 Data Encrypted for Impact",
        "severity": "critical",
        "likelihood": "medium",
        # Commodity ransomware delivered over network (email/RDP/exploit).
        # No privileges needed initially; victim must interact to trigger.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "Ransomware is malicious software that locks every file on your computers and "
            "servers and demands a payment in exchange for the key to unlock them. "
			"It most commonly arrives through a phishing email, an "
            "unsecured remote desktop connection, or an unpatched software vulnerability. "
            "Once it executes, it can spread across an entire network in minutes, encrypting "
            "shared drives, servers, and cloud-synced folders simultaneously. Cloud sync "
            "services like OneDrive and Google Drive are NOT a defense. Ransomware encrypts "
            "files locally and the changes sync to the cloud before anyone realizes what has "
            "happened. Without a tested, offline backup, there is no technical recovery option. "
            "Learn more: https://www.cisa.gov/stopransomware"
        ),
        "business_impact": (
            "According to Sophos's State of Ransomware 2024 report, the average total recovery "
            "cost from a ransomware attack (including downtime, IT remediation, legal fees, "
            "and lost business) reached $2.73 million, up from $1.82 million the prior year. "
            "The average ransom payment alone was $2 million. For small businesses, the Verizon "
            "2024 Data Breach Investigations Report found ransomware was present in 23% of all "
            "breaches. CISA estimates that 60% of small businesses that suffer a ransomware "
            "attack close within six months. For a business with no offline backup, the choice "
            "is binary: pay a criminal with no guarantee of recovery, or accept permanent loss "
            "of all business data, customer records, financial history, contracts, and "
            "operational systems. Either outcome is typically existential for a small business. "
            "Source: https://www.sophos.com/en-us/content/state-of-ransomware"
        ),
        "recommendation": (
            "Implement the 3-2-1 backup rule: 3 copies, 2 different media types, "
            "1 stored offline or air-gapped. Test restoration monthly. Cloud sync "
            "alone (OneDrive, Google Drive) is NOT a backup; ransomware can encrypt "
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
        # Fully automated internet attack. No privileges or user interaction
        # required — bots test leaked credentials continuously.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Credential stuffing is an automated attack where criminals take large lists of "
            "usernames and passwords stolen from other websites (there are billions of these "
            "freely available on the dark web) and automatically test them against your "
            "business accounts. If any of your employees reuse the same password across "
            "multiple sites, their credentials are likely already in one of these lists. "
            "The attack runs 24 hours a day, requires no human involvement, and succeeds "
            "silently when a match is found. The attacker gains full access to the account "
            "without any alert or warning. Without multi-factor authentication (MFA), a "
            "single reused password is all that stands between an attacker and complete "
            "access to your email, files, and business systems. "
            "Check if your employees' emails appear in known breaches: https://haveibeenpwned.com"
        ),
        "business_impact": (
            "Microsoft reports that MFA blocks over 99.9% of automated credential attacks. "
            "Without it, a successful account takeover gives an attacker full access to "
            "everything in that account: every email sent and received, every file stored, "
            "every contact, and potentially administrative access to other systems if the "
            "compromised account has elevated privileges. The IBM Cost of Data Breach 2024 "
            "report found that stolen or compromised credentials are the most common initial "
            "attack vector, accounting for 16% of breaches at an average cost of $4.81 million. "
            "For SMEs, a compromised email account is the typical entry point for business "
            "email compromise fraud, ransomware delivery, and customer data theft — often "
            "without the business being aware for weeks or months. "
            "Source: https://www.microsoft.com/en-us/security/blog/2019/08/20/one-simple-action-you-can-take-to-prevent-99-9-percent-of-account-attacks/"
        ),
        "recommendation": (
            "Enable MFA on all accounts immediately; prioritize email, admin accounts, "
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
        # Attacker uses purchased/stolen valid credentials over the network.
        # Requires low-level credentials (not admin), no UI interaction.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "low",
        "cvss_ui": "none",
        "description": (
            "When an employee or contractor leaves your organization, their login accounts "
            "typically remain active unless someone manually disables them. These 'stale' "
            "accounts represent open doors into your systems. A former employee who left on "
            "bad terms can log in at any time. More commonly, an attacker who purchased "
            "stolen credentials, or who compromised the former employee's personal email "
            "to recover their password. can use the active account to gain access. Because "
            "the login uses a real, valid username and password, there is no alert or warning. "
            "The access looks completely normal to any security system that is not specifically "
            "monitoring for accounts belonging to former staff. "
            "Learn more: https://attack.mitre.org/techniques/T1078/"
        ),
        "business_impact": (
            "The Verizon 2024 Data Breach Investigations Report found that the use of stolen "
            "or misused credentials was involved in 24% of all data breaches. Stale accounts "
            "are a primary enabler: they give attackers authenticated, trusted access that "
            "bypasses most security controls. A former employee with retained access to "
            "customer databases, financial systems, or email can exfiltrate data over an "
            "extended period without triggering alerts. The Ponemon Institute's 2022 Cost "
            "of Insider Threats report found that the average cost of a credential-based "
            "insider incident was $679,621, with incidents involving former employees "
            "averaging higher due to longer dwell times before detection. For small "
            "businesses, the most common outcome is theft of customer lists, pricing data, "
            "or intellectual property by a departing employee or their new employer. "
            "Source: https://www.verizon.com/business/resources/reports/dbir/"
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
        # Post-compromise technique: attacker already has account access (low PR),
        # sets rule over network automatically with no further UI interaction.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "low",
        "cvss_ui": "none",
        "description": (
            "After gaining access to an email account (through phishing, credential stuffing, "
            "or any other method) attackers frequently plant a hidden rule that automatically "
            "forwards a copy of every email the account sends and receives to an address they "
            "control. The rule is invisible to the account owner: their email appears to work "
            "normally, there is no notification, and the forwarded copies leave no trace in "
            "the sent folder. The attacker then monitors the account passively for weeks or "
            "months, collecting business intelligence, intercepting payment information, and "
            "waiting for the right opportunity to act. This technique is used in the majority "
            "of business email compromise cases to gather context before initiating fraud. "
            "Learn more: https://attack.mitre.org/techniques/T1114/003/"
        ),
        "business_impact": (
            "Hidden email forwarding is particularly damaging because it operates silently "
            "over an extended period. Every email sent to and from the compromised account "
            "is being read by an attacker in real time. The FBI IC3 2023 report identified "
			"email account compromise as a key enabler "
            "of BEC fraud, with losses averaging $137,000 per incident. In many cases the "
            "forwarding rule is discovered only after a fraudulent transaction has already "
            "occurred, meaning the business has been under active surveillance for weeks "
            "without knowing it. Beyond financial fraud, continuous email access also "
            "constitutes a data breach under most state privacy laws, potentially triggering "
            "customer notification obligations and regulatory fines. "
            "Source: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
        ),
        "recommendation": (
            "Audit all mailbox forwarding rules now. In Microsoft 365: Exchange Admin "
            "Center → Mail Flow → Rules. In Google Workspace: Admin Console → Reporting → Audit and Investigation → Email log search. Disable automatic external forwarding at the "
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
        # Attacker compromises a vendor and pivots using their trusted credentials
        # (low PR). Network-delivered, no user interaction required.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "low",
        "cvss_ui": "none",
        "description": (
            "Many small businesses grant their IT providers, accountants, web developers, "
            "or other vendors ongoing access to their systems for maintenance and support. "
            "When vendors share a single login with your staff or use a generic account, "
            "you lose the ability to track who did what and when. More critically, if the "
            "vendor itself is compromised, which is increasingly common, the attacker "
            "inherits all of the access your vendor had across every client they serve. "
            "This is not a theoretical risk: some of the largest breaches in history have "
            "started at small vendors with trusted access to larger organizations. "
            "Learn more: https://attack.mitre.org/techniques/T1199/"
        ),
        "business_impact": (
            "The supply chain attack vector is well-documented at the enterprise level, but "
            "it applies equally to SMEs. The 2014 Target breach, which resulted in $291 million "
            "in total losses including settlements, originated through an HVAC vendor with "
            "trusted network access. Verizon's DBIR has consistently found that third-party "
            "involvement appears in roughly 15% of breaches annually. For SMEs that share "
            "credentials with IT providers or use a single vendor account for multiple staff, "
            "the exposure is direct: an attacker who compromises your IT provider gains "
            "authenticated access to every system the provider manages. This can result in "
            "ransomware deployment, data theft, or persistent access that is difficult to "
            "detect because the access originates from a trusted source. Legal and contractual "
            "liability for vendor-enabled breaches remains with the business that was breached, "
            "not the vendor. "
            "Source: https://www.verizon.com/business/resources/reports/dbir/"
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
        # Absence of controls means any network-based attacker operates freely.
        # No privileges or interaction needed to exploit a logging gap.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "If no one is monitoring who logs into your systems and from where, an attacker "
            "who gains access can operate freely for weeks or months without being detected. "
            "Login logging and anomaly detection are the most basic form of security "
            "visibility; they record when accounts are accessed, from which location, "
            "and at what time. Without them, you have no way to know that an account "
            "has been compromised, that someone is accessing your files from another country, "
            "or that an attacker has been inside your systems. Most cloud platforms like "
            "Microsoft 365 and Google Workspace include basic login logging at no additional "
            "cost. It simply needs to be reviewed. "
            "Learn more: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ),
        "business_impact": (
            "The IBM Cost of a Data Breach 2024 report found that the average time to "
            "identify and contain a breach was 258 days. Organizations with security "
            "monitoring in place identified breaches 108 days faster on average, reducing "
            "the average cost by $1.02 million. For SMEs without any logging or alerting, "
            "a breach may go undetected until a customer reports fraud, a ransomware "
            "note appears on screen, or a regulatory body notifies the business that "
            "its customer data was found on the dark web. By that point, the attacker "
            "has had extended access to all business data, email, and financial systems. "
            "The longer an attacker remains undetected, the greater the volume of data "
            "exfiltrated and the higher the total cost of the incident. Detection gaps "
            "also complicate cyber insurance claims, as insurers increasingly require "
            "evidence of monitoring as a condition of coverage. "
            "Source: https://www.ibm.com/reports/data-breach"
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
        # IoT devices often adjacent-network or internet-exposed. Default creds
        # are public knowledge (AC: low). No privileges or user interaction needed.
        "cvss_av": "adjacent",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Almost every network-connected device (printers, security cameras, smart TVs, "
            "routers, door access systems) ships from the factory with a default username "
            "and password, typically something like 'admin/admin' or 'admin/password.' These "
            "defaults are publicly listed on manufacturer websites and in databases that "
            "attackers use to automate compromise. If the default password is never changed, "
            "anyone on your network, or in some cases anyone on the internet, can log "
            "into the device. This is not a sophisticated attack. Automated tools scan for "
            "devices with default credentials continuously. CISA has documented multiple "
            "cases where a printer with unchanged default credentials was used as the entry "
            "point into an entire corporate network. "
            "CISA advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"
        ),
        "business_impact": (
            "CISA has published specific case studies showing that printers with default "
            "credentials and domain accounts loaded were used to compromise entire Active "
            "Directory environments, giving attackers full control of every computer in "
            "the organization. The 2016 Mirai botnet, which recruited IoT devices with "
            "default credentials into a massive attack network, caused an estimated "
            "$110 million in damages and disrupted internet access across the US East Coast. "
            "For small businesses, a compromised IoT device on the same network as business "
            "computers provides an attacker with a persistent foothold to launch further "
            "attacks, deploy ransomware, or exfiltrate data. The device itself often shows "
            "no visible signs of compromise. IoT devices are also typically not covered by "
            "endpoint security software, making them invisible to most security tools. "
            "Sources: https://www.cisa.gov/news-events/news/2023/09/28/cisa-shares-lessons-learned-printer-compromise | "
            "https://www.cisa.gov/news-events/news/2024/05/14/cisa-shares-lessons-learned-printer-compromise-part-2"
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
        # Requires physical presence. No privileges needed once on-site.
        # No user interaction required — attacker acts directly on hardware.
        "cvss_av": "physical",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Physical access to a computer or server bypasses virtually every digital "
            "security control in place. An attacker who can walk up to an unlocked, "
            "unattended workstation can plug in a USB drive loaded with malware, copy "
            "files, capture saved passwords, or install a persistent backdoor, all in "
            "under two minutes. In open office environments, this risk extends to anyone "
            "who can enter the space: delivery drivers, contractors, cleaning staff, "
            "visitors, and former employees who still have building access. Screens left "
            "unlocked when an employee steps away are among the most common vectors for "
            "both opportunistic theft and targeted data collection. "
            "Learn more: https://www.cisa.gov/topics/physical-security"
        ),
        "business_impact": (
            "Physical security incidents are often underreported, but the IBM Cost of a "
            "Data Breach 2024 report found that physical security compromise was a "
            "contributing factor in a meaningful percentage of breaches. A stolen laptop "
            "without full disk encryption gives an attacker complete access to every file, "
            "credential, and email on the device, immediately triggering breach notification "
            "obligations in most US states for any customer PII stored on the device. "
            "The average notification cost alone ranges from $125 to $175 per affected "
            "individual. Beyond laptops, an attacker who plugs a malicious USB device into "
            "a network-connected workstation can establish persistent remote access that "
            "survives password changes and persists undetected for months. Physical access "
            "is the highest-impact, lowest-technical-skill attack vector available. "
            "Source: https://www.ibm.com/reports/data-breach"
        ),
        "recommendation": (
            "Lock server rooms and IT equipment at all times. Require employees to "
            "lock screens when leaving desks. Escort all non-employee visitors. "
            "Log visitor entry and exit. Consider cable locks for laptops in shared spaces."
        ),
        "references": [
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
        # Phishing email reaches admin over network. Low PR because attacker
        # first needs to get the admin to click (UI: required).
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "An administrator account has elevated permissions: the ability to install "
            "software, create and delete accounts, access all files, and change system "
            "settings across the entire environment. When the person who manages IT uses "
            "their admin account for everyday tasks like reading email and browsing the web, "
            "they are constantly exposed at the highest possible privilege level. If a "
            "phishing email tricks them into clicking a malicious link, or a compromised "
            "website silently installs malware, the attacker immediately has full "
            "administrative control over every system, not just the account that was "
            "compromised. CISA and NSA have jointly identified this as one of the top ten "
            "most common misconfigurations found during network assessments. "
            "CISA advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"
        ),
        "business_impact": (
            "Using an admin account for daily work dramatically amplifies the impact of any "
            "successful attack. A phishing click that would normally compromise one employee's "
            "email account instead gives an attacker immediate, full control of every computer, "
            "server, and account in the environment. CISA's advisory AA23-278A, based on "
            "assessments of over 1,000 organizations, identifies improper privilege separation "
            "as a top initial access enabler for ransomware operators specifically because "
            "it eliminates the need for privilege escalation: the attacker already has "
            "admin rights from the moment of compromise. The remediation cost of a full "
            "domain compromise, where the attacker has admin control, is significantly "
            "higher than a standard account compromise, often requiring complete system "
            "rebuilds rather than targeted remediation. Average enterprise remediation "
            "costs for full domain compromise exceed $500,000. For an SME, the equivalent "
            "is rebuilding every computer from scratch. "
            "Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"
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
        # Attacker must be on the adjacent network (guest Wi-Fi). Once there,
        # no further privileges or user interaction needed to scan/attack.
        "cvss_av": "adjacent",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "When customers, clients, or visitors connect to the same Wi-Fi network as "
            "your business computers and servers, they are on the same internal network "
            "as your most sensitive systems. A visitor's device that is already infected "
            "with malware, without the visitor knowing, can silently scan your network "
            "and attack business computers while sitting in your waiting room. This also "
            "applies to personal phones and laptops used by your own employees if they "
            "are on the same network. Network segmentation (creating a separate guest "
            "Wi-Fi that cannot communicate with business systems) is a standard feature "
            "on virtually every modern router and costs nothing to configure. "
            "Learn more: https://www.cisa.gov/news-events/news/understanding-firewalls-home-and-small-office-use"
        ),
        "business_impact": (
            "An unsegmented guest Wi-Fi is the equivalent of leaving your front door "
            "unlocked and inviting strangers to sit next to your filing cabinets. Any "
            "device on your network can attempt to connect to every other device on the "
            "same network. Retail businesses, medical practices, law firms, and any "
            "business with a public waiting area face the highest risk. In a typical "
            "attack scenario, a compromised device on the guest Wi-Fi uses automated "
            "tools to identify business computers, printers, and servers on the same "
            "segment within minutes. This can provide a direct path to deploying "
            "ransomware or exfiltrating data that bypasses internet-facing security "
            "controls entirely, since the attack originates from inside the network "
            "perimeter. CISA identifies network segmentation as a foundational control "
            "specifically because it contains the blast radius of any compromise to a "
            "single network segment. "
            "Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
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
        # Financial exposure amplifier: any network-delivered attack that
        # succeeds creates uninsured losses. No privileges or UI required
        # to exploit the absence of insurance coverage.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Cyber insurance is a policy that covers the financial costs of a data breach "
            "or cyberattack, including emergency IT response, customer notification, legal "
            "defense, regulatory fines, business interruption losses, and in some cases "
            "ransom payments. Without it, every one of those costs falls directly on the "
            "business. Despite the growing threat environment, only 28% of small business "
            "owners in the US report having cyber insurance. Premiums for basic small "
            "business coverage typically range from $500 to $3,000 per year, a fraction "
            "of what a single incident can cost. Cyber insurance also often provides access "
            "to breach response resources and legal counsel, which are critical in the "
            "first 72 hours after an incident. "
            "FTC guidance: https://www.ftc.gov/business-guidance/small-businesses/cybersecurity/cyber-insurance"
        ),
        "business_impact": (
            "The IBM Cost of a Data Breach 2024 report found the average total cost of a "
            "data breach for small and midsize businesses was $3.31 million. For a business "
            "with no cyber insurance, this cost is absorbed entirely out of pocket. Even "
            "a relatively minor incident (i.e. a single compromised email account requiring "
            "forensic investigation and customer notification) can cost $50,000 to $150,000 "
            "in professional response fees alone. Ransomware events with full system recovery "
            "routinely cost $200,000 to $500,000 for small businesses when IT remediation, "
            "downtime, and data recovery are factored in. The FTC reports that 60% of small "
            "businesses that suffer a major cyber incident fail within six months, with "
            "uninsured financial loss being a primary contributor. Cyber insurance does not "
            "replace good security practices but significantly reduces the existential "
            "financial exposure of a breach. "
            "Source: https://www.ibm.com/reports/data-breach"
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
        # Data exfiltration happens over network. No privileges needed beyond
        # initial access; no user interaction required to exfiltrate.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "If your business collects customer information (names, email addresses, "
            "phone numbers, payment details, health information, or Social Security numbers) "
            "you are legally required under most US state laws and federal regulations "
            "to notify affected customers and, in many cases, government agencies within a "
            "specific timeframe after a data breach. These obligations exist regardless of "
            "whether you think the data was actually accessed. The notification window can "
            "be as short as 72 hours under some regulations. Failing to notify on time "
            "compounds the original breach with separate regulatory penalties. Every US "
            "state now has a data breach notification law. "
            "State notification laws: https://www.ncsl.org/technology-and-communication/security-breach-notification-laws"
        ),
        "business_impact": (
            "The legal and financial consequences of a notification failure can exceed the "
            "cost of the original breach. Under GDPR, fines for failure to notify can reach "
            "4% of annual global revenue or €20 million, whichever is higher. US state law "
            "penalties vary but typically range from $100 to $750 per affected individual "
            "per violation — which can reach millions of dollars for businesses with large "
            "customer databases. Beyond regulatory fines, failure to notify exposes the "
            "business to class action lawsuits from affected customers. The average cost "
            "of a US data breach notification is approximately $125 to $175 per affected "
            "record, including legal fees, communication costs, and credit monitoring "
            "services. For a business with 5,000 customer records, that is $625,000 to "
            "$875,000 in notification costs alone. "
            "Source: https://www.ibm.com/reports/data-breach"
        ),
        "recommendation": (
            "Document a breach notification procedure today — before an incident occurs. "
            "Identify: which states and regulations apply to your customers, who internally "
            "is responsible for making notification decisions, and which law firm or "
            "attorney you would call. Review your state's specific data breach notification "
            "law at ncsl.org/technology-and-communication/security-breach-notification-laws."
        ),
        "references": [
            "https://www.ncsl.org/technology-and-communication/security-breach-notification-laws",
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
        # Requires physical access to the device. Once obtained, no privileges
        # or user interaction needed — attacker boots from USB or removes disk.
        "cvss_av": "physical",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Full disk encryption scrambles all data on a device so that it is unreadable "
            "without the correct password. Without it, anyone who physically obtains a "
            "laptop or hard drive can read every file on it, even without knowing the "
            "Windows or Mac login password. An attacker simply boots the device from a "
            "USB drive, bypasses the login screen entirely, and has direct access to the "
            "raw disk. This is not a sophisticated technique; free tools to do this are "
            "widely available. Both Windows (BitLocker) and macOS (FileVault) include "
            "full disk encryption built in, at no additional cost. It simply needs to "
            "be enabled. "
            "CISA guidance: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ),
        "business_impact": (
            "The IBM Cost of a Data Breach 2024 report found that physical security "
            "incidents involving lost or stolen devices had an average total cost of "
            "$3.1 million. Beyond the replacement cost of the hardware, the primary "
            "financial exposure is the data stored on the device. For any business "
            "that stores customer PII, a stolen unencrypted laptop triggers mandatory "
            "breach notification in every US state, with notification costs averaging "
            "$125 to $175 per affected customer record. A laptop containing records "
            "for even 1,000 customers generates $125,000 to $175,000 in notification "
            "and response costs. Full disk encryption completely eliminates this risk: "
            "an encrypted device that is stolen is legally treated as a non-breach "
            "event in most jurisdictions because the data is unreadable. Enabling "
            "BitLocker or FileVault takes under five minutes per device and prevents "
            "what would otherwise be a mandatory and costly disclosure. "
            "Source: https://www.ibm.com/reports/data-breach"
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
        # Same delivery vector as ransomware_no_backup. User interaction
        # required for initial access; data theft/exfil then automated.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "Modern ransomware attacks do not simply encrypt your files and wait for payment. "
            "Before encrypting anything, attackers first quietly copy your most sensitive "
            "data (customer records, financial files, contracts, employee data) to their "
            "own servers. They then encrypt your systems and present two threats: pay to "
            "unlock your files, and pay to prevent the stolen data from being published "
            "publicly on criminal leak sites. This 'double extortion' tactic eliminates "
            "the effectiveness of backups as a complete defense, because even if you "
            "restore your systems from backup, the attacker still holds your data and "
            "can threaten to release it. This has become the dominant ransomware model "
            "since 2020. NIST IR 8374 specifically addresses this evolved threat profile. "
            "NIST IR 8374: https://csrc.nist.gov/pubs/ir/8374/final"
        ),
        "business_impact": (
            "Double extortion ransomware attacks have resulted in some of the largest SME "
            "losses in recent years. The Sophos State of Ransomware 2024 report found "
            "that 32% of ransomware victims whose data was also stolen paid the ransom "
            "even though they had backups, because the threat of data publication created "
            "separate liability exposure. Average total recovery costs for double extortion "
            "attacks were $3.58 million, compared to $2.73 million for encryption-only "
            "attacks. For a business holding customer financial data, health records, "
            "or confidential contracts, the threat of public data release triggers "
            "mandatory breach notification, regulatory fines, and potential class action "
            "liability — all independent of whether the ransom is paid. The 2021 Kaseya "
            "VSA attack, which affected over 1,500 SMEs through a single managed IT "
            "provider, demonstrated that small businesses are primary targets for this "
            "attack class. "
            "Source: https://www.sophos.com/en-us/content/state-of-ransomware | "
            "Kaseya case: https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-200a"
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
        # Phone/remote social engineering: network-delivered (VOIP/internet),
        # no privileges needed, but victim must cooperate (UI: required).
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "In a tech support impersonation attack, a criminal calls an employee pretending "
            "to be Microsoft support, the company's IT provider, or another trusted technical "
            "contact. The caller claims there is a problem (a virus detected, a security "
            "alert, an account issue) and asks the employee to install a remote access tool "
            "or provide their login credentials so the 'technician' can fix it. Once the "
            "employee complies, the attacker has full, real-time access to the employee's "
            "computer and everything on it. These calls are designed to create urgency and "
            "bypass skepticism. Businesses without a clearly communicated IT contact policy "
            "are especially vulnerable because employees have no reliable way to verify "
            "whether a caller is legitimate. "
            "FBI IC3 report: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
        ),
        "business_impact": (
            "The FBI IC3 2023 report ranked tech support fraud as the third-costliest "
            "cybercrime category, with reported losses exceeding $924 million — and the "
            "FBI notes that these figures significantly undercount actual losses due to "
            "underreporting. The average loss per victim was $27,994, but corporate victims "
            "report substantially higher losses when business systems are compromised. "
            "Once an attacker has remote access to a business computer, they typically "
            "move immediately to: access saved passwords and banking credentials, "
            "transfer funds from any open financial accounts, install persistent malware "
            "for ongoing access, and pivot to other computers on the same network. "
            "The total cost of a successful tech support scam that results in full "
            "network access can easily reach $100,000 to $500,000 when financial fraud, "
            "IT remediation, and incident response are combined. SMEs with informal IT "
            "arrangements are disproportionately targeted precisely because employees "
            "cannot verify who their real IT contact is. "
            "Source: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
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
        # Known CVEs with public exploit kits. Network-reachable, no privileges
        # needed, no user interaction (remote code execution on unpatched systems).
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Software that has reached its 'end of life' no longer receives security "
            "updates from the manufacturer. This means that every new vulnerability "
            "discovered in that software after the end-of-life date will never be patched "
            "— it becomes a permanent, public entry point. Windows 10, for example, "
            "reached end of life in October 2025. Attackers maintain lists of known "
            "vulnerabilities in end-of-life software and use automated tools to scan "
            "the internet for systems running those versions. No user action is required "
            "for many of these exploits, the attacker simply sends a specially crafted "
            "request to the vulnerable software and gains access. "
            "Check software end-of-life dates: https://endoflife.date"
        ),
        "business_impact": (
            "The 2017 WannaCry ransomware attack exploited a known vulnerability in "
            "unpatched Windows systems and caused an estimated $4 billion to $8 billion "
            "in damages globally, affecting over 200,000 organizations across 150 countries "
            ", including the UK's National Health Service, which had to cancel 19,000 "
            "medical appointments. The vulnerability WannaCry exploited had been patched "
            "by Microsoft two months earlier; organizations running unpatched or end-of-life "
            "Windows had no protection. CISA's guidance on ransomware prevention specifically "
            "identifies unpatched and end-of-life software as among the highest-risk "
            "conditions for ransomware infection. For small businesses, a single successful "
            "exploit against an unpatched system can result in full network compromise, "
            "ransomware deployment, and recovery costs averaging $2.73 million according "
            "to Sophos's 2024 report. "
            "WannaCry case study: https://www.cisa.gov/news-events/cybersecurity-advisories/aa17-132a"
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
        # Default firewall exposes services directly to internet. Automated
        # scanners find them with no privileges or interaction needed.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "A firewall is the gatekeeper between your internal network and the internet. "
            "A firewall running on its factory default settings has not been configured "
            "for your specific environment — it typically allows more inbound connections "
            "than necessary and may leave administrative interfaces accessible from the "
            "internet with default passwords still in place. Attackers use automated "
            "scanning tools that continuously probe the entire internet looking for "
            "misconfigured or default-credential devices. A router with a default admin "
            "password can be taken over in seconds by a bot that found it through a "
            "routine internet scan. Once an attacker controls your firewall or router, "
            "they can redirect your traffic, access every device on your network, "
            "and disable any security controls you have in place. "
            "CISA guidance: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ),
        "business_impact": (
            "CISA and NSA's joint advisory AA23-278A, based on assessments of over 1,000 "
            "networks, identified default configurations as one of the top ten most "
            "common security weaknesses found across both government and private sector "
            "organizations. A misconfigured or default-credential firewall is not a "
            "theoretical risk; Shodan, a publicly accessible internet scanning service, "
            "indexes millions of exposed devices with default credentials at any given "
            "time. An attacker who gains control of your network perimeter device can "
            "intercept all network traffic, redirect users to malicious sites, gain "
            "access to every device behind the firewall, and maintain persistent access "
            "that survives password changes on individual workstations. The cost of "
            "full network remediation after a firewall compromise averages $200,000 to "
            "$500,000 for small businesses, including forensic investigation, system "
            "rebuilds, and business interruption. "
            "Source: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"
        ),
        "recommendation": (
            "Change all firewall and router admin passwords from defaults immediately. "
            "Disable remote management over the internet unless absolutely necessary. "
            "Block all inbound connections except those explicitly required. Enable "
            "automatic firmware updates on your router. If you use a managed service provider (MSP), ask them "
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
        # Untracked internet-connected devices are network-reachable by default.
        # No privileges or interaction needed to exploit forgotten assets.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "An asset inventory is a simple list of every device and piece of software "
            "used in your business: computers, servers, phones, printers, routers, "
            "and the applications running on them. Without it, you have no baseline to "
            "work from. You cannot patch what you don't know about, you cannot monitor "
            "what you haven't identified, and you cannot protect a device you don't know "
            "is connected to your network. Forgotten or decommissioned devices are "
            "particularly dangerous as they are often running outdated, unpatched software "
            "and remain connected to the network indefinitely without anyone noticing. "
            "NIST explicitly identifies maintaining an asset inventory as the first and "
            "most foundational step in any cybersecurity program. "
            "NIST guidance: https://csrc.nist.gov/files/pubs/other/2022/02/24/getting-started-with-cybersecurity-risk-management/final/docs/quick-start-guide--ransomware.pdf"
        ),
        "business_impact": (
            "Every untracked device is a potential entry point that cannot be monitored "
            "or protected. The Verizon 2024 DBIR found that asset management failures ( "
            "including untracked and unpatched devices) were contributing factors in a "
            "significant percentage of ransomware incidents. The practical business impact "
            "is compounding: a business without an asset inventory cannot complete a "
            "meaningful risk assessment, cannot verify that all devices are patched, "
            "cannot confirm that former employees' devices have been wiped, and cannot "
            "accurately scope a breach notification if an incident occurs. This last "
            "point has direct financial consequences; if you cannot determine which "
            "devices were affected in a breach, you must assume all devices were, "
            "dramatically expanding the scope of required notification and the associated "
            "cost of $125 to $175 per customer record. Maintaining a basic spreadsheet "
            "asset inventory costs nothing and is the prerequisite for almost every other "
            "security control. "
            "Source: https://www.verizon.com/business/resources/reports/dbir/"
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
        # Impact amplifier: the triggering attack is network-delivered.
        # Absence of BCP requires no privileges or interaction to exploit.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "A business continuity plan is a simple, documented answer to the question: "
            "'What do we do if our computers stop working?' It does not need to be long "
            "or complex, a single page covering who to call, how to communicate with "
            "customers, how to process transactions manually if needed, and who has "
            "authority to make decisions is enough to significantly reduce the chaos "
            "and cost of an outage. Without one, every person in the organization is "
            "improvising during a crisis, when improvising is most likely to result "
            "in costly mistakes such as paying a ransom unnecessarily, delaying required "
            "regulatory notifications, or making IT decisions that destroy forensic evidence. "
            "NIST SP 1800-26 guidance: https://www.nccoe.nist.gov/data-integrity-detecting-and-responding-ransomware-and-other-destructive-events"
        ),
        "business_impact": (
            "NIST SP 1800-26 identifies the absence of a recovery plan as a primary "
            "multiplier of incident cost and duration. Research consistently shows that "
            "organizations with tested incident response plans contain breaches faster "
            "and at significantly lower cost. The IBM Cost of a Data Breach 2024 report "
            "found that organizations with an incident response team and regularly tested "
            "plan saved an average of $1.49 million per breach compared to those without. "
            "For small businesses, the most common failure mode is extended downtime: "
            "without a plan, restoring systems from backup can take days instead of "
            "hours, every additional hour of downtime has a direct revenue impact. "
            "For a business generating $500,000 in annual revenue, each day of full "
            "operational outage costs approximately $1,370 in lost revenue alone. "
            "Source: https://www.ibm.com/reports/data-breach"
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
        # Fully automated internet attack against cloud login portals.
        # Bots run 24/7 with no privileges or user interaction required.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Microsoft 365 and Google Workspace are among the most targeted platforms "
            "for automated credential attacks because they hold everything: email, "
            "files, contacts, calendars, financial integrations, and often administrative "
            "access to other connected applications. Attackers continuously test billions "
            "of leaked username and password combinations against the login portals of "
            "these platforms. A 2024 CyberArk study found that 49% of employees reuse "
            "the same credentials across multiple work-related applications. Without "
            "multi-factor authentication, any employee whose password appears in a "
            "leaked credential database, from any website, not just your own, is "
            "immediately vulnerable. The attack is fully automated, runs around the clock, "
            "and succeeds silently. "
            "CISA MFA guidance: https://www.cisa.gov/MFA"
        ),
        "business_impact": (
            "A successful Microsoft 365 or Google Workspace account takeover gives an "
            "attacker immediate access to every email ever sent or received, every file "
            "stored in OneDrive or Google Drive, every contact and calendar entry, and "
            "any application connected via single sign-on. For most small businesses, "
            "this represents the entirety of their business data and operations. "
            "The IBM Cost of a Data Breach 2024 report found that compromised credentials "
            "were the most common initial attack vector, with an average breach cost of "
            "$4.81 million. For cloud-first SMEs where Microsoft 365 or Google Workspace "
            "is the primary business system, a full account compromise can be operationally "
            "equivalent to a complete network breach. Microsoft reports that enabling MFA "
            "blocks over 99.9% of automated credential attacks, making it the single "
            "highest-return security control available, at zero additional cost for "
            "businesses already paying for these platforms. "
            "Source: https://www.ibm.com/reports/data-breach"
        ),
        "recommendation": (
            "Enable MFA on all cloud services immediately, especially Microsoft 365 "
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
        # Insider has local access and legitimate credentials (low PR).
        # Acts directly on systems with no network barrier or UI dependency.
        "cvss_av": "local",
        "cvss_ac": "low",
        "cvss_pr": "low",
        "cvss_ui": "none",
        "description": (
            "An insider threat is any employee, contractor, or business partner who "
            "misuses their legitimate access to cause harm — intentionally or accidentally. "
            "For small businesses without formal access controls, most employees have "
            "access to most business systems and data. A departing employee who knows "
            "they are leaving, or who has been terminated, may copy customer lists, "
            "pricing data, financial records, or trade secrets before their access is "
            "revoked. This is particularly common in industries like professional services, "
            "sales, and technology where customer relationships and intellectual property "
            "are the core business assets. Insider threats are uniquely difficult to "
            "detect because the access used is completely legitimate. "
            "CISA insider threat guidance: https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats"
        ),
        "business_impact": (
            "The Ponemon Institute's 2022 Cost of Insider Threats Global Report found "
            "that the average cost of an insider incident was $648,062, with incidents "
            "involving credential theft averaging $804,997. For small businesses, insider "
            "theft most commonly results in: loss of customer relationships when a "
            "departing employee takes client data to a competitor, competitive harm when "
            "pricing, proposals, or product plans are stolen, and legal liability when "
            "customer PII is taken and subsequently breached at the recipient. "
            "Verizon's Data Breach Investigation Report consistently finds that insiders are responsible for approximately "
            "20% of breaches annually, and that small businesses are disproportionately "
            "affected because they lack the monitoring controls to detect unauthorized "
            "data access before it happens. Applying the principle of least privilege "
            "(giving employees access only to what they need for their specific role) "
            "is the primary control, and it costs nothing to implement. "
            "Source: https://www.ponemon.org/research/ponemon-library/security/cost-of-insider-threats-global.html"
        ),
        "recommendation": (
            "Combine two controls: (1) Least privilege — employees should only ever "
            "have access to what their current role requires. (2) Immediate offboarding "
            ": accounts disabled on the last day, no exceptions. CISA's insider threat "
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
        # Attacker sends spoofed email over network with no privileges.
        # Recipient (UI: required) must be deceived to make the attack succeed.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "Without proper email authentication records (SPF, DKIM, and DMARC) configured "
            "for your domain, any person in the world can send an email that appears to "
            "come from your exact email address. Your customers, vendors, and employees "
            "will see your real domain name as the sender, they have no way to know the "
            "email is fake. Attackers use this to send fraudulent invoices to your clients "
            "in your name, impersonate your executives to your staff, and intercept "
            "payments by redirecting them to attacker-controlled accounts. SPF, DKIM, and "
            "DMARC are free DNS records that tell email servers how to verify that an "
            "email actually came from you. Free tools like MXToolbox can check whether "
            "they are configured: https://mxtoolbox.com/dmarc.aspx"
        ),
        "business_impact": (
            "The FBI IC3 2023 report recorded 21,489 BEC complaints, many enabled by "
            "domain spoofing, with adjusted losses exceeding $2.9 billion. Email domain "
            "spoofing is the primary technical enabler of invoice fraud, where attackers "
            "send fake invoices to your customers appearing to come from your legitimate "
            "address and directing payment to attacker-controlled bank accounts. Your "
            "business bears the reputational and legal consequences even though you were "
            "not the one who sent the fraudulent email. Customers who receive fraudulent "
            "emails from your domain may hold your business liable for their losses, "
            "particularly in B2B contexts governed by contracts that include reasonable "
            "security obligations. Beyond fraud, an unprotected domain can be used to "
            "mass-send spam or phishing emails, resulting in your domain being blacklisted "
            "and your legitimate emails no longer being delivered. "
            "Source: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
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
            "https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf",
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
        # Requires physical access to disposed device. Commercial recovery tools
        # need no privileges and work without user interaction.
        "cvss_av": "physical",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "When a computer, laptop, phone, or hard drive is discarded, sold, donated, "
            "or traded in, a standard factory reset or quick format does not erase the "
            "data. The files are removed from the directory but the actual data remains "
            "on the disk until it is overwritten. Commercially available data recovery "
            "software can reconstruct files, emails, photographs, "
            "saved passwords, and browsing history from a 'wiped' drive in minutes. "
            "NIST SP 800-88 defines approved methods for secure media sanitization that "
            "actually prevent recovery. Secure erasure takes the same amount of time as "
            "a standard format on most devices and completely eliminates the risk. "
            "NIST SP 800-88: https://csrc.nist.gov/pubs/sp/800/88/r1/final"
        ),
        "business_impact": (
            "For businesses that handle customer PII, financial data, or health information, "
            "data recovered from improperly disposed devices constitutes a data breach "
            "regardless of whether the data was intentionally accessed. This triggers "
            "mandatory breach notification obligations under most state laws and federal "
            "regulations. The average cost of notification is $125 to $175 per affected "
            "record (IBM 2024). A single old laptop containing records for 2,000 customers "
            "could generate $250,000 to $350,000 in notification and response costs from "
            "what appeared to be a routine device disposal. Academic researchers and "
            "security firms have repeatedly demonstrated this risk: a 2019 study by "
            "Blancco found that 42% of second-hand hard drives purchased on eBay contained "
            "recoverable data, including corporate documents, customer PII, and "
            "financial records. Secure erasure tools are free and the process adds "
            "minutes to the disposal workflow. "
            "Source: https://csrc.nist.gov/pubs/sp/800/88/r1/final"
        ),
        "recommendation": (
            "Use NIST-approved secure erasure methods before disposing of any device: "
            "DBAN (https://dban.org/) for hard drives, or physical destruction for drives containing "
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
        # Email-delivered over network, no privileges needed.
        # User must click/open (UI: required) — the defining characteristic
        # of phishing as an attack class.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "required",
        "description": (
            "Phishing is an email designed to deceive the recipient into taking an action "
            "that benefits the attacker: clicking a link that steals their password, "
            "opening an attachment that installs malware, or approving a transaction they "
            "believe is legitimate. Spearphishing is a targeted variant where the attacker "
            "researches the business first, learning the names of executives, vendors, "
            "and current projects, to craft a convincing, personalized message. A "
            "spearphishing email might appear to come from the business owner asking an "
            "employee to urgently process a payment, from an accountant asking for a "
            "W-2 form, or from IT notifying that a password reset is required. These "
            "emails are increasingly difficult to distinguish from legitimate ones. "
            "FBI phishing data: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
        ),
        "business_impact": (
            "Phishing was the most frequently reported cybercrime in the FBI IC3 2023 "
            "report, accounting for over 298,000 complaints, approximately 34% of all "
            "reported cyber incidents. It is also the most common initial access vector "
            "for ransomware, BEC fraud, and credential theft. A single successful phishing "
            "click can result in any of the following: immediate ransomware deployment "
            "across the entire network, credential theft leading to full account takeover, "
            "a fraudulent wire transfer averaging $137,000 for BEC-related phishing, "
            "or silent malware installation providing persistent network access. "
            "The Verizon 2024 DBIR found phishing involved in 36% of all breaches. "
            "Despite being the most common threat, it is also highly preventable: "
            "technical email filtering combined with employee awareness training "
            "significantly reduces successful phishing rates. Businesses with no "
            "email filtering and no training have no technical or human layer of "
            "defense against the most common attack vector in existence. "
            "Source: https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"
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
        # Directly internet-facing RDP. Automated brute-force bots need no
        # privileges and no user interaction — highest-risk CVSS profile.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Remote Desktop Protocol (RDP) is a built-in Windows feature that allows "
            "someone to connect to and control a computer over the internet as if they "
            "were sitting in front of it. When RDP is exposed directly to the internet "
            "without a VPN or other protection layer, it is immediately visible to "
            "automated scanning tools that continuously probe the entire internet looking "
            "for open RDP ports. These tools then attempt to log in using lists of common "
            "usernames and passwords, a process called brute-forcing, running thousands "
            "of attempts per minute, around the clock. A weak password is all that stands "
            "between an attacker and complete remote control of the target computer. "
            "CISA identifies exposed RDP as one of the top initial access vectors for "
            "ransomware operators. "
            "CISA advisory: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ),
        "business_impact": (
            "CISA Advisory AA22-137A, based on assessments across hundreds of organizations, "
            "identifies exposed remote services, particularly RDP, as the most common "
            "initial access vector for ransomware attacks. Once an attacker successfully "
            "logs into an exposed RDP session, they have full interactive control of that "
            "computer with the privileges of the account they compromised. From that "
            "position, attackers typically deploy ransomware across the entire network "
            "within hours. The Sophos 2024 ransomware report found that RDP compromise "
            "was responsible for 32% of ransomware incidents, with average recovery costs "
            "of $2.73 million. Unlike phishing attacks that require an employee to make "
            "a mistake, exposed RDP requires no human involvement to exploit — an attacker "
            "can compromise an exposed RDP server at 3 AM on a Sunday with no one aware "
            "until Monday morning when encrypted files are discovered. Placing RDP behind "
            "a VPN eliminates this attack surface entirely and takes less than an hour "
            "to configure. "
            "Source: https://www.sophos.com/en-us/content/state-of-ransomware"
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
        # Multiple public-facing services, misconfigured firewall. Automated
        # scanners probe continuously with no privileges or interaction.
        "cvss_av": "network",
        "cvss_ac": "low",
        "cvss_pr": "none",
        "cvss_ui": "none",
        "description": (
            "Every service that is accessible from the internet (a website, a customer "
            "portal, a file sharing server, remote desktop, email server, or VPN) is "
            "a potential entry point that attackers can probe for vulnerabilities. When "
            "three or more services are internet-exposed and the network perimeter is "
            "protected only by a default or misconfigured firewall, the attack surface "
            "becomes large and difficult to defend. Automated scanners operated by "
            "criminal groups continuously probe the entire internet, cataloging every "
            "exposed service and testing each one for known vulnerabilities, default "
            "credentials, and unpatched software. A business with multiple exposed "
            "services provides multiple independent opportunities for compromise, "
            "only one needs to succeed. "
            "CISA external exposure guidance: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"
        ),
        "business_impact": (
            "CISA Advisory AA23-278A found that the presence of multiple internet-exposed "
            "services with weak perimeter controls was one of the most consistent findings "
            "across over 1,000 assessed networks. Each additional exposed service "
            "multiplies the attack surface. A business with three exposed services and "
            "a misconfigured firewall is not three times as exposed as a business with "
            "one, it is exponentially more exposed, because each service may have "
            "different vulnerabilities, different patch levels, and different credential "
            "policies. Shodan, a public internet scanning service, indexes millions of "
            "exposed business services at any given time, many of which are running "
            "unpatched software with known vulnerabilities. The average cost of a breach "
            "originating from an exposed public-facing application was $4.55 million "
            "according to IBM's Cost of a Data Breach 2024 report, reflecting the broad system access "
            "typically achieved through this vector. "
            "Source: https://www.ibm.com/reports/data-breach"
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