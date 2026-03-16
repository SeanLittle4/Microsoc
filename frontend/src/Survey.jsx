import { useState, useEffect } from "react";

// ─── PASTA + ATT&CK SURVEY DATA ───────────────────────────────────────────────

const SECTIONS = [
  {
    id: "objectives",
    pastaStage: 1,
    pastaLabel: "Business Objectives",
    pastaDesc: "Define what must be protected and why it matters",
    attackTactics: ["TA0043 – Reconnaissance"],
    color: "#c8922a",
    icon: "I",
    title: "Business Objectives & Priorities",
    subtitle:
      "PASTA begins by anchoring the threat model in your business goals — not technology. Attackers conduct reconnaissance (TA0043) to understand exactly what you value before they strike.",
    questions: [
      {
        id: "industry",
        pastaNote: "Determines regulatory exposure and attacker motivation profile",
        text: "What industry is your business in?",
        options: [
          "Healthcare or medical services",
          "Finance, accounting, or insurance",
          "Legal or professional services",
          "Retail or e-commerce",
          "Construction, real estate, or property management",
          "Manufacturing or supply chain",
          "Technology or IT services",
          "Government contracting or public sector services",
          "Other",
        ],
      },
      {
        id: "employees",
        pastaNote: "Scopes attack surface size and insider risk complexity",
        text: "How many people work at your company, including part-time staff and contractors?",
        options: [
          "1–5 people",
          "6–15 people",
          "16–50 people",
          "51–100 people",
          "More than 100 people",
        ],
      },
      {
        id: "crown_jewel",
        pastaNote: "Identifies primary business asset — the target attackers optimize for",
        text: "If a cyberattack succeeded tomorrow, which outcome would be most devastating to your business?",
        hint: "Think about what would force you to close, face lawsuits, or lose your customers' trust permanently.",
        options: [
          "Theft of customer data — lawsuits, lost trust, regulatory fines",
          "Loss of access to our systems — unable to operate for days or weeks",
          "Theft of money directly from bank or payment accounts",
          "Exposure of confidential contracts, pricing, or business strategies",
          "Reputational damage from public breach notification",
          "Regulatory penalties for non-compliance with data protection laws",
          "I'm not sure — we haven't thought through the worst case",
        ],
      },
      {
        id: "compliance",
        pastaNote: "Maps to regulatory threat scenarios with elevated attacker motivation",
        text: "Is your business required by law, contract, or industry rules to protect certain data?",
        hint: "For example: HIPAA for healthcare, PCI-DSS for card payments, state privacy laws like CCPA.",
        options: [
          "Yes — healthcare data regulations (HIPAA)",
          "Yes — payment card regulations (PCI-DSS)",
          "Yes — state privacy laws (e.g., CCPA, VCDPA)",
          "Yes — contractual requirements from customers or partners",
          "Yes — multiple of the above",
          "No known regulatory requirements",
          "I'm not sure",
        ],
      },
      {
        id: "downtime_tolerance",
        pastaNote: "Quantifies availability impact for ransomware and disruption threat scenarios",
        text: "If your business systems were completely unavailable for 48 hours, what would happen?",
        options: [
          "We would lose significant revenue and might not recover",
          "Serious disruption — we'd lose customers and face real financial harm",
          "Moderate disruption — painful but we'd survive",
          "Minor inconvenience — we have manual fallback processes",
          "We're not sure what would happen",
        ],
      },
      {
        id: "cyber_insurance",
        pastaNote: "SEANCE Layer 1 — financial risk transfer reduces existential impact of incidents",
        text: "Does your business have cyber insurance to help cover costs in the event of a cyberattack?",
        hint: "Cyber insurance can cover costs like legal fees, customer notification, ransomware payments, and lost revenue.",
        options: [
          "Yes — we have a dedicated cyber insurance policy",
          "Possibly — it may be included in our general business insurance but we haven't confirmed",
          "No — we don't have cyber insurance",
          "I'm not sure",
        ],
      },
      {
        id: "business_continuity",
        pastaNote: "SEANCE Layer 1 — absence of BCP multiplies recovery time and financial impact",
        text: "Does your business have a plan for continuing to operate during or after a cyberattack or major IT outage?",
        hint: "A business continuity plan covers things like: who takes over if a key person is unavailable, how you operate without your systems, and how you communicate with customers during an incident.",
        options: [
          "Yes — we have a written business continuity plan",
          "Informally — we have a rough idea but nothing written down",
          "No — we haven't thought through how we'd operate without our systems",
          "I'm not sure",
        ],     
      },
    ],
  },
  {
    id: "scope",
    pastaStage: 2,
    pastaLabel: "Technical Scope",
    pastaDesc: "Map the systems and platforms that support business operations",
    attackTactics: ["TA0043 – Reconnaissance", "TA0001 – Initial Access"],
    color: "#a87fc2",
    icon: "II",
    title: "Your Technology Environment",
    subtitle:
      "PASTA Stage 2 maps the technical boundaries of your business. Attackers use reconnaissance (TA0043) to profile your public-facing systems before choosing an initial access path (TA0001).",
    questions: [
      {
        id: "infra_model",
        pastaNote: "Determines whether threat scenarios are cloud-native, hybrid, or on-prem",
        text: "How is your business technology primarily set up?",
        options: [
          "Everything is in the cloud — no on-site servers (e.g., Microsoft 365, Google Workspace)",
          "Primarily on-site servers and infrastructure",
          "A mix — some systems on-site, some in the cloud (hybrid)",
          "We rely almost entirely on third-party software managed by vendors",
          "I'm not sure how to categorize our setup",
        ],
      },
      {
        id: "platforms",
        pastaNote: "Identifies platform-specific attack surfaces and misconfiguration risk",
        text: "Which of the following platforms does your business actively use?",
        multi: true,
        options: [
          "Microsoft 365 (Outlook, Teams, SharePoint, OneDrive)",
          "Google Workspace (Gmail, Drive, Meet)",
          "Cloud file storage (Dropbox, Box, or similar)",
          "On-site Windows file servers or Active Directory",
          "Customer or project management software (Salesforce, HubSpot, etc.)",
          "Accounting or finance software (QuickBooks, Xero, etc.)",
          "HR or payroll platform (Gusto, ADP, etc.)",
          "Custom-built or industry-specific software",
        ],
      },
      {
        id: "devices",
        pastaNote: "Unmanaged personal devices are high-risk endpoints with no enterprise controls",
        text: "What devices do employees use to access work systems?",
        options: [
          "Company-owned and managed devices only",
          "Primarily company devices, but some personal devices are used too",
          "Mix of company and personal devices — no formal policy",
          "Mostly personal devices (bring your own device)",
          "I'm not sure",
        ],
      },
      {
        id: "internet_exposed",
        pastaNote: "Directly maps to externally accessible attack surface for TA0001",
        text: "Which of the following does your business expose directly to the internet?",
        hint: "\"Exposed to the internet\" means external people can reach it without a VPN or special network connection.",
        multi: true,
        options: [
          "Business website or web application",
          "Email system (people can email you from outside)",
          "Remote desktop — employees connect to office computers from home",
          "Client portal or customer login page",
          "File sharing links accessible via the web",
          "VPN gateway for remote employee access",
          "None — everything requires being on-site",
          "I'm not sure what's exposed",
        ],
      },
      {
        id: "asset_inventory",
        pastaNote: "SEANCE Layer 3 — you cannot protect assets you haven't identified",
        text: "Does your business maintain an inventory of all devices used for work — computers, phones, tablets, servers?",
        hint: "An asset inventory is a simple list of every device, who uses it, and what data it stores or accesses.",
        options: [
          "Yes — we have an up-to-date list of all devices and their designated users",
          "Partially — we track some devices but not all",
          "No — we don't have a formal inventory",
          "I'm not sure",
        ],
      },
      {
        id: "unsupported_software",
        pastaNote: "SEANCE Layer 3 — end-of-life software has no security patches, permanent vulnerability",
        text: "Does your business use any software or operating systems that are no longer receiving security updates from the manufacturer?",
        hint: "Examples: Windows 7, Windows 10 (support ends 2025), Office 2013, or any software where the vendor has announced end-of-life.",
        options: [
          "No — all software and operating systems we use are actively supported",
          "Yes — some systems are running end-of-life software",
          "I'm not sure whether all our software is still supported",
        ],
      },
      {
        id: "iot_devices",
        pastaNote: "SEANCE Layer 3 — IoT default credentials are trivially exploited and rarely changed",
        text: "Does your business use any internet-connected devices beyond computers and phones — such as smart TVs, security cameras, printers, or building access systems?",
        hint: "These are called IoT (Internet of Things) devices. They often come with default passwords that are never changed, making them easy entry points.",
        options: [
          "Yes — and we have changed all default passwords and keep firmware updated",
          "Yes — but we haven't changed default passwords or checked for updates",
          "No — we don't use any such devices",
          "I'm not sure what counts or what we have",
        ],
      },
      {
        id: "website_security",
        pastaNote: "SEANCE Layer 3 — unencrypted or unpatched websites expose customers and business data",
        text: "Does your business have a public-facing website? If so, how is it secured?",
        options: [
          "Yes — it uses HTTPS and is regularly updated",
          "Yes — but we're not sure if it's fully secured or up to date",
          "Yes — and it accepts customer payments or account logins",
          "No — we don't have a public website",
        ],
      },
    ],
  },
  {
    id: "decomposition",
    pastaStage: 3,
    pastaLabel: "Application Decomposition",
    pastaDesc: "Trace how data flows and who can touch it",
    attackTactics: ["TA0001 – Initial Access", "TA0006 – Credential Access"],
    color: "#4ea8a0",
    icon: "III",
    title: "Data Flows & Trust Boundaries",
    subtitle:
      "PASTA Stage 3 maps every path data travels and every person or system that touches it. These are your trust boundaries — each one is a potential entry point for TA0001 and TA0006.",
    questions: [
      {
        id: "data_movement",
        pastaNote: "Identifies unauthorized data movement paths and exfiltration risk",
        text: "How does sensitive business data typically move in your organization?",
        multi: true,
        options: [
          "Emailed internally between employees",
          "Emailed externally to clients, vendors, or partners",
          "Shared via cloud storage links (OneDrive, Google Drive, Dropbox)",
          "Stored on USB drives or physical media",
          "Accessed through a web portal or app by remote workers",
          "Transmitted to third-party systems automatically (e.g., accounting sync, CRM integration)",
          "Printed and handled as physical documents",
          "We haven't mapped how our data moves",
        ],
      },
      {
        id: "vendor_access",
        pastaNote: "Third-party access is a trusted-relationship entry vector in TA0001",
        text: "Do outside vendors, IT contractors, or business partners have access to your systems or data?",
        options: [
          "Yes — multiple vendors have ongoing, regular access",
          "Yes — one vendor or IT provider has access",
          "Occasionally, for specific one-time projects only",
          "No — only our own employees have access",
          "I'm not sure who has access",
        ],
      },
      {
        id: "vendor_controls",
        pastaNote: "Shared/uncontrolled vendor credentials are a common breach path",
        text: "How is outside vendor or contractor access to your systems managed?",
        options: [
          "Vendors use their own dedicated accounts we created for them",
          "Vendors use a shared account we gave them",
          "Vendors use an employee's account when they need access",
          "We don't have a formal process — it varies",
          "We have no outside vendor access",
          "I'm not sure",
        ],
      },
      {
        id: "connected_apps",
        pastaNote: "OAuth app grants are a persistent trust boundary that survives password changes",
        text: "Have employees connected personal or third-party apps to work accounts?",
        hint: "Examples: a productivity tool connected to work email, a scheduling app with calendar access, or a file tool synced to company storage.",
        options: [
          "Yes — employees regularly connect apps to their work accounts",
          "Yes — a few apps are connected but it's controlled",
          "No — this is technically blocked or there is a clear policy against it",
          "I'm not sure",
        ],
      },
      {
        id: "offboarding",
        pastaNote: "Stale accounts are high-value credential targets; ghost access is a persistent risk",
        text: "When an employee or contractor leaves your company, how quickly are their accounts and access removed?",
        options: [
          "Immediately on their last day — we have a formal checklist",
          "Within a few days — someone handles it eventually",
          "We try to remember, but it varies and isn't tracked",
          "We don't have a formal process for revoking access",
          "I'm not sure if past employees still have access",
        ],
      },
      {
        id: "customer_pii",
        pastaNote: "SEANCE Layer 5 — PII collection creates regulatory and breach notification obligations",
        text: "Does your business collect and store personal information about customers — such as names, addresses, emails, or payment details?",
        options: [
          "Yes — and we have a clear privacy policy and process for handling it",
          "Yes — but we don't have a formal process for managing or protecting it",
          "Minimally — we only collect what's absolutely necessary to conduct business",
          "No — we don't collect or store customer personal information",
        ],
      },
      {
        id: "customer_breach_notification",
        pastaNote: "SEANCE Layer 5 — regulatory breach notification deadlines can be as short as 72 hours (GDPR)",
        text: "If customer data were exposed in a breach, do you have a process for notifying affected customers and any required regulators?",
        options: [
          "Yes — we have a documented notification process and know our legal obligations",
          "Somewhat — we know we'd need to notify people but haven't formalized the steps",
          "No — we don't have a notification process in place",
          "I'm not sure what our obligations would be",
        ],
      },
      {
        id: "data_encryption",
        pastaNote: "SEANCE Layer 3 — unencrypted data-at-rest is immediately readable if a device is stolen",
        text: "Is sensitive business data encrypted when it is stored on devices or transmitted between systems?",
        hint: "Encryption scrambles data so it's unreadable without the correct key — even if a device is stolen, encrypted data cannot be accessed.",
        options: [
          "Yes — full disk encryption is enabled on all devices and we use encrypted connections",
          "Partially — some devices or transfers are encrypted but not all",
          "No — we don't use encryption for stored or transmitted data",
          "I'm not sure",
        ],
      },
      {
        id: "data_disposal",
        pastaNote: "SEANCE Layer 3 — improperly disposed devices are a common source of data recovery attacks",
        text: "When your business disposes of old computers, phones, or storage drives, how is the data removed?",
        options: [
          "We use a secure wipe tool or professional destruction service before disposal",
          "We do a standard factory reset or format",
          "We dispose of devices without specifically wiping them first",
          "We don't have a formal process for this",
        ],
      },
    ],
  },
  {
    id: "threats",
    pastaStage: 4,
    pastaLabel: "Threat Analysis",
    pastaDesc: "Identify realistic attacker profiles and how they would target you",
    attackTactics: ["TA0001 – Initial Access", "TA0006 – Credential Access", "TA0043 – Reconnaissance"],
    color: "#e05c5c",
    icon: "IV",
    title: "Threat Actors & Attack Vectors",
    subtitle:
      "PASTA Stage 4 identifies who would realistically attack your business and how. Most SME breaches start with phishing (TA0001) or stolen credentials (TA0006) — not sophisticated hacking.",
    questions: [
      {
        id: "phishing_posture",
        pastaNote: "Phishing is the #1 initial access vector for BEC, ransomware, and credential theft",
        text: "How confident are you that your employees can identify a fake or malicious email (phishing)?",
        hint: "Phishing emails impersonate real companies or colleagues to steal passwords or trick employees into transferring money.",
        options: [
          "Very confident — we have regular security awareness training",
          "Somewhat confident — most employees are careful",
          "Not confident — we haven't had formal phishing training",
          "We've already had an incident involving a phishing email",
          "I'm not sure",
        ],
      },
      {
        id: "email_filtering",
        pastaNote: "Email filtering reduces TA0001 surface area; absence dramatically increases risk",
        text: "Does your email system automatically scan for malicious attachments and suspicious links?",
        options: [
          "Yes — our email scans attachments and warns about dangerous links",
          "Partially — we have some filtering but it's not comprehensive",
          "No — emails arrive with no automated scanning",
          "I'm not sure what protections our email has",
        ],
      },
      {
        id: "email_domain_auth",
        pastaNote: "DMARC/SPF/DKIM absence allows attackers to send email appearing to come from your exact domain",
        text: "Has anyone set up protections to prevent attackers from sending emails that appear to come from your business's email address?",
        hint: "This is called email authentication (SPF, DKIM, and DMARC). Without it, an attacker can send a fake invoice or payment request and your customers or partners will see your real email address as the sender — with no way to tell it's fraudulent.",
        options: [
            "Yes — our IT provider or email admin has confirmed SPF, DKIM, and DMARC are configured",
            "We have an IT provider but I'm not sure if they've set this up",
            "No — we manage our own email and haven't configured these protections",
            "I'm not sure what this is or whether it's in place",
        ],
      },
      {
        id: "wire_transfer_risk",
        pastaNote: "Business Email Compromise (BEC) targeting wire transfers is among the highest-cost SME attacks",
        text: "Does your business ever send payments, wire transfers, or change vendor banking details based on email instructions?",
        hint: "Business Email Compromise (BEC) is when attackers impersonate a boss or vendor over email to redirect payments.",
        options: [
          "Yes — financial decisions are routinely made via email",
          "Yes — occasionally, with limited verification steps",
          "No — we always verify payment changes through a second channel (phone call, in person)",
          "We don't send wire transfers or large payments",
          "I'm not sure what our process is",
        ],
      },
      {
        id: "credential_reuse",
        pastaNote: "Credential stuffing (TA0006) exploits reused passwords from other breached services",
        text: "Do employees use the same or similar passwords across multiple accounts — personal and work?",
        options: [
          "No — we require unique passwords and use a password manager",
          "We have a password policy but can't verify compliance",
          "Probably — we haven't enforced a password policy",
          "Yes — password reuse is common here",
          "I'm not sure",
        ],
      },
      {
        id: "social_engineering",
        pastaNote: "Vishing and impersonation attacks target employees with high access and low training",
        text: "Could an attacker call your office, pretend to be IT support or a vendor, and convince an employee to reveal a password or grant access?",
        hint: "This is called social engineering — it exploits trust rather than technology.",
        options: [
          "Unlikely — employees are trained to verify identity through official channels",
          "Possibly — employees might comply without formal verification",
          "Very likely — we haven't trained employees on this risk",
          "I'm not sure",
        ],
      },
      {
        id: "physical_security",
        pastaNote: "SEANCE Layer 6 — physical access bypasses all digital controls",
        text: "What physical security controls does your business have in place to protect computers and servers from unauthorized access?",
        options: [
          "Locked office with badge or key access — visitors are always supervised",
          "Locked office but access isn't strictly controlled",
          "Open environment — physical access to computers is not restricted",
          "Fully remote — no central office or physical equipment to secure",
        ],
      },
      {
        id: "visitor_tracking",
        pastaNote: "SEANCE Layer 6 — untracked external visitors are an insider threat and physical recon vector",
        text: "Does your business track or log non-employee visitors to your workplace — such as suppliers, contractors, or repair technicians?",
        options: [
          "Yes — all visitors sign in and are escorted",
          "Informally — we generally know who is in the building but don't log it",
          "No — visitors come and go without a formal process",
          "We are fully remote — this isn't applicable",
        ],
      },
      {
        id: "employee_personal_wifi",
        pastaNote: "SEANCE Layer 2 — unencrypted public Wi-Fi exposes credentials and data in transit",
        text: "When employees work remotely from public places like coffee shops or airports, do they take precautions with their internet connection?",
        options: [
          "Yes — remote employees are required to use a VPN on public Wi-Fi",
          "We recommend it but don't enforce it",
          "No — employees connect to public Wi-Fi without a VPN",
          "We don't have remote employees, or they don't work from public places",
          "I'm not sure",
        ],
      },
    ],
  },
  {
    id: "vulnerabilities",
    pastaStage: 5,
    pastaLabel: "Vulnerability Analysis",
    pastaDesc: "Identify exploitable weaknesses in your current security controls",
    attackTactics: ["TA0006 – Credential Access", "TA0004 – Privilege Escalation", "TA0005 – Defense Evasion"],
    color: "#e8a020",
    icon: "V",
    title: "Security Weaknesses & Configuration Gaps",
    subtitle:
      "PASTA Stage 5 identifies specific vulnerabilities an attacker can exploit. Weak authentication, excess privilege, and poor patching are the top entry points for TA0006 and TA0004.",
    questions: [
      {
        id: "mfa",
        pastaNote: "Absent MFA is exploited in >80% of cloud identity compromises",
        text: "Is two-step verification (also called MFA or 2FA) required to log into your most critical systems?",
        hint: "MFA means logging in requires both a password AND a second step — like a code sent to your phone.",
        options: [
          "Yes — required for all accounts without exception",
          "Yes — required for some accounts (e.g., email) but not others",
          "It's available but optional — employees decide whether to use it",
          "No — we rely on passwords only",
          "I'm not sure",
        ],
      },
      {
        id: "admin_access",
        pastaNote: "Excessive admin accounts expand TA0004 privilege escalation surface",
        text: "Who in your organization has administrator-level access — the ability to change system settings, create accounts, or manage other users?",
        options: [
          "Only one dedicated IT person or administrator",
          "A small group of 2–4 IT staff",
          "Several employees across different departments",
          "An outside IT company or managed service provider",
          "I'm not sure who has admin-level access",
        ],
      },
      {
        id: "least_privilege",
        pastaNote: "Overprivileged accounts are primary targets for lateral movement post-compromise",
        text: "Do employees only have access to the files, systems, and accounts they actually need for their specific job?",
        hint: "This is called 'least privilege' — limiting what each person can access reduces damage if their account is compromised.",
        options: [
          "Yes — access is strictly controlled based on job role",
          "Mostly — but some people have broader access than necessary",
          "No — most employees can access most company systems and data",
          "I'm not sure what level of access employees have",
        ],
      },
      {
        id: "patching",
        pastaNote: "Unpatched systems are the primary vector for exploitation of known vulnerabilities (TA0005)",
        text: "How are software updates and security patches applied to computers and systems in your business?",
        options: [
          "Automatically — updates install themselves without employee action",
          "Manually, on a regular schedule — we check and apply updates consistently",
          "When problems arise or IT notices something is out of date",
          "Rarely — updates are disruptive and we defer them",
          "I'm not sure how updates are handled",
        ],
      },
      {
        id: "legacy_auth",
        pastaNote: "Legacy auth protocols bypass MFA and Conditional Access — a top Entra/M365 risk",
        text: "Do any of your systems or email applications use older connection methods that might bypass security checks?",
        hint: "Examples: older versions of Outlook, email apps that use basic protocols (IMAP/POP3), or software that doesn't support two-step login.",
        options: [
          "No — all software uses modern, secure login methods",
          "Yes — we have some older applications that connect this way",
          "Yes — several systems rely on these older methods",
          "I'm not sure what authentication methods our software uses",
        ],
      },
      {
        id: "admin_daily_use",
        pastaNote: "SEANCE Layer 1 — admin accounts used for daily tasks dramatically increase compromise blast radius",
        text: "Do the people with administrator access use their admin account for everyday tasks like email and browsing, or do they have a separate regular account for daily use?",
        hint: "Best practice is to have two accounts — a regular one for daily work and a separate admin account only used when making system changes.",
        options: [
          "Admins use a separate regular account for daily tasks",
          "Admins use their admin account for everything including daily work",
          "We only have one account per person regardless of access level",
          "I'm not sure",
        ],
      },
      {
        id: "firewall",
        pastaNote: "SEANCE Layer 4 — firewall is the primary network perimeter control; default configs are often insecure",
        text: "Does your business have a firewall protecting your network, and has it been configured beyond the factory defaults?",
        hint: "A firewall controls what traffic is allowed in and out of your network. Most routers include one but it needs to be properly configured.",
        options: [
          "Yes — we have a firewall and it has been reviewed and configured",
          "Yes — we have a firewall but it's running on default settings",
          "We rely on our internet provider's router with no additional configuration",
          "We are fully remote and don't have a traditional network to protect with a firewall",
          "I'm not sure if we have a firewall or what its settings are",
        ],
      },
      {
        id: "guest_wifi",
        pastaNote: "SEANCE Layer 4 — shared customer/business Wi-Fi allows lateral movement from guest devices",
        text: "If customers, visitors, or contractors use Wi-Fi at your premises, is it a separate network from the one your business devices use?",
        options: [
          "Yes — we have a separate guest network isolated from business systems",
          "No — customers and business devices share the same Wi-Fi network",
          "We don't offer Wi-Fi to customers or visitors",
          "I'm not sure",
        ],
      },
    ],
  },
  {
    id: "attack_paths",
    pastaStage: 6,
    pastaLabel: "Attack Modeling",
    pastaDesc: "Simulate how a real attacker would chain vulnerabilities together",
    attackTactics: ["TA0008 – Lateral Movement", "TA0010 – Exfiltration", "TA0040 – Impact"],
    color: "#5b8dd4",
    icon: "VI",
    title: "How Far Could an Attack Spread?",
    subtitle:
      "PASTA Stage 6 simulates realistic attack chains. Once inside, attackers move laterally (TA0008), steal data (TA0010), or deploy ransomware (TA0040). These questions map how far they could go.",
    questions: [
      {
        id: "network_segmentation",
        pastaNote: "Flat networks allow attackers to reach all systems after a single endpoint compromise",
        text: "Are different parts of your network or cloud environment separated from each other?",
        hint: "For example: can an attacker who compromises one employee's laptop automatically access your financial systems or server?",
        options: [
          "Yes — critical systems are isolated on separate network segments",
          "Partially — some separation exists, but it's not comprehensive",
          "No — all devices and systems are on the same flat network",
          "We're fully cloud-based with no on-site network to segment",
          "I'm not sure",
        ],
      },
      {
        id: "data_exfil_controls",
        pastaNote: "Absence of DLP controls enables TA0010 exfiltration via email, USB, and cloud sync",
        text: "Can employees copy or transfer sensitive company files to personal devices, personal cloud storage, or USB drives?",
        options: [
          "No — this is technically blocked and enforced by policy",
          "There is a policy against it, but it isn't technically enforced",
          "Yes — employees can freely move files wherever they want",
          "I'm not sure",
        ],
      },
      {
        id: "email_forwarding",
        pastaNote: "Hidden mailbox forwarding rules are a primary BEC persistence and exfiltration technique",
        text: "Do you know whether any business email accounts are automatically forwarding messages to an outside address?",
        hint: "After compromising an email account, attackers often set up hidden forwarding rules to silently receive copies of all future emails.",
        options: [
          "Yes — I've verified which forwarding rules exist and they're all authorized",
          "There are some forwarding rules but I'm not certain they're all approved",
          "No — I've never checked for forwarding rules",
          "I'm not sure how to check this",
        ],
      },
      {
        id: "backups",
        pastaNote: "Ransomware impact (TA0040) is catastrophic without tested, offline backups",
        text: "How does your business back up important files and data?",
        options: [
          "Automated daily backups stored separately from primary systems — regularly tested",
          "Regular backups exist but we haven't tested whether they can actually be restored",
          "Occasional, informal backups — no consistent schedule or testing",
          "We rely on cloud sync (e.g., OneDrive, Google Drive) as our only backup",
          "We don't have a formal backup process",
          "I'm not sure what our backup situation is",
        ],
      },
      {
        id: "cloud_sharing",
        pastaNote: "Unrestricted external sharing enables unauthorized data access without credential compromise",
        text: "Can your employees share files or folders from company storage directly with external people via a web link — without approval?",
        hint: "This is common in tools like SharePoint, OneDrive, Google Drive, and Dropbox.",
        options: [
          "No — external sharing is blocked at the system level",
          "Yes — but all external shares require manager approval or are automatically logged",
          "Yes — employees can share files externally without restrictions or oversight",
          "I'm not sure what our sharing settings allow",
        ],
      },
    ],
  },
  {
    id: "risk_impact",
    pastaStage: 7,
    pastaLabel: "Risk & Impact Analysis",
    pastaDesc: "Quantify business consequences and your ability to detect and recover",
    attackTactics: ["TA0005 – Defense Evasion", "Detection Gaps", "Incident Response"],
    color: "#60b06e",
    icon: "VII",
    title: "Business Risk & Recovery Capability",
    subtitle:
      "PASTA Stage 7 translates technical threats into business impact. Attackers exploit poor visibility (TA0005) to stay hidden for weeks. This section identifies your detection gaps and real-world resilience.",
    questions: [
      {
        id: "logging",
        pastaNote: "Login audit logs are required to detect TA0001, TA0006, and lateral movement post-incident",
        text: "Does your business log or record who logs into systems, from where, and when?",
        hint: "Login logs let you trace what happened during a breach — without them, you may never know the full extent of a compromise.",
        options: [
          "Yes — login logs are collected and reviewed regularly",
          "Yes — logs are collected but rarely if ever reviewed",
          "No — we don't have login logging in place",
          "I'm not sure",
        ],
      },
      {
        id: "anomaly_alerts",
        pastaNote: "Absence of behavioral alerts allows attackers to operate undetected for an average of 197 days",
        text: "Would you automatically receive an alert if someone logged into a business account from an unusual country, device, or at 3am?",
        options: [
          "Yes — we have alerts configured for suspicious or unusual logins",
          "Possibly — our system might have this but I'm unsure if it's configured",
          "No — we would have no automatic warning",
          "I'm not sure",
        ],
      },
      {
        id: "incident_history",
        pastaNote: "Prior incidents indicate the organization is already in attacker databases as a viable target",
        text: "Has your business ever experienced a cyberattack, data breach, or suspicious security event?",
        options: [
          "Yes — it caused significant operational or financial damage",
          "Yes — we caught it early and contained it",
          "We suspected something happened but were never certain",
          "No — not that we know of",
        ],
      },
      {
        id: "incident_response",
        pastaNote: "Absence of IR planning multiplies financial impact and recovery time by 2-3x",
        text: "If you discovered an active cyberattack in your systems right now, do you have a plan for what to do?",
        options: [
          "Yes — we have a written incident response plan and have practiced it",
          "Somewhat — we know who to call but haven't formalized the steps",
          "No — we would figure it out as the situation unfolded",
          "I'm not sure who would even be responsible for handling it",
        ],
      },
      {
        id: "breach_cost",
        pastaNote: "Financial impact tolerance determines risk threshold for Gordon-Loeb economic modeling",
        text: "How much financial loss could your business realistically absorb from a cyberattack before it threatened your survival?",
        hint: "This helps calibrate which threat scenarios represent existential risk versus recoverable setbacks.",
        options: [
          "Less than $10,000 — even a small incident could be catastrophic",
          "$10,000 – $50,000 — significant but we might survive",
          "$50,000 – $250,000 — painful but recoverable",
          "More than $250,000 — we have financial resilience",
          "We've never thought about this",
        ],
      },
      {
        id: "power_resilience",
        pastaNote: "SEANCE Layer 6 — power outages without UPS cause data loss and corrupt systems",
        text: "Does your business have any protection against sudden power outages — such as an uninterruptible power supply (UPS) for critical equipment?",
        hint: "A UPS is a battery backup that keeps computers and servers running long enough to save data and shut down safely if power is lost.",
        options: [
          "Yes — critical equipment has UPS protection",
          "No — a power outage would immediately cut off all equipment",
          "We are fully cloud-based — power outages only affect our internet connection",
          "I'm not sure",
        ],
      },
    ],
  },
];

// ─── COMPONENTS ───────────────────────────────────────────────────────────────

const PastaStageMap = ({ current }) => (
  <div style={{ display: "flex", alignItems: "stretch", gap: 0, marginBottom: 36 }}>
    {SECTIONS.map((s, i) => {
      const state = i < current ? "done" : i === current ? "active" : "future";
      return (
        <div key={s.id} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
          <div style={{
            width: "100%", height: 4, borderRadius: 2,
            background: state === "done" ? s.color : state === "active" ? s.color : "#1e2832",
            opacity: state === "future" ? 0.3 : 1,
            transition: "all 0.4s",
          }} />
          <div title={`Stage ${s.pastaStage}: ${s.pastaLabel}`} style={{
            width: 22, height: 22, borderRadius: "50%", display: "flex", alignItems: "center",
            justifyContent: "center", fontSize: 9, fontFamily: "monospace", fontWeight: 700,
            background: state === "done" ? s.color : state === "active" ? s.color : "#1e2832",
            color: state === "active" || state === "done" ? "#0b1117" : "#2e4052",
            border: state === "active" ? `2px solid ${s.color}` : "2px solid transparent",
            boxShadow: state === "active" ? `0 0 12px ${s.color}55` : "none",
            transition: "all 0.4s", cursor: "default",
          }}>
            {s.icon}
          </div>
        </div>
      );
    })}
  </div>
);

const AttackBadge = ({ tactic }) => (
  <span style={{
    display: "inline-block", padding: "2px 8px", borderRadius: 3, marginRight: 6, marginBottom: 4,
    background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)",
    color: "#4a6278", fontSize: 10, fontFamily: "monospace", letterSpacing: "0.05em",
  }}>
    {tactic}
  </span>
);

const ChoiceBtn = ({ label, selected, onClick, multi }) => (
  <button onClick={onClick} style={{
    display: "flex", alignItems: "flex-start", gap: 14, width: "100%",
    textAlign: "left", padding: "14px 18px", borderRadius: 8, cursor: "pointer",
    border: selected ? "1.5px solid rgba(255,255,255,0.25)" : "1.5px solid #1a2530",
    background: selected ? "rgba(255,255,255,0.06)" : "rgba(255,255,255,0.015)",
    marginBottom: 7, transition: "all 0.15s ease",
  }}>
    <div style={{
      width: 20, height: 20, flexShrink: 0, marginTop: 1,
      borderRadius: multi ? 4 : "50%",
      border: selected ? "2px solid #c8922a" : "2px solid #2a3d50",
      background: selected ? "#c8922a" : "transparent",
      display: "flex", alignItems: "center", justifyContent: "center",
      transition: "all 0.15s",
    }}>
      {selected && (multi
        ? <span style={{ color: "#0b1117", fontSize: 11, fontWeight: 900, lineHeight: 1 }}>✓</span>
        : <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#0b1117" }} />
      )}
    </div>
    <span style={{ color: selected ? "#e8ddd0" : "#5a7a90", fontSize: 14.5, lineHeight: 1.55, fontFamily: "Georgia, serif" }}>
      {label}
    </span>
  </button>
);

const Question = ({ q, qi, accentColor, answer, onAnswer, onToggle }) => (
  <div style={{ marginBottom: 36, paddingBottom: 36, borderBottom: "1px solid #141e28" }}>
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 6 }}>
        <span style={{ color: accentColor, fontFamily: "monospace", fontSize: 12, fontWeight: 700, opacity: 0.8 }}>
          Q{qi + 1}
        </span>
        {q.pastaNote && (
          <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", fontStyle: "italic" }}>
            ↳ {q.pastaNote}
          </span>
        )}
      </div>
      <p style={{ color: "#c8c0b4", fontSize: 16, fontWeight: 600, fontFamily: "Georgia, serif", lineHeight: 1.5, margin: "0 0 6px" }}>
        {q.text}
      </p>
      {q.hint && (
        <p style={{ color: "#3a5568", fontSize: 13, fontStyle: "italic", margin: "0 0 10px", lineHeight: 1.5 }}>
          {q.hint}
        </p>
      )}
      {q.multi && (
        <p style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", margin: "0 0 10px", letterSpacing: "0.08em" }}>
          SELECT ALL THAT APPLY
        </p>
      )}
    </div>
    {q.options.map(opt => (
      <ChoiceBtn
        key={opt} label={opt} multi={!!q.multi}
        selected={q.multi ? (answer || []).includes(opt) : answer === opt}
        onClick={() => q.multi ? onToggle(q.id, opt) : onAnswer(q.id, opt)}
      />
    ))}
  </div>
);

// ─── THREAT FINDINGS DISPLAY ──────────────────────────────────────────────────

const SEVERITY_COLORS = {
  critical: "#e05c5c",
  high:     "#e8a020",
  medium:   "#5b8dd4",
  low:      "#60b06e",
};

const FindingCard = ({ finding }) => {
  const [expanded, setExpanded] = useState(false);
  const color = SEVERITY_COLORS[finding.severity] || "#5a7a90";
  return (
    <div style={{
      border: `1px solid ${color}30`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 8,
      marginBottom: 12,
      background: "rgba(255,255,255,0.015)",
      overflow: "hidden",
    }}>
      <button
        onClick={() => setExpanded(e => !e)}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", padding: "14px 18px", background: "transparent",
          border: "none", cursor: "pointer", textAlign: "left", gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12, flex: 1, minWidth: 0 }}>
          <span style={{
            flexShrink: 0, padding: "2px 8px", borderRadius: 4,
            background: color + "20", border: `1px solid ${color}40`,
            color: color, fontSize: 10, fontFamily: "monospace",
            fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.06em",
          }}>
            {finding.severity}
          </span>
          <span style={{ color: "#c8c0b4", fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif", lineHeight: 1.3 }}>
            {finding.name}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <span style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace" }}>
            {finding.attack_technique}
          </span>
          <span style={{ color: "#2e4458", fontSize: 12 }}>{expanded ? "▲" : "▼"}</span>
        </div>
      </button>

      {expanded && (
        <div style={{ padding: "0 18px 18px", borderTop: "1px solid #141e28" }}>
          <div style={{ paddingTop: 14, display: "flex", flexDirection: "column", gap: 14 }}>
            <div>
              <div style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace", marginBottom: 5, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Business Impact
              </div>
              <p style={{ color: "#8a9eb0", fontSize: 14, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: 0 }}>
                {finding.business_impact}
              </p>
            </div>
            <div>
              <div style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace", marginBottom: 5, textTransform: "uppercase", letterSpacing: "0.08em" }}>
                Recommendation
              </div>
              <p style={{ color: "#8a9eb0", fontSize: 14, fontFamily: "Georgia, serif", lineHeight: 1.6, margin: 0 }}>
                {finding.recommendation}
              </p>
            </div>
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
              <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace" }}>
                Tactic: <span style={{ color: "#4a6278" }}>{finding.attack_tactic}</span>
              </span>
              <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace" }}>
                PASTA: <span style={{ color: "#4a6278" }}>{finding.pasta_stage}</span>
              </span>
              {finding.likelihood && (
                <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace" }}>
                  Likelihood: <span style={{ color: "#4a6278" }}>{finding.likelihood}</span>
                </span>
              )}
            </div>
            {finding.references && finding.references.length > 0 && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {finding.references.map(ref => (
                  <a key={ref} href={ref} target="_blank" rel="noreferrer" style={{
                    color: "#2e4458", fontSize: 11, fontFamily: "monospace",
                    textDecoration: "underline", textDecorationColor: "#1e2e3e",
                  }}>
                    {ref.replace("https://", "")}
                  </a>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const ThreatReport = ({ threatModel }) => {
  const { summary, findings } = threatModel;
  const scoreColor =
    summary.overall_risk_score >= 70 ? "#e05c5c" :
    summary.overall_risk_score >= 40 ? "#e8a020" : "#60b06e";
  const buildReportHTML = () => {
    const severityColors = {
      critical: "#e05c5c",
      high: "#e8a020",
      medium: "#5b8dd4",
      low: "#60b06e",
    };

    const findingsHTML = findings.map(f => `
      <div class="finding" style="border-left: 4px solid ${severityColors[f.severity] || '#5a7a90'}; margin-bottom: 24px; padding: 16px 20px; background: #f9f9f9; border-radius: 4px;">
        <div style="display:flex; align-items:center; gap:12px; margin-bottom:10px;">
          <span style="background:${severityColors[f.severity]}22; border:1px solid ${severityColors[f.severity]}66; color:${severityColors[f.severity]}; padding:2px 10px; border-radius:4px; font-size:11px; font-weight:700; text-transform:uppercase; font-family:monospace;">
            ${f.severity}
          </span>
          <strong style="font-size:16px;">${f.name}</strong>
        </div>
        <p style="margin:0 0 6px; font-size:12px; color:#666; font-family:monospace;">${f.attack_tactic} · ${f.attack_technique}</p>
        <p style="margin:0 0 6px; font-size:12px; color:#666; font-family:monospace;">PASTA: ${f.pasta_stage} · Likelihood: ${f.likelihood}</p>
        <h4 style="margin:12px 0 4px; font-size:13px; color:#333;">Business Impact</h4>
        <p style="margin:0 0 12px; font-size:14px; line-height:1.6;">${f.business_impact}</p>
        <h4 style="margin:0 0 4px; font-size:13px; color:#333;">Recommendation</h4>
        <p style="margin:0 0 12px; font-size:14px; line-height:1.6;">${f.recommendation}</p>
        ${f.references && f.references.length > 0 ? `
          <h4 style="margin:0 0 4px; font-size:13px; color:#333;">References</h4>
          <ul style="margin:0; padding-left:18px;">
            ${f.references.map(r => `<li><a href="${r}" style="color:#5b8dd4; font-size:13px;">${r}</a></li>`).join("")}
          </ul>
        ` : ""}
      </div>
    `).join("");

    const html = `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8"/>
    <title>MicroSOC Threat Model Report</title>
    <style>
      body { font-family: Georgia, serif; max-width: 900px; margin: 40px auto; padding: 0 24px; color: #1a1a1a; }
      h1 { font-size: 28px; margin-bottom: 4px; }
      h2 { font-size: 20px; margin: 32px 0 12px; border-bottom: 2px solid #eee; padding-bottom: 8px; }
      .meta { color: #666; font-size: 13px; font-family: monospace; margin-bottom: 32px; }
      .scores { display: flex; gap: 20px; margin-bottom: 32px; flex-wrap: wrap; }
      .score-box { padding: 12px 20px; border-radius: 8px; text-align: center; border: 1px solid #ddd; }
      .score-box .num { font-size: 28px; font-weight: 700; font-family: monospace; }
      .score-box .label { font-size: 11px; font-family: monospace; text-transform: uppercase; color: #666; }
    </style>
  </head>
  <body>
    <h1>MicroSOC Threat Model Report</h1>
    <p class="meta">Generated: ${new Date().toLocaleString()} · PASTA + MITRE ATT&CK Framework</p>

    <h2>Risk Summary</h2>
    <div class="scores">
      <div class="score-box">
        <div class="num" style="color:${summary.overall_risk_score >= 70 ? '#e05c5c' : summary.overall_risk_score >= 40 ? '#e8a020' : '#60b06e'}">
          ${summary.overall_risk_score}
        </div>
        <div class="label">Risk Score / 100</div>
      </div>
      <div class="score-box">
        <div class="num" style="color:#e05c5c">${summary.critical}</div>
        <div class="label">Critical</div>
      </div>
      <div class="score-box">
        <div class="num" style="color:#e8a020">${summary.high}</div>
        <div class="label">High</div>
      </div>
      <div class="score-box">
        <div class="num" style="color:#5b8dd4">${summary.medium || 0}</div>
        <div class="label">Medium</div>
      </div>
    </div>

    <h2>Findings (${findings.length})</h2>
    ${findingsHTML}

    <p style="margin-top:48px; font-size:12px; color:#999; font-family:monospace;">
      Generated by MicroSOC · PASTA + MITRE ATT&CK · All responses processed locally
    </p>
  </body>
  </html>`;

    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `microsoc-threat-report-${new Date().toISOString().split("T")[0]}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadHTML = () => {
    const html = buildReportHTML();
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `microsoc-threat-report-${new Date().toISOString().split("T")[0]}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPDF = () => {
    const html = buildReportHTML();
    const win = window.open("", "_blank");
    win.document.write(html);
    win.document.close();
    win.focus();
    setTimeout(() => { win.print(); win.close(); }, 500);
  };

  return (
    <div style={{ marginTop: 36, paddingTop: 36, borderTop: "1px solid #141e28" }}>
      <div style={{ marginBottom: 28 }}>
        <div style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", marginBottom: 8, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Threat Model Results
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 20, flexWrap: "wrap" }}>
          <div style={{ textAlign: "center" }}>
            <div style={{ fontSize: 42, fontWeight: 700, color: scoreColor, fontFamily: "monospace", lineHeight: 1 }}>
              {summary.overall_risk_score}
            </div>
            <div style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace", marginTop: 4 }}>RISK SCORE / 100</div>
          </div>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {summary.critical > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: "#e05c5c15", border: "1px solid #e05c5c30", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: "#e05c5c", fontFamily: "monospace" }}>{summary.critical}</div>
                <div style={{ fontSize: 10, color: "#e05c5c", fontFamily: "monospace" }}>CRITICAL</div>
              </div>
            )}
            {summary.high > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: "#e8a02015", border: "1px solid #e8a02030", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: "#e8a020", fontFamily: "monospace" }}>{summary.high}</div>
                <div style={{ fontSize: 10, color: "#e8a020", fontFamily: "monospace" }}>HIGH</div>
              </div>
            )}
            {summary.medium > 0 && (
              <div style={{ padding: "8px 14px", borderRadius: 8, background: "#5b8dd415", border: "1px solid #5b8dd430", textAlign: "center" }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: "#5b8dd4", fontFamily: "monospace" }}>{summary.medium}</div>
                <div style={{ fontSize: 10, color: "#5b8dd4", fontFamily: "monospace" }}>MEDIUM</div>
              </div>
            )}
          </div>
        </div>
      </div>

      <div style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace", marginBottom: 12, letterSpacing: "0.08em", textTransform: "uppercase" }}>
        {findings.length} Finding{findings.length !== 1 ? "s" : ""} — click any row to expand
      </div>
      {findings.map(f => <FindingCard key={f.id} finding={f} />)}
      <div style={{ display: "flex", gap: 12, marginTop: 28, paddingTop: 24, borderTop: "1px solid #141e28" }}>
        <button
          onClick={downloadHTML}
          style={{
            padding: "10px 22px", borderRadius: 8, border: "1.5px solid #5b8dd4",
            background: "transparent", color: "#5b8dd4", cursor: "pointer",
            fontSize: 14, fontFamily: "Georgia, serif",
          }}>
          ↓ Download HTML Report
        </button>
        <button
          onClick={downloadPDF}
          style={{
            padding: "10px 22px", borderRadius: 8, border: "none",
            background: "#5b8dd4", color: "#0b1117", cursor: "pointer",
            fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif",
          }}>
          ↓ Save as PDF
        </button>
      </div>
    </div>
  );
};

// ─── SUMMARY VIEW ─────────────────────────────────────────────────────────────

const SummaryView = ({ answers, threatModel, onRestart }) => {
  const all = SECTIONS.flatMap(s => s.questions.map(q => ({ ...q, sec: s })));
  const answered = all.filter(q => {
    const a = answers[q.id];
    return a !== undefined && (Array.isArray(a) ? a.length > 0 : true);
  });
  return (
    <div>
      <div style={{ textAlign: "center", padding: "36px 0 40px", borderBottom: "1px solid #141e28", marginBottom: 36 }}>
        <div style={{
          width: 60, height: 60, borderRadius: "50%", margin: "0 auto 16px",
          background: "rgba(200,146,42,0.1)", border: "2px solid #c8922a",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 24, color: "#c8922a",
        }}>✓</div>
        <h2 style={{ color: "#e8ddd0", fontFamily: "Georgia, serif", fontSize: 24, margin: "0 0 10px" }}>
          Risk Assessment Complete
        </h2>
        <p style={{ color: "#4a6278", margin: 0 }}>
          {answered.length} of {all.length} questions answered — threat model generated below.
        </p>
      </div>

      {/* ── Threat report (shown when backend returns findings) ── */}
      {threatModel ? (
        <ThreatReport threatModel={threatModel} />
      ) : (
        <div style={{
          padding: "24px", borderRadius: 8, border: "1px dashed #1e2e3e",
          textAlign: "center", marginBottom: 28,
        }}>
          <p style={{ color: "#2e4458", fontFamily: "monospace", fontSize: 13, margin: 0 }}>
            No threat model data — make sure the backend is running and reachable at{" "}
            <code style={{ color: "#4a6278" }}>http://localhost:5000/api/survey</code>
          </p>
        </div>
      )}

      {/* ── Raw answers summary ── */}
      <div style={{ marginTop: 36, paddingTop: 36, borderTop: "1px solid #141e28" }}>
        <div style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", marginBottom: 20, letterSpacing: "0.1em", textTransform: "uppercase" }}>
          Survey Responses
        </div>
        {SECTIONS.map(sec => {
          const sq = sec.questions.filter(q => {
            const a = answers[q.id];
            return a !== undefined && (Array.isArray(a) ? a.length > 0 : true);
          });
          if (!sq.length) return null;
          return (
            <div key={sec.id} style={{ marginBottom: 28 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 14 }}>
                <div style={{
                  width: 30, height: 30, borderRadius: "50%", background: sec.color + "20",
                  border: `1.5px solid ${sec.color}`, display: "flex", alignItems: "center",
                  justifyContent: "center", fontSize: 9, fontFamily: "monospace", fontWeight: 700, color: sec.color,
                }}>{sec.icon}</div>
                <div>
                  <span style={{ color: "#4a6278", fontSize: 11, fontFamily: "monospace", marginRight: 8 }}>
                    STAGE {sec.pastaStage}
                  </span>
                  <span style={{ color: "#8a9eb0", fontSize: 14, fontFamily: "Georgia, serif", fontWeight: 700 }}>
                    {sec.title}
                  </span>
                </div>
              </div>
              {sq.map(q => (
                <div key={q.id} style={{
                  background: "#0e1822", border: "1px solid #141e28", borderRadius: 8,
                  padding: "12px 16px", marginBottom: 8,
                }}>
                  <div style={{ color: "#2e4458", fontSize: 12, fontFamily: "monospace", marginBottom: 5 }}>{q.text}</div>
                  <div style={{ color: sec.color, fontSize: 14, fontFamily: "Georgia, serif", fontWeight: 700 }}>
                    {Array.isArray(answers[q.id]) ? answers[q.id].join(" · ") : answers[q.id]}
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </div>

      <div style={{ paddingTop: 24, borderTop: "1px solid #141e28" }}>
        <button onClick={onRestart} style={{
          padding: "11px 26px", borderRadius: 8, border: "1.5px solid #1e2e3e",
          background: "transparent", color: "#4a6278", cursor: "pointer",
          fontSize: 14, fontFamily: "Georgia, serif",
        }}>
          ← Start Over
        </button>
      </div>
    </div>
  );
};

// ─── MAIN ─────────────────────────────────────────────────────────────────────

export default function App() {
  const [sIdx, setSIdx] = useState(0);
  const [answers, setAnswers] = useState({});
  const [done, setDone] = useState(false);
  const [visible, setVisible] = useState(false);

  // ── NEW: API state ──────────────────────────────────────────────────────────
  const [threatModel, setThreatModel] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  // ───────────────────────────────────────────────────────────────────────────

  useEffect(() => { setTimeout(() => setVisible(true), 60); }, []);

  const sec = SECTIONS[sIdx];
  const isLast = sIdx === SECTIONS.length - 1;

  const onAnswer = (id, val) => setAnswers(p => ({ ...p, [id]: val }));
  const onToggle = (id, val) => setAnswers(p => {
    const cur = p[id] || [];
    return { ...p, [id]: cur.includes(val) ? cur.filter(v => v !== val) : [...cur, val] };
  });

  const answeredCount = sec.questions.filter(q => {
    const a = answers[q.id];
    return a !== undefined && (Array.isArray(a) ? a.length > 0 : true);
  }).length;
  const canAdvance = answeredCount === sec.questions.length;

  // ── NEW: async complete handler ─────────────────────────────────────────────
  const handleComplete = async () => {
    if (!canAdvance) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("http://localhost:5000/api/survey", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ responses: answers }),
      });
      if (!res.ok) throw new Error(`Server responded with status ${res.status}`);
      const data = await res.json();
      setThreatModel(data);
      setDone(true);
    } catch (err) {
      setError("Could not reach the analysis server. Make sure the backend is running on port 5000.");
    } finally {
      setLoading(false);
    }
  };
  // ───────────────────────────────────────────────────────────────────────────

  return (
    <div style={{
      minHeight: "100vh",
      background: "#0b1117",
      backgroundImage: `
        radial-gradient(ellipse 60% 50% at 15% 0%, rgba(200,146,42,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 100%, rgba(91,141,212,0.04) 0%, transparent 60%)
      `,
      fontFamily: "Georgia, serif",
      padding: "48px 20px 100px",
      opacity: visible ? 1 : 0,
      transform: visible ? "none" : "translateY(8px)",
      transition: "opacity 0.5s, transform 0.5s",
    }}>
      <div style={{ maxWidth: 900, margin: "0 auto" }}>

        {/* Header */}
        <div style={{ marginBottom: 52 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 22 }}>
            <div style={{
              width: 8, height: 8, borderRadius: "50%", background: "#c8922a",
              boxShadow: "0 0 10px #c8922a88",
            }} />
            <span style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace", letterSpacing: "0.16em", textTransform: "uppercase" }}>
              MicroSOC · Business Risk Assessment
            </span>
          </div>
          <h1 style={{ fontSize: 38, color: "#e8ddd0", margin: "0 0 4px", lineHeight: 1.1, fontWeight: 700, letterSpacing: "-0.5px" }}>
            Cyber Risk Survey
          </h1>
          <p style={{ color: "#3a5568", fontSize: 16, margin: "8px 0 0", lineHeight: 1.7, maxWidth: 800 }}>
            A <strong style={{ color: "#5a7a90" }}>PASTA + MITRE ATT&CK</strong> assessment that translates your business environment into a prioritized risk profile. No technical knowledge required.
          </p>
        </div>

        {/* Card */}
        <div style={{
          background: "#0e1822",
          border: "1px solid #141e28",
          borderRadius: 16,
          padding: "40px 44px",
          boxShadow: "0 8px 60px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.03)",
        }}>
          {!done ? (
            <>
              <PastaStageMap current={sIdx} />

              {/* Section header */}
              <div style={{ marginBottom: 32 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 16, marginBottom: 14 }}>
                  <div style={{
                    width: 44, height: 44, borderRadius: 10, flexShrink: 0,
                    background: sec.color + "15",
                    border: `1.5px solid ${sec.color}40`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 10, fontFamily: "monospace", fontWeight: 900, color: sec.color,
                  }}>
                    {sec.icon}
                  </div>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 3 }}>
                      <span style={{ color: sec.color, fontFamily: "monospace", fontSize: 10, fontWeight: 700, letterSpacing: "0.1em" }}>
                        PASTA STAGE {sec.pastaStage}
                      </span>
                      <span style={{ color: "#1e2e3e", fontSize: 10, fontFamily: "monospace" }}>·</span>
                      <span style={{ color: "#2e4458", fontSize: 10, fontFamily: "monospace" }}>{sec.pastaLabel}</span>
                    </div>
                    <h2 style={{ color: "#e8ddd0", fontSize: 21, fontWeight: 700, margin: 0, lineHeight: 1.2 }}>
                      {sec.title}
                    </h2>
                  </div>
                </div>

                <p style={{ color: "#3a5568", fontSize: 14, lineHeight: 1.7, margin: "0 0 12px", paddingLeft: 60 }}>
                  {sec.subtitle}
                </p>

                <div style={{ paddingLeft: 60 }}>
                  {sec.attackTactics.map(t => <AttackBadge key={t} tactic={t} />)}
                </div>
              </div>

              <div style={{ height: 1, background: "#141e28", margin: "0 0 32px" }} />

              {/* Questions */}
              {sec.questions.map((q, qi) => (
                <Question
                  key={q.id} q={q} qi={qi}
                  accentColor={sec.color}
                  answer={answers[q.id]}
                  onAnswer={onAnswer}
                  onToggle={onToggle}
                />
              ))}

              {/* Nav */}
              <div style={{
                display: "flex", alignItems: "center", justifyContent: "space-between",
                paddingTop: 24, borderTop: "1px solid #141e28",
              }}>
                <button
                  onClick={() => sIdx > 0 && setSIdx(s => s - 1)}
                  disabled={sIdx === 0}
                  style={{
                    padding: "11px 22px", borderRadius: 8, border: "1.5px solid #141e28",
                    background: "transparent", color: sIdx === 0 ? "#1a2a38" : "#3a5568",
                    cursor: sIdx === 0 ? "not-allowed" : "pointer", fontSize: 14, fontFamily: "Georgia, serif",
                  }}>
                  ← Back
                </button>

                <div style={{ textAlign: "center" }}>
                  <div style={{ color: "#2e4458", fontSize: 11, fontFamily: "monospace" }}>
                    {answeredCount}/{sec.questions.length} answered
                  </div>
                  {!canAdvance && answeredCount > 0 && (
                    <div style={{ color: sec.color + "aa", fontSize: 11, fontFamily: "monospace", marginTop: 3 }}>
                      Answer remaining questions to continue
                    </div>
                  )}
                  {/* ── NEW: error message ── */}
                  {error && isLast && (
                    <div style={{ color: "#e05c5c", fontSize: 11, fontFamily: "monospace", marginTop: 6, maxWidth: 280 }}>
                      ⚠ {error}
                    </div>
                  )}
                </div>

                {/* ── UPDATED: Complete button uses handleComplete ── */}
                <button
                  onClick={() => { if (!canAdvance) return; isLast ? handleComplete() : setSIdx(s => s + 1); }}
                  disabled={!canAdvance || loading}
                  style={{
                    padding: "11px 28px", borderRadius: 8, border: "none",
                    background: canAdvance && !loading ? sec.color : "#141e28",
                    color: canAdvance && !loading ? "#0b1117" : "#1e2e3e",
                    cursor: canAdvance && !loading ? "pointer" : "not-allowed",
                    fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif",
                    boxShadow: canAdvance && !loading ? `0 2px 16px ${sec.color}44` : "none",
                    transition: "all 0.2s",
                  }}>
                  {/* ── UPDATED: loading state label ── */}
                  {isLast ? (loading ? "Analyzing…" : "Complete Assessment →") : "Next Stage →"}
                </button>
              </div>
            </>
          ) : (
            // ── UPDATED: passes threatModel + clears it on restart ──
            <SummaryView
              answers={answers}
              threatModel={threatModel}
              onRestart={() => { setDone(false); setSIdx(0); setAnswers({}); setThreatModel(null); setError(null); }}
            />
          )}
        </div>

        <p style={{ textAlign: "center", color: "#1a2a38", fontSize: 11, marginTop: 20, fontFamily: "monospace" }}>
          All responses processed locally · No data transmitted externally
        </p>
      </div>
    </div>
  );
}
