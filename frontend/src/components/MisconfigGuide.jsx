import { useState, useMemo } from "react";

// ─── Design tokens — exact match with Survey.jsx ──────────────────────────────
const BG       = "#0b1117";
const CARD     = "#0e1822";
const BORDER   = "#141e28";
const BORDER2  = "#1e2e3e";
const GOLD     = "#c8922a";
const TEXT_PRI = "#e8ddd0";
const TEXT_SEC = "#8a9eb0";
const TEXT_DIM = "#3a5568";
const TEXT_MUT = "#2e4458";
const CRIT     = "#e05c5c";
const HIGH_C   = "#e8a020";
const MED_C    = "#5b8dd4";
const LOW_C    = "#60b06e";

const SEV_COLORS  = { critical: CRIT, high: HIGH_C, medium: MED_C, low: LOW_C };

// ─── PASTA stage palette — matches Survey.jsx section colors ──────────────────
const STAGE_META = {
  "Stage 2": { label: "Technical Scope",         color: "#a87fc2", icon: "II"  },
  "Stage 3": { label: "Application/Process Decompisition",     color: "#4ea8a0", icon: "III" },
  "Stage 4": { label: "Threat Analysis",         color: "#e05c5c", icon: "IV"  },
  "Stage 5": { label: "Vulnerability Analysis",  color: "#e8a020", icon: "V"   },
  "Stage 6": { label: "Attack Modeling",         color: "#5b8dd4", icon: "VI"  },
  "Stage 7": { label: "Risk & Impact Analysis",  color: "#60b06e", icon: "VII" },
};

// ─── Full 27-rule catalog (authoritative source: backend/threat_model/rules.py)
const MISCONFIG_CATALOG = [
  { id: "bec_wire_fraud", name: "Business Email Compromise \u2014 Wire Transfer Fraud", pasta_stage: "Stage 4: Threat Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1566 Phishing / T1534 Internal Spearphishing", severity: "critical", likelihood: "high", business_impact: "Attacker impersonates an executive or vendor over email and tricks an employee into wiring funds to a fraudulent account. Average SME loss exceeds $50,000 per incident with minimal recovery.", recommendation: "Require out-of-band verification (phone call to a known number, video conference, etc...) for ALL payment changes or wire transfers, regardless of how urgent the email appears. No exceptions.", references: ["https://www.ic3.gov/Media/Y2023/PSA230609"] },
  { id: "ransomware_no_backup", name: "Ransomware with No Recovery Path", pasta_stage: "Stage 6: Attack Modeling", attack_tactic: "TA0040 Impact", attack_technique: "T1486 Data Encrypted for Impact", severity: "critical", likelihood: "medium", business_impact: "Ransomware encrypts all business files and systems. Without tested offline backups, the only options are paying the ransom or permanent data loss. For businesses with low downtime tolerance, this is existential.", recommendation: "Implement the 3-2-1 backup rule: 3 copies, 2 different media types, 1 stored offline or air-gapped. Test restoration monthly. Cloud sync alone (OneDrive, Google Drive) is NOT a backup \u2014 ransomware can encrypt synced files too.", references: ["https://www.cisa.gov/stopransomware"] },
  { id: "credential_stuffing_no_mfa", name: "Credential Stuffing \u2014 Account Takeover", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0006 Credential Access", attack_technique: "T1110.004 Credential Stuffing", severity: "high", likelihood: "high", business_impact: "Attackers use leaked password databases to automatically try credentials against your email and cloud accounts. Without MFA, a single reused password from any data breach gives full account access.", recommendation: "Enable MFA on all accounts immediately \u2014 prioritize email, admin accounts, and financial systems. Use an authenticator app (not SMS where possible). Deploy a password manager so employees stop reusing passwords.", references: ["https://attack.mitre.org/techniques/T1110/004/"] },
  { id: "ghost_access_stale_accounts", name: "Unauthorized Access via Stale Accounts", pasta_stage: "Stage 3: Application Decomposition", attack_tactic: "TA0001 Initial Access", attack_technique: "T1078 Valid Accounts", severity: "high", likelihood: "medium", business_impact: "Former employees or contractors retain active credentials after leaving. A disgruntled ex-employee or an attacker who purchases stolen credentials can silently access systems for months without detection.", recommendation: "Create an offboarding checklist that disables ALL accounts on the last day of employment. Run a quarterly audit of active accounts against current employee/contractor roster. Automate where possible via your identity provider.", references: ["https://attack.mitre.org/techniques/T1078/"] },
  { id: "hidden_email_forwarding", name: "Silent Email Exfiltration via Forwarding Rules", pasta_stage: "Stage 6: Attack Modeling", attack_tactic: "TA0010 Exfiltration", attack_technique: "T1114.003 Email Forwarding Rule", severity: "high", likelihood: "medium", business_impact: "After compromising an email account, attackers plant hidden forwarding rules that silently copy every inbound and outbound email to an external address. The account owner sees nothing abnormal. Sensitive data leaks continuously.", recommendation: "Audit all mailbox forwarding rules now. In Microsoft 365: Exchange Admin Center \u2192 Mail Flow \u2192 Rules. Disable automatic external forwarding at the tenant level. Set an alert for any new forwarding rules being created.", references: ["https://attack.mitre.org/techniques/T1114/003/"] },
  { id: "uncontrolled_vendor_access", name: "Supply Chain / Vendor Compromise", pasta_stage: "Stage 3: Application Decomposition", attack_tactic: "TA0001 Initial Access", attack_technique: "T1199 Trusted Relationship", severity: "high", likelihood: "medium", business_impact: "Vendors with shared or uncontrolled access become a secondary attack surface. An attacker who compromises your IT provider or accountant gains direct access to your systems under trusted credentials.", recommendation: "Create dedicated, named accounts for each vendor with the minimum access required. Never share employee credentials with vendors. Review and revoke vendor access after each engagement ends.", references: ["https://attack.mitre.org/techniques/T1199/"] },
  { id: "no_detection_capability", name: "No Visibility \u2014 Breach Goes Undetected", pasta_stage: "Stage 7: Risk & Impact Analysis", attack_tactic: "TA0005 Defense Evasion", attack_technique: "T1562 Impair Defenses", severity: "medium", likelihood: "high", business_impact: "Without login logging or anomaly alerts, attackers operate undetected for an average of 197 days. The longer they're in, the more data they steal and the more damage they can cause before discovery.", recommendation: "Enable login audit logging in your identity platform (Microsoft Entra or Google Workspace). Configure alerts for logins from new countries, impossible travel, or outside business hours. Review logs monthly at minimum.", references: ["https://learn.microsoft.com/en-us/entra/identity/monitoring-health/"] },
  { id: "iot_default_credentials", name: "IoT Device Compromise via Default Credentials", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1078.001 Valid Accounts: Default Accounts", severity: "high", likelihood: "high", business_impact: "Printers, cameras, smart TVs, and other internet-connected devices shipped with default passwords are trivially compromised. Once inside, attackers use the device as a foothold to move laterally across the network. CISA has documented cases where printers with default credentials allowed attackers to compromise entire Active Directory environments.", recommendation: "Immediately change default passwords on ALL network-connected devices. Maintain an inventory of every IoT device. Isolate IoT devices on a separate network segment away from business systems. Enable automatic firmware updates where available.", references: ["https://www.cisa.gov/news-events/news/2023/09/28/cisa-shares-lessons-learned-printer-compromise", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"] },
  { id: "physical_access_risk", name: "Unauthorized Physical Access to Systems", pasta_stage: "Stage 4: Threat Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1052 Exfiltration Over Physical Medium / T1091 Replication Through Removable Media", severity: "medium", likelihood: "medium", business_impact: "An open office environment allows any visitor \u2014 delivery drivers, contractors, former employees \u2014 to physically access computers, plug in a USB device, photograph screens, or steal hardware. Physical access bypasses every digital security control you have in place.", recommendation: "Lock server rooms and IT equipment at all times. Require employees to lock screens when leaving desks. Escort all non-employee visitors. Log visitor entry and exit. Consider cable locks for laptops in shared spaces.", references: ["https://www.cisa.gov/topics/physical-security/insider-threat-mitigation"] },
  { id: "admin_daily_use_risk", name: "Elevated Blast Radius from Admin Account Misuse", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0004 Privilege Escalation", attack_technique: "T1078.003 Valid Accounts: Local Accounts", severity: "high", likelihood: "medium", business_impact: "When administrators use their privileged account for everyday tasks like browsing and email, a single phishing click can give attackers immediate admin-level access to the entire environment. CISA identifies this as one of the top ten systemic misconfigurations found across assessed networks.", recommendation: "Admins must have two separate accounts: a standard account for daily work and a dedicated admin account used only for administrative tasks. Never browse the web or read email while logged into an admin account. This is called Privileged Access Workstation (PAW) hygiene.", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-278a"] },
  { id: "shared_guest_wifi", name: "Lateral Movement via Unsegmented Guest Wi-Fi", pasta_stage: "Stage 6: Attack Modeling", attack_tactic: "TA0008 Lateral Movement", attack_technique: "T1016 System Network Configuration Discovery / T1049 System Network Connections Discovery", severity: "medium", likelihood: "medium", business_impact: "When customers or visitors share the same Wi-Fi network as business devices, a compromised or malicious visitor device can scan and attack internal systems directly. This completely negates firewall protections designed to block external attackers, since the threat is already inside the network perimeter.", recommendation: "Create a separate, isolated guest Wi-Fi network with no access to business systems. Most modern routers support this natively. Business devices should be on a completely separate SSID. Verify the networks cannot communicate with each other.", references: ["https://www.cisa.gov/news-events/news/understanding-firewalls-home-and-small-office-use"] },
  { id: "no_cyber_insurance", name: "No Financial Safety Net \u2014 Uninsured Breach Exposure", pasta_stage: "Stage 7: Risk & Impact Analysis", attack_tactic: "TA0040 Impact", attack_technique: "T1486 Data Encrypted for Impact", severity: "medium", likelihood: "high", business_impact: "Without cyber insurance, the full cost of a breach \u2014 legal fees, customer notification, regulatory fines, system restoration, and lost revenue \u2014 falls entirely on the business. For SMEs with low financial resilience, a single incident can be fatal. Only 28% of small business owners in the US report having cyber insurance.", recommendation: "Obtain a cyber liability insurance policy. At minimum, look for coverage that includes: breach response costs, business interruption, ransomware payments, and regulatory defense. Premiums for small businesses typically range from $500\u2013$3,000/year depending on industry and revenue.", references: ["https://www.ftc.gov/business-guidance/small-businesses/cybersecurity/cyber-insurance"] },
  { id: "pii_no_notification_plan", name: "Regulatory Breach Notification Failure \u2014 Customer PII at Risk", pasta_stage: "Stage 7: Risk & Impact Analysis", attack_tactic: "TA0010 Exfiltration", attack_technique: "T1530 Data from Cloud Storage", severity: "high", likelihood: "medium", business_impact: "Businesses that collect customer PII are legally required to notify affected individuals and regulators within strict timeframes after a breach \u2014 as short as 72 hours under GDPR or 30 days under many US state laws. Failure to notify compounds the original breach with regulatory fines, class action exposure, and reputational damage that often exceeds the direct cost of the incident.", recommendation: "Document a breach notification procedure today \u2014 before an incident occurs. Identify: which states and regulations apply to your customers, who internally is responsible for making notification decisions, and which law firm or attorney you would call. Review state breach notification laws at ncsl.org.", references: ["https://csrc.nist.gov/Topics/Security-and-Privacy/risk-management/threats/ransomware"] },
  { id: "unencrypted_data_at_rest", name: "Unencrypted Data \u2014 Readable on Stolen or Lost Devices", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0006 Credential Access", attack_technique: "T1552.001 Credentials In Files", severity: "high", likelihood: "medium", business_impact: "A stolen or lost laptop without full disk encryption gives an attacker complete access to every file, email, saved password, and credential on that device \u2014 no password required. They simply boot from a USB drive or remove the disk. For businesses handling customer PII or financial data, this triggers mandatory breach notification regardless of whether the data was actually accessed.", recommendation: "Enable BitLocker on all Windows devices and FileVault on all Macs. Both are built into the operating system at no additional cost. For Microsoft 365 environments, Intune can enforce and verify encryption across all managed devices. Encryption is the single most effective control against physical device loss.", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"] },
  { id: "ransomware_double_extortion", name: "Ransomware \u2014 Double Extortion via Data Theft Before Encryption", pasta_stage: "Stage 6: Attack Modeling", attack_tactic: "TA0040 Impact", attack_technique: "T1486 Data Encrypted for Impact / T1537 Transfer Data to Cloud Account", severity: "critical", likelihood: "medium", business_impact: "Modern ransomware groups no longer just encrypt files \u2014 they first steal copies of sensitive data, then threaten to publish it publicly if the ransom is not paid. This double extortion eliminates the fallback of restoring from backups, since the attacker can still cause harm by leaking customer data, financial records, or business secrets.", recommendation: "Backups alone are no longer sufficient protection against ransomware. Combine tested backups with data classification (know what's sensitive), Data Loss Prevention (DLP) controls to detect bulk data movement before exfiltration, and network monitoring to detect unusual outbound transfers. Review NIST IR 8374 Ransomware Risk Management profile for a complete control checklist.", references: ["https://csrc.nist.gov/pubs/ir/8374/final"] },
  { id: "tech_support_impersonation", name: "Tech Support Impersonation Fraud", pasta_stage: "Stage 4: Threat Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1566.004 Phishing: Spearphishing Voice", severity: "high", likelihood: "medium", business_impact: "Attackers call employees posing as Microsoft support, IT vendors, or the business owner\u2019s IT provider and convince them to install remote access tools or reveal credentials. The FBI IC3 2023 report recorded tech support scams as the third-costliest cybercrime category with over $924 million in reported losses. SMEs with informal IT arrangements are disproportionately targeted.", recommendation: "Establish a written IT contact protocol: employees should have one verified phone number and email for IT support, and should never act on unsolicited calls claiming to be IT or Microsoft. Legitimate IT providers never cold-call to install software. Run a tabletop exercise simulating a tech support call.", references: ["https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"] },
  { id: "end_of_life_software", name: "Exploitation of End-of-Life Software", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1190 Exploit Public-Facing Application / T1203 Exploitation for Client Execution", severity: "high", likelihood: "high", business_impact: "End-of-life software no longer receives security patches, meaning every newly discovered vulnerability is permanently exploitable. NIST recommends maintaining hardware and software inventories as a foundational ransomware prevention step because unpatched systems are among the most common ransomware entry points.", recommendation: "Immediately inventory all software and identify end-of-life versions. Windows 10 reaches end-of-life in October 2025 \u2014 plan upgrades now. If legacy software cannot be replaced, isolate the device from the internet and other network segments. Prioritize replacing or upgrading within 90 days.", references: ["https://csrc.nist.gov/files/pubs/other/2022/02/24/getting-started-with-cybersecurity-risk-management/final/docs/quick-start-guide--ransomware.pdf"] },
  { id: "weak_firewall", name: "Inadequate Network Perimeter \u2014 Firewall Misconfiguration", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1133 External Remote Services", severity: "high", likelihood: "medium", business_impact: "A firewall running on factory default settings (or no firewall at all) exposes all internal services directly to the internet. CISA and NSA assessments of over 1,000 networks found default configurations are among the top ten systemic weaknesses. Attackers routinely scan for default router credentials and exposed admin interfaces as their first move.", recommendation: "Change all firewall and router admin passwords from defaults immediately. Disable remote management over the internet unless absolutely necessary. Block all inbound connections except those explicitly required. Enable automatic firmware updates on your router.", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"] },
  { id: "no_asset_inventory", name: "Unknown Attack Surface \u2014 No Asset Inventory", pasta_stage: "Stage 2: Technical Scope", attack_tactic: "TA0043 Reconnaissance", attack_technique: "T1592 Gather Victim Host Information", severity: "medium", likelihood: "high", business_impact: "You cannot protect what you do not know exists. Without an asset inventory, forgotten devices \u2014 old laptops, decommissioned servers, personal phones with work email \u2014 remain connected to your network indefinitely, unpatched and unmonitored. NIST\u2019s ransomware guidance explicitly lists maintaining a hardware and software inventory as a foundational first step.", recommendation: "Create a simple spreadsheet listing every device used for work: device type, user, operating system, and what data it accesses. Update it whenever a device is added or removed. Free tools like Angry IP Scanner (for on-prem) or Microsoft Intune (cloud) can automate discovery.", references: ["https://csrc.nist.gov/files/pubs/other/2022/02/24/getting-started-with-cybersecurity-risk-management/final/docs/quick-start-guide--ransomware.pdf"] },
  { id: "no_business_continuity", name: "No Business Continuity Plan \u2014 Extended Outage Risk", pasta_stage: "Stage 7: Risk & Impact Analysis", attack_tactic: "TA0040 Impact", attack_technique: "T1485 Data Destruction / T1486 Data Encrypted for Impact", severity: "high", likelihood: "medium", business_impact: "Without a business continuity plan, a ransomware attack or major outage leaves employees with no guidance on how to operate, who to contact, or how to communicate with customers. NIST SP 1800-26 identifies the absence of recovery planning as a multiplier of incident impact.", recommendation: "Draft a one-page business continuity plan covering: how to operate without email and computers for 72 hours, emergency contacts for IT support and legal counsel, how to notify customers of an outage, and who has authority to make decisions during an incident. Store a printed copy off-site.", references: ["https://www.nccoe.nist.gov/data-integrity-detecting-and-responding-ransomware-and-other-destructive-events"] },
  { id: "cloud_account_takeover", name: "Cloud Account Takeover via Credential Stuffing", pasta_stage: "Stage 5: Vulnerability Analysis", attack_tactic: "TA0006 Credential Access", attack_technique: "T1110.004 Credential Stuffing", severity: "critical", likelihood: "high", business_impact: "Attackers purchase leaked credential databases from past breaches and automatically test them against Microsoft 365, Google Workspace, and cloud services. A 2024 CyberArk study found 49% of employees reuse the same credentials across multiple work-related applications. Without MFA, a single reused password grants full access to email, files, and admin portals.", recommendation: "Enable MFA on all cloud services immediately \u2014 especially Microsoft 365 and Google Workspace. This single control blocks over 99% of automated credential attacks even when passwords are already compromised. Use an authenticator app rather than SMS where possible. Deploy Conditional Access policies to block logins from unexpected countries.", references: ["https://www.cisa.gov/MFA"] },
  { id: "insider_threat_overprivileged", name: "Insider Threat \u2014 Disgruntled or Departing Employee Data Theft", pasta_stage: "Stage 3: Application Decomposition", attack_tactic: "TA0009 Collection", attack_technique: "T1078 Valid Accounts / T1213 Data from Information Repositories", severity: "high", likelihood: "medium", business_impact: "CISA defines insider threat as any person with authorized access who intentionally or unintentionally causes harm. For SMEs with no formal offboarding and broad access controls, a departing employee can exfiltrate customer lists, financial data, or trade secrets in the days before leaving \u2014 often without detection.", recommendation: "Combine two controls: (1) Least privilege \u2014 employees should only ever have access to what their current role requires. (2) Immediate offboarding \u2014 accounts disabled on the last day, no exceptions. CISA\u2019s insider threat guidance recommends a formal offboarding checklist that includes account revocation, device return, and access log review.", references: ["https://www.cisa.gov/topics/physical-security/insider-threat-mitigation/defining-insider-threats"] },
  { id: "email_domain_spoofing", name: "Email Domain Spoofing \u2014 No DMARC Protection", pasta_stage: "Stage 4: Threat Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1566.002 Phishing: Spearphishing Link / T1598 Phishing for Information", severity: "high", likelihood: "high", business_impact: "Domain-based Message Authentication, Reporting, and Conformance (DMARC) is an essential email security protocol that prevents attackers from spoofing a domain to send phishing or malicious emails. Without DMARC, attackers can send emails that appear to come from your exact domain \u2014 your customers, partners, and employees will see your real email address as the sender. The FBI IC3 2023 report recorded 21,489 BEC complaints with over $2.9 billion in adjusted losses.", recommendation: "Configure SPF, DKIM, and DMARC DNS records for your email domain. SPF and DKIM specify which servers are authorized to send mail from your domain; DMARC tells receiving servers what to do with mail that fails those checks. Free tools like MXToolbox can check your current configuration.", references: ["https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf"] },
  { id: "improper_data_disposal", name: "Data Recovery from Improperly Disposed Devices", pasta_stage: "Stage 6: Attack Modeling", attack_tactic: "TA0009 Collection", attack_technique: "T1530 Data from Cloud Storage / T1005 Data from Local System", severity: "medium", likelihood: "medium", business_impact: "Standard factory resets and quick formats do not securely erase data \u2014 commercial recovery tools can reconstruct files, emails, and credentials from drives that appear wiped. Disposed devices sold, donated, or thrown away without secure erasure are a documented source of PII exposure and credential recovery.", recommendation: "Use NIST-approved secure erasure methods before disposing of any device: DBAN for hard drives, or physical destruction for drives containing highly sensitive data. For SSDs, use manufacturer-provided secure erase tools or full disk encryption before disposal. Document all disposals.", references: ["https://csrc.nist.gov/pubs/sp/800/88/r1/final"] },
  { id: "phishing_spearphishing", name: "Phishing and Spearphishing \u2014 Human-Layer Initial Access", pasta_stage: "Stage 4: Threat Analysis", attack_tactic: "TA0001 Initial Access", attack_technique: "T1566.001 Spearphishing Attachment / T1566.002 Spearphishing Link", severity: "critical", likelihood: "high", business_impact: "Phishing is the most frequently reported cybercrime in the FBI IC3 2023 report with over 298,000 complaints \u2014 accounting for approximately 34% of all reported incidents. A single successful click can deliver ransomware, steal credentials, or initiate a fraudulent wire transfer. Businesses with untrained employees and no email filtering have no technical layer to compensate for human error.", recommendation: "Layer three controls together: (1) Technical \u2014 enable email filtering (Microsoft Defender for Office 365 Safe Links and Safe Attachments). (2) Human \u2014 run annual phishing simulation training. Free tools: GoPhish (self-hosted) and Microsoft Attack Simulator (included in M365 E5). (3) Process \u2014 establish a one-click reporting mechanism so employees can flag suspicious emails without friction.", references: ["https://www.ic3.gov/annualreport/reports/2023_IC3Report.pdf", "https://attack.mitre.org/techniques/T1566/", "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a"] },
  { id: "exposed_remote_desktop", name: "Exposed Remote Desktop \u2014 Direct Internet Attack Surface", pasta_stage: "Stage 2: Technical Scope", attack_tactic: "TA0001 Initial Access", attack_technique: "T1133 External Remote Services / T1110 Brute Force", severity: "critical", likelihood: "high", business_impact: "Remote Desktop Protocol (RDP) exposed directly to the internet is one of the most commonly exploited entry points for ransomware. Attackers continuously scan the internet for open RDP ports and use automated brute force tools to guess weak passwords \u2014 no phishing or social engineering required.", recommendation: "Never expose RDP directly to the internet. Place it behind a Virtual Private Network (VPN) so that only authenticated users can reach it at all. If a VPN is not feasible, restrict RDP access by IP allowlist, enable Network Level Authentication (NLA), which requires a user to authenticate prior to connecting, and enforce Multi-Factor Authentication. Changing the default RDP port (3389) to a random port (less than 65535) not in use can serve as an additional deterrent.", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a", "https://attack.mitre.org/techniques/T1133/"] },
  { id: "exposed_services_no_firewall", name: "Multiple Internet-Exposed Services with Weak Perimeter Controls", pasta_stage: "Stage 2: Technical Scope", attack_tactic: "TA0001 Initial Access", attack_technique: "T1190 Exploit Public-Facing Application", severity: "high", likelihood: "high", business_impact: "Every service exposed to the internet is a potential entry point. Businesses exposing three or more services \u2014 website, email, file sharing, client portal, remote desktop \u2014 with a misconfigured or default firewall have a large, unmonitored attack surface. Attackers use automated scanners to continuously probe all exposed services for known vulnerabilities.", recommendation: "Audit every internet-exposed service and ask: does this need to be publicly reachable, or can it be placed behind a Virtual Private Network (VPN)? For services that must remain public, ensure they are patched, use MFA, and are monitored for suspicious activity. Run a free external scan using a tool such as Shodan or nmap to see what attackers can see from the outside.", references: ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-137a", "https://attack.mitre.org/techniques/T1190/"] },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────
const stageKey  = (r) => r.pasta_stage.split(":")[0].trim();  // "Stage 4"
const stageNum  = (r) => parseInt(r.pasta_stage.match(/\d+/)?.[0] ?? "0");

function scoreLabel(passed, total) {
  const pct = Math.round((passed / total) * 100);
  if (pct >= 85) return { label: "Strong", color: LOW_C };
  if (pct >= 60) return { label: "Moderate", color: HIGH_C };
  return { label: "Needs Work", color: CRIT };
}

// ─── Shared UI pieces ─────────────────────────────────────────────────────────
const MonoLabel = ({ children, style }) => (
  <div style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", textTransform: "uppercase", letterSpacing: "0.1em", ...style }}>
    {children}
  </div>
);

const SevBadge = ({ sev, small }) => (
  <span style={{
    padding: small ? "1px 6px" : "2px 8px",
    borderRadius: 4,
    background: (SEV_COLORS[sev] || TEXT_MUT) + "18",
    border: `1px solid ${(SEV_COLORS[sev] || TEXT_MUT)}35`,
    color: SEV_COLORS[sev] || TEXT_MUT,
    fontSize: small ? 9 : 10,
    fontFamily: "monospace", fontWeight: 700,
    textTransform: "uppercase", letterSpacing: "0.05em",
    flexShrink: 0,
  }}>{sev}</span>
);

// ─── Single misconfig card ────────────────────────────────────────────────────
function MisconfigCard({ rule, flagged, expanded, onToggle }) {
  const stageK  = stageKey(rule);
  const stageMt = STAGE_META[stageK] || { color: TEXT_MUT, icon: "?" };

  return (
    <div style={{
      borderRadius: 8,
      border: flagged
        ? `1px solid ${SEV_COLORS[rule.severity]}40`
        : `1px solid ${BORDER}`,
      borderLeft: `3px solid ${flagged ? SEV_COLORS[rule.severity] : BORDER2}`,
      marginBottom: 8,
      background: flagged ? (SEV_COLORS[rule.severity] + "06") : "rgba(255,255,255,0.012)",
      overflow: "hidden",
      transition: "border-color 0.2s",
    }}>
      {/* Header row — always visible */}
      <button
        onClick={onToggle}
        style={{
          display: "flex", alignItems: "center", justifyContent: "space-between",
          width: "100%", padding: "13px 16px",
          background: "transparent", border: "none", cursor: "pointer",
          textAlign: "left", gap: 12,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 }}>
          {/* Stage dot */}
          <div style={{
            width: 18, height: 18, borderRadius: "50%", flexShrink: 0,
            background: stageMt.color + "20",
            border: `1.5px solid ${stageMt.color}50`,
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 6, fontFamily: "monospace", fontWeight: 900, color: stageMt.color,
          }}>{stageMt.icon}</div>

          <SevBadge sev={rule.severity} />

          <span style={{
            color: flagged ? TEXT_PRI : TEXT_SEC,
            fontSize: 13.5, fontFamily: "Georgia, serif", fontWeight: flagged ? 700 : 400,
            lineHeight: 1.3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>
            {rule.name}
          </span>

          {flagged && (
            <span style={{
              flexShrink: 0, fontSize: 9, fontFamily: "monospace", fontWeight: 700,
              color: SEV_COLORS[rule.severity],
              background: SEV_COLORS[rule.severity] + "15",
              border: `1px solid ${SEV_COLORS[rule.severity]}30`,
              padding: "1px 6px", borderRadius: 3, letterSpacing: "0.05em",
              textTransform: "uppercase",
            }}>
              ⚠ flagged
            </span>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
          <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace", display: "none" }}>
            {rule.attack_technique.split(" ")[0]}
          </span>
          <span style={{ color: TEXT_MUT, fontSize: 12 }}>{expanded ? "▲" : "▼"}</span>
        </div>
      </button>

      {/* Expanded body */}
      {expanded && (
        <div style={{ padding: "0 16px 18px", borderTop: `1px solid ${BORDER}` }}>
          <div style={{ paddingTop: 14, display: "flex", flexDirection: "column", gap: 14 }}>

            {/* MITRE metadata strip */}
            <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>
                Tactic: <span style={{ color: "#4a6278" }}>{rule.attack_tactic}</span>
              </span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>
                Technique: <span style={{ color: "#4a6278" }}>{rule.attack_technique}</span>
              </span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>
                PASTA: <span style={{ color: stageMt.color }}>{rule.pasta_stage}</span>
              </span>
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>
                Likelihood: <span style={{ color: "#4a6278" }}>{rule.likelihood}</span>
              </span>
            </div>

            {/* Business impact */}
            <div>
              <MonoLabel style={{ marginBottom: 5 }}>Why this matters</MonoLabel>
              <p style={{ color: TEXT_DIM, fontSize: 13.5, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
                {rule.business_impact}
              </p>
            </div>

            {/* Recommendation */}
            <div style={{
              background: BG,
              border: `1px solid ${BORDER}`,
              borderLeft: `3px solid ${stageMt.color}`,
              borderRadius: 6,
              padding: "12px 16px",
            }}>
              <MonoLabel style={{ marginBottom: 6, color: stageMt.color }}>How to fix it</MonoLabel>
              <p style={{ color: TEXT_SEC, fontSize: 13.5, fontFamily: "Georgia, serif", lineHeight: 1.65, margin: 0 }}>
                {rule.recommendation}
              </p>
            </div>

            {/* References */}
            {rule.references?.length > 0 && (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {rule.references.map((ref) => (
                  <a
                    key={ref} href={ref} target="_blank" rel="noreferrer"
                    style={{
                      color: TEXT_MUT, fontSize: 11, fontFamily: "monospace",
                      textDecoration: "underline", textDecorationColor: BORDER2,
                      wordBreak: "break-all",
                    }}
                  >
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
}

// ─── Score ring ───────────────────────────────────────────────────────────────
function ScoreRing({ passed, total }) {
  const pct    = passed / total;
  const r      = 36;
  const circ   = 2 * Math.PI * r;
  const dash   = pct * circ;
  const sl     = scoreLabel(passed, total);

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
      <svg width={90} height={90} style={{ flexShrink: 0 }}>
        <circle cx={45} cy={45} r={r} fill="none" stroke={BORDER} strokeWidth={6} />
        <circle
          cx={45} cy={45} r={r} fill="none"
          stroke={sl.color} strokeWidth={6}
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 45 45)"
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        <text x={45} y={49} textAnchor="middle"
          style={{ fill: sl.color, fontSize: 15, fontFamily: "monospace", fontWeight: 800 }}>
          {passed}/{total}
        </text>
      </svg>
      <div>
        <div style={{ color: sl.color, fontSize: 18, fontWeight: 700, fontFamily: "monospace" }}>
          {sl.label}
        </div>
        <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginTop: 2 }}>
          {passed} check{passed !== 1 ? "s" : ""} passed · {total - passed} flagged
        </div>
      </div>
    </div>
  );
}

// ─── Report generator ─────────────────────────────────────────────────────────
function generateReport(rules, flaggedIds, mode) {
  const date  = new Date().toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  const total = rules.length;
  const flagged = rules.filter(r => flaggedIds.has(r.id));
  const passed  = rules.filter(r => !flaggedIds.has(r.id));
  const sevColors = { critical: "#e05c5c", high: "#e8a020", medium: "#5b8dd4", low: "#60b06e" };

  const ruleHTML = (r, isFlag) => `
    <div style="border-left:4px solid ${sevColors[r.severity]||"#999"};margin-bottom:18px;padding:14px 18px;background:${isFlag?"#fff8f8":"#f9f9f9"};border-radius:4px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;flex-wrap:wrap;">
        <span style="background:${sevColors[r.severity]}22;border:1px solid ${sevColors[r.severity]}55;color:${sevColors[r.severity]};padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;font-family:monospace;">${r.severity}</span>
        ${isFlag ? `<span style="background:#e05c5c15;border:1px solid #e05c5c30;color:#e05c5c;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace;">⚠ FLAGGED IN ASSESSMENT</span>` : ""}
        <strong style="font-size:14px;font-family:Georgia,serif;">${r.name}</strong>
      </div>
      <p style="margin:0 0 4px;font-size:11px;color:#666;font-family:monospace;">${r.attack_tactic} · ${r.attack_technique} · Likelihood: ${r.likelihood}</p>
      <p style="margin:0 0 4px;font-size:11px;color:#888;font-family:monospace;">PASTA: ${r.pasta_stage}</p>
      <h4 style="margin:10px 0 4px;font-size:12px;color:#333;font-family:Georgia,serif;">Why this matters</h4>
      <p style="margin:0 0 10px;font-size:13px;line-height:1.6;font-family:Georgia,serif;">${r.business_impact}</p>
      <h4 style="margin:0 0 4px;font-size:12px;color:#333;font-family:Georgia,serif;">How to fix it</h4>
      <p style="margin:0 0 10px;font-size:13px;line-height:1.6;font-family:Georgia,serif;">${r.recommendation}</p>
      ${r.references?.length ? `<p style="margin:0;font-size:11px;color:#666;font-family:monospace;">References: ${r.references.map(u => `<a href="${u}" style="color:#5b8dd4;">${u.replace("https://","")}</a>`).join(" · ")}</p>` : ""}
    </div>`;

  const sl = scoreLabel(total - flaggedIds.size, total);
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>MicroSOC — Threat Report</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:Georgia,serif;background:#fff;color:#1a202c;font-size:14px}.page{max-width:820px;margin:0 auto;padding:48px 40px}.header{background:#0b1117;color:#fff;padding:32px 40px;border-radius:10px;margin-bottom:32px}.header h1{font-size:22px;font-weight:800;color:#c8922a;margin-bottom:4px}.header .sub{color:#94a3b8;font-size:13px}.header .date{color:#4a5568;font-size:11px;margin-top:6px;font-family:monospace}h2{font-size:14px;font-weight:700;color:#0b1117;text-transform:uppercase;letter-spacing:0.07em;margin:28px 0 12px;border-bottom:2px solid #c8922a;padding-bottom:6px}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}.stat{background:#f7fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px 16px;flex:1;min-width:110px}.stat .lbl{font-size:10px;text-transform:uppercase;letter-spacing:0.07em;color:#718096;margin-bottom:4px;font-family:monospace}.stat .val{font-size:20px;font-weight:800;font-family:monospace}.footer{margin-top:48px;padding-top:16px;border-top:1px solid #e2e8f0;color:#718096;font-size:10px;text-align:center;font-family:monospace}@media print{.page{padding:20px}}</style>
</head><body><div class="page">
<div class="header"><h1>MicroSOC — Threat Reference Report</h1><div class="sub">Security Configuration Checklist · PASTA + MITRE ATT&amp;CK Framework</div><div class="date">Generated: ${date} · ${total} checks reviewed · Source: CISA, NIST, FBI IC3, MITRE ATT&amp;CK</div></div>

<h2>Security Posture Summary</h2>
<div class="stats">
  <div class="stat"><div class="lbl">Total Checks</div><div class="val">${total}</div></div>
  <div class="stat"><div class="lbl">Flagged</div><div class="val" style="color:#e05c5c">${flaggedIds.size}</div></div>
  <div class="stat"><div class="lbl">Passed</div><div class="val" style="color:#60b06e">${total - flaggedIds.size}</div></div>
  <div class="stat"><div class="lbl">Posture</div><div class="val" style="color:${sl.color}">${sl.label}</div></div>
</div>

${flagged.length > 0 ? `<h2>Flagged Issues (${flagged.length})</h2>${flagged.map(r => ruleHTML(r, true)).join("")}` : ""}
${mode !== "flagged-only" ? `<h2>All ${total} Checks</h2>${rules.map(r => ruleHTML(r, flaggedIds.has(r.id))).join("")}` : ""}

<div class="footer">MicroSOC · PASTA + MITRE ATT&amp;CK · Threat Module · ${new Date().toISOString().slice(0,10)}</div>
</div></body></html>`;

  const win = window.open("", "_blank");
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => { win.print(); }, 500);
}

// ─── Main component ───────────────────────────────────────────────────────────
export default function MisconfigGuide({ threatModel, onBack }) {
  // If threat model is provided, pre-compute which rule IDs were flagged
  const flaggedIds = useMemo(() => {
    if (!threatModel) return new Set();
    return new Set(threatModel.findings.map(f => f.id));
  }, [threatModel]);

  const hasThreatModel = !!threatModel;
  const total          = MISCONFIG_CATALOG.length;
  const flaggedCount   = flaggedIds.size;
  const passedCount    = total - flaggedCount;

  // ── Filter / view state ───────────────────────────────────────────────────
  const [sevFilter,  setSevFilter]  = useState("all");         // all | critical | high | medium | low
  const [viewMode,   setViewMode]   = useState(hasThreatModel ? "flagged-first" : "by-stage"); // flagged-first | by-stage | flagged-only
  const [search,     setSearch]     = useState("");
  const [expanded,   setExpanded]   = useState(new Set());
  const [expandAll,  setExpandAll]  = useState(false);

  const toggleExpanded = (id) =>
    setExpanded(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; });

  // ── Filtering ─────────────────────────────────────────────────────────────
  const filtered = useMemo(() => {
    let rules = MISCONFIG_CATALOG;
    if (sevFilter !== "all")    rules = rules.filter(r => r.severity === sevFilter);
    if (viewMode === "flagged-only") rules = rules.filter(r => flaggedIds.has(r.id));
    if (search.trim()) {
      const q = search.toLowerCase();
      rules = rules.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.attack_technique.toLowerCase().includes(q) ||
        r.attack_tactic.toLowerCase().includes(q) ||
        r.recommendation.toLowerCase().includes(q)
      );
    }
    return rules;
  }, [sevFilter, viewMode, search, flaggedIds]);

  // ── Grouping ──────────────────────────────────────────────────────────────
  const grouped = useMemo(() => {
    if (viewMode === "flagged-first") {
      const flaggedRules = filtered.filter(r => flaggedIds.has(r.id));
      const otherRules   = filtered.filter(r => !flaggedIds.has(r.id));
      const groups = [];
      if (flaggedRules.length) groups.push({ key: "flagged", label: `⚠ Flagged in your assessment (${flaggedRules.length})`, color: CRIT, rules: flaggedRules });
      if (otherRules.length)   groups.push({ key: "passed",  label: `✓ Not triggered (${otherRules.length})`,                 color: LOW_C, rules: otherRules });
      return groups;
    }
    // by-stage or flagged-only: group by PASTA stage
    const stageMap = {};
    for (const r of filtered) {
      const k = stageKey(r);
      if (!stageMap[k]) stageMap[k] = { key: k, label: `${k}: ${STAGE_META[k]?.label || ""}`, color: STAGE_META[k]?.color || TEXT_MUT, rules: [] };
      stageMap[k].rules.push(r);
    }
    return Object.values(stageMap).sort((a, b) => parseInt(a.key.match(/\d+/)?.[0]) - parseInt(b.key.match(/\d+/)?.[0]));
  }, [filtered, viewMode, flaggedIds]);

  const isExpanded = (id) => expandAll || expanded.has(id);

  return (
    <div style={{
      minHeight: "100vh",
      background: BG,
      backgroundImage: `
        radial-gradient(ellipse 60% 50% at 15% 0%, rgba(200,146,42,0.04) 0%, transparent 60%),
        radial-gradient(ellipse 50% 40% at 85% 100%, rgba(91,141,212,0.04) 0%, transparent 60%)
      `,
      fontFamily: "Georgia, serif",
      padding: "48px 20px 100px",
    }}>
      <div style={{ maxWidth: 860, margin: "0 auto" }}>

        {/* ── Page header ── */}
        <div style={{ marginBottom: 40 }}>
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 22 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <div style={{ width: 8, height: 8, borderRadius: "50%", background: GOLD, boxShadow: `0 0 10px ${GOLD}88` }} />
              <span style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", letterSpacing: "0.16em", textTransform: "uppercase" }}>
                MicroSOC · Module 5
              </span>
            </div>
            {onBack && (
              <button onClick={onBack} style={{
                background: "none", border: `1px solid ${BORDER}`, borderRadius: 6,
                color: TEXT_DIM, cursor: "pointer", fontSize: 12,
                padding: "5px 14px", fontFamily: "Georgia, serif",
              }}>
                ← Back to home
              </button>
            )}
          </div>

          <h1 style={{ fontSize: 34, color: TEXT_PRI, margin: "0 0 4px", lineHeight: 1.1, fontWeight: 700, letterSpacing: "-0.5px" }}>
            Threat Reference Guide
          </h1>
          <p style={{ color: TEXT_DIM, fontSize: 15, margin: "8px 0 0", lineHeight: 1.7, maxWidth: 620 }}>
            Every threat MicroSOC monitors along with step-by-step remediation and authoritative references from CISA, NIST, and the FBI IC3.
            {hasThreatModel && <strong style={{ color: TEXT_SEC }}> {flaggedCount} of {total} checks flagged in your assessment.</strong>}
          </p>
        </div>

        {/* ── Score card (only shown when threat model is available) ── */}
        {hasThreatModel && (
          <div style={{
            background: CARD, border: `1px solid ${BORDER}`, borderRadius: 12,
            padding: "22px 28px", marginBottom: 24,
            display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 20,
          }}>
            <ScoreRing passed={passedCount} total={total} />

            <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
              {["critical", "high", "medium"].map(sev => {
                const n = [...flaggedIds].filter(id => MISCONFIG_CATALOG.find(r => r.id === id)?.severity === sev).length;
                if (!n) return null;
                return (
                  <div key={sev} style={{
                    padding: "10px 16px", borderRadius: 8, textAlign: "center",
                    background: (SEV_COLORS[sev] || TEXT_MUT) + "12",
                    border: `1px solid ${(SEV_COLORS[sev] || TEXT_MUT)}30`,
                  }}>
                    <div style={{ fontSize: 22, fontWeight: 700, color: SEV_COLORS[sev], fontFamily: "monospace" }}>{n}</div>
                    <div style={{ fontSize: 10, color: SEV_COLORS[sev], fontFamily: "monospace", textTransform: "uppercase" }}>{sev}</div>
                  </div>
                );
              })}
            </div>

            <button
              onClick={() => generateReport(MISCONFIG_CATALOG, flaggedIds, "full")}
              style={{
                padding: "10px 20px", borderRadius: 8, border: "none",
                background: GOLD, color: "#0b1117", cursor: "pointer",
                fontSize: 13, fontWeight: 700, fontFamily: "Georgia, serif",
                boxShadow: `0 2px 12px ${GOLD}44`,
              }}
            >
              ↓ Download Report
            </button>
          </div>
        )}

        {/* ── Filter bar ── */}
        <div style={{
          background: CARD, border: `1px solid ${BORDER}`, borderRadius: 10,
          padding: "16px 20px", marginBottom: 20,
          display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center",
        }}>
          {/* Search */}
          <input
            placeholder="Search by name, technique, or keyword…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{
              flex: 2, minWidth: 200,
              background: BG, border: `1px solid ${BORDER}`,
              borderRadius: 7, padding: "8px 12px",
              color: TEXT_PRI, fontSize: 13, fontFamily: "Georgia, serif",
            }}
          />

          {/* Severity filter */}
          <div style={{ display: "flex", gap: 4 }}>
            {["all", "critical", "high", "medium"].map(s => (
              <button
                key={s}
                onClick={() => setSevFilter(s)}
                style={{
                  padding: "6px 12px", borderRadius: 6, cursor: "pointer",
                  fontSize: 11, fontFamily: "monospace", fontWeight: 700,
                  textTransform: "uppercase", letterSpacing: "0.05em",
                  border: `1px solid ${sevFilter === s ? (SEV_COLORS[s] || GOLD) : BORDER}`,
                  background: sevFilter === s ? (SEV_COLORS[s] || GOLD) + "18" : "transparent",
                  color: sevFilter === s ? (SEV_COLORS[s] || GOLD) : TEXT_MUT,
                  transition: "all 0.15s",
                }}
              >{s}</button>
            ))}
          </div>

          {/* View mode */}
          {hasThreatModel && (
            <div style={{ display: "flex", gap: 4, marginLeft: "auto" }}>
              {[
                { key: "flagged-first", label: "Flagged first" },
                { key: "by-stage",     label: "By stage"      },
                { key: "flagged-only", label: "Flagged only"  },
              ].map(({ key, label }) => (
                <button
                  key={key}
                  onClick={() => setViewMode(key)}
                  style={{
                    padding: "6px 12px", borderRadius: 6, cursor: "pointer",
                    fontSize: 11, fontFamily: "monospace",
                    border: `1px solid ${viewMode === key ? GOLD : BORDER}`,
                    background: viewMode === key ? GOLD + "18" : "transparent",
                    color: viewMode === key ? GOLD : TEXT_MUT,
                    transition: "all 0.15s",
                  }}
                >{label}</button>
              ))}
            </div>
          )}

          {/* Expand/collapse toggle */}
          <button
            onClick={() => { setExpandAll(e => !e); setExpanded(new Set()); }}
            style={{
              padding: "6px 12px", borderRadius: 6, cursor: "pointer",
              fontSize: 11, fontFamily: "monospace",
              border: `1px solid ${BORDER}`, background: "transparent", color: TEXT_MUT,
            }}
          >
            {expandAll ? "Collapse all" : "Expand all"}
          </button>
        </div>

        {/* ── Result count ── */}
        <div style={{ color: TEXT_MUT, fontSize: 11, fontFamily: "monospace", marginBottom: 14 }}>
          Showing {filtered.length} of {total} checks
          {search && ` · search: "${search}"`}
          {sevFilter !== "all" && ` · severity: ${sevFilter}`}
        </div>

        {/* ── Grouped rule list ── */}
        {grouped.map(group => (
          <div key={group.key} style={{ marginBottom: 28 }}>
            {/* Group header */}
            <div style={{
              display: "flex", alignItems: "center", gap: 12, marginBottom: 12,
              paddingBottom: 10, borderBottom: `1px solid ${BORDER}`,
            }}>
              <div style={{
                width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                background: group.color + "18",
                border: `1.5px solid ${group.color}50`,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 8, fontFamily: "monospace", fontWeight: 900, color: group.color,
              }}>
                {STAGE_META[group.key]?.icon ?? (group.key === "flagged" ? "⚠" : "✓")}
              </div>
              <div>
                <span style={{ color: group.color, fontSize: 11, fontFamily: "monospace", fontWeight: 700, letterSpacing: "0.08em" }}>
                  {group.label.toUpperCase()}
                </span>
              </div>
              <div style={{ flex: 1, height: 1, background: BORDER }} />
              <span style={{ color: TEXT_MUT, fontSize: 10, fontFamily: "monospace" }}>
                {group.rules.length} check{group.rules.length !== 1 ? "s" : ""}
              </span>
            </div>

            {/* Cards */}
            {group.rules.map(rule => (
              <MisconfigCard
                key={rule.id}
                rule={rule}
                flagged={flaggedIds.has(rule.id)}
                expanded={isExpanded(rule.id)}
                onToggle={() => toggleExpanded(rule.id)}
              />
            ))}
          </div>
        ))}

        {filtered.length === 0 && (
          <div style={{
            padding: "32px", borderRadius: 8, border: `1px dashed ${BORDER}`,
            textAlign: "center",
          }}>
            <p style={{ color: TEXT_MUT, fontFamily: "monospace", fontSize: 13, margin: 0 }}>
              No checks match the current filters.
            </p>
          </div>
        )}

        {/* ── Bottom download (no threat model mode) ── */}
        {!hasThreatModel && (
          <div style={{ marginTop: 24, display: "flex", gap: 12 }}>
            <button
              onClick={() => generateReport(MISCONFIG_CATALOG, flaggedIds, "full")}
              style={{
                padding: "11px 24px", borderRadius: 8, border: "none",
                background: GOLD, color: "#0b1117", cursor: "pointer",
                fontSize: 14, fontWeight: 700, fontFamily: "Georgia, serif",
                boxShadow: `0 2px 12px ${GOLD}44`,
              }}
            >
              ↓ Download Full Reference (PDF)
            </button>
          </div>
        )}

        <p style={{ textAlign: "center", color: "#1a2a38", fontSize: 11, marginTop: 28, fontFamily: "monospace" }}>
          Sources: CISA, NIST, FBI IC3, MITRE ATT&amp;CK · All data processed locally
        </p>
      </div>
    </div>
  );
}
