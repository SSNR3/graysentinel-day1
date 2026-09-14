# Comprehensive Technical Report: Attack Surface Risk Register

## 1. Executive Summary
An external attack surface reconnaissance and risk assessment was conducted across the *FinPay Global* public network perimeter. The assessment aimed to discover, categorize, and quantify exposures across internet-facing hosts, cloud storage endpoints, and DNS records. 

A total of **6 primary internet-facing assets** were cataloged into the Attack Surface Risk Register. The assessment revealed that while core consumer web portals implement baseline controls, peripheral staging servers and legacy integration endpoints present significant attack avenues, including potential unauthenticated remote code execution and subdomain hijacking.

---

## 2. Attack Surface Risk Register

| Asset ID | Asset Description & Surface | Exposed Port / Service | Identified Vulnerability / Exposure | CVSS v3.1 | Inherent Risk (L x I) | Residual Risk | Assigned SLA |
|---|---|---|---|---|---|---|---|
| **EXT-SVR-01** | Perimeter VPN Gateway (`vpn.finpay.internal`) | UDP 1194 / TCP 443 (SSL-VPN) | Outdated Gateway Firmware / Pre-Auth RCE Vulnerability | **9.8** (Crit) | **20** (4 × 5) | **4** (2 × 2) | **7 Days** |
| **EXT-API-02** | Legacy Merchant API (`webhook-legacy.finpay.internal`) | TCP 8443 (Node.js / Express) | Weak TLS 1.0 Ciphers & Missing Endpoint Rate Limiting | **7.5** (High) | **16** (4 × 4) | **4** (2 × 2) | **14 Days** |
| **EXT-DNS-03** | Developer Subdomain (`dev-portal.finpay.internal`) | DNS CNAME (Route53 -> S3) | Dangling DNS Record Allowing Subdomain Takeover | **8.1** (High) | **12** (3 × 4) | **2** (1 × 2) | **14 Days** |
| **EXT-DEV-04** | Staging Jenkins CI/CD (`ci-stage.finpay.internal`) | TCP 8080 (Jetty / Jenkins) | Publicly Exposed CI/CD Dashboard with Anonymous Read | **8.8** (High) | **15** (3 × 5) | **3** (1 × 3) | **14 Days** |
| **EXT-STR-05** | Cloud Archival Storage (`finpay-db-backups-temp`) | HTTPS (AWS S3 Endpoint) | Misconfigured Bucket ACL Permitting Global Object Listing | **6.5** (Med) | **9** (3 × 3) | **1** (1 × 1) | **30 Days** |
| **EXT-WEB-06** | Primary Web Portal (`app.finpay.internal`) | TCP 443 (Nginx Reverse Proxy) | Missing Strict Transport & Content Security Headers | **4.3** (Low) | **3** (3 × 1) | **1** (1 × 1) | **60 Days** |

*Inherent Risk Formula:* $\text{Likelihood (1–5)} \times \text{Impact (1–5)} = \text{Score (1–25)}$.  
*Rating Bands:* Critical (20–25), High (12–19), Medium (6–11), Low (1–5).

---

## 3. Threat Mapping & Engineering Countermeasures

### 1. Perimeter SSL-VPN Appliance (`EXT-SVR-01`)
* **Threat Persona:** Initial Access Broker / Advanced Persistent Threat (APT).
* **MITRE ATT&CK:** `T1190` (Exploit Public-Facing Application), `T1133` (External Remote Services).
* **Prescribed Control:** Decommission legacy SSL-VPN listener. Transition internal workforce access to an authenticated Zero-Trust Network Access (ZTNA) model enforced via Entra ID Conditional Access and hardware-bound FIDO2 MFA.

### 2. Legacy Merchant Webhook Endpoint (`EXT-API-02`)
* **Threat Persona:** Fraud syndicate / Financial Man-in-the-Middle.
* **MITRE ATT&CK:** `T1557` (Adversary-in-the-Middle), `T1110` (Brute Force).
* **Prescribed Control:** Enforce TLS 1.3 only; disable TLS 1.0/1.1 on upstream reverse proxies. Implement mutual TLS (mTLS) with public-key client certificates issued exclusively to authorized enterprise settlement partners.

### 3. Dangling Route53 DNS CNAME (`EXT-DNS-03`)
* **Threat Persona:** Brand impersonator / Phishing operator.
* **MITRE ATT&CK:** `T1584.004` (Compromise Infrastructure: Serverless), `T1566` (Phishing).
* **Prescribed Control:** Implement an automated Route53 alias hygiene pipeline that triggers AWS Lambda to verify CNAME destination targets and automatically purges orphan DNS records when backend buckets are deleted.

### 4. Public Staging Jenkins Server (`EXT-DEV-04`)
* **Threat Persona:** Supply chain infiltrator / Cryptojacker.
* **MITRE ATT&CK:** `T1078` (Valid Accounts), `T1195.002` (Supply Chain Compromise: Compromise Software Supply Chain).
* **Prescribed Control:** Move the Jenkins master behind a private Application Load Balancer with zero direct public IPv4 mapping. Restrict access via internal corporate VPN and require SAML SSO authentication for all endpoints.

---

## 4. Remediation Governance & SLA Tracking

```text
Aggregate Inherent Risk Score:  75 / 150
Aggregate Residual Risk Score:  15 / 150
Overall Risk Reduction:         80.0%
