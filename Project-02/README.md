# Project 02: Attack Surface Risk Register

## 1. Problem
Modern enterprises experience rapid attack surface drift due to dynamic cloud provisioning, shadow IT, forgotten staging environments, and dangling DNS configurations. Security teams lack an authoritative, real-time inventory of internet-exposed assets, resulting in unmonitored perimeter gaps that adversaries routinely exploit before patch management cycles occur.

## 2. Objective
- Execute external reconnaissance and asset discovery across an enterprise public-facing perimeter.
- Categorize exposed network services, DNS records, cloud storage buckets, and management interfaces.
- Correlate identified exposure points with CVE intelligence and CVSS v3.1 severity metrics.
- Build an actionable **Attack Surface Risk Register** calculating Inherent Risk, Residual Risk, and SLA-bound remediation workflows.

## 3. Scenario
**Target Organization:** *FinPay Global Perimeter (`finpay.internal` / ASN 64500 analog)*
- **External Scope:** Public IPv4 block `198.51.100.0/24` and subdomains across `finpay.internal`.
- **Identified Surfaces:** Remote access VPN portals, legacy merchant webhook endpoints, dangling documentation CNAMEs, CI/CD build servers, and public AWS S3 storage buckets.
- **Threat Persona:** External opportunistic attacker and specialized financial sector threat actor conducting automated perimeter mapping.

## 4. Approach
1. **Discovery & Reconnaissance:** Perform non-intrusive port, banner, and DNS mapping across exposed ranges.
2. **Exposure Profiling:** Enumerate TLS configurations, exposed software versions, and authentication boundaries.
3. **Risk Quantification:**
   $$\text{Inherent Risk} = \text{Likelihood (1–5)} \times \text{Impact (1–5)}$$
   $$\text{Residual Risk} = \text{Post-Mitigation Likelihood} \times \text{Post-Mitigation Impact}$$
4. **Register Formalization:** Document ownership, CVSS v3.1 metrics, MITRE ATT&CK techniques, and remediation SLAs.

## 5. Implementation
- **Tooling:** Python `nmap` wrapper (`src/asm_recon_scanner.py`), ProjectDiscovery `nuclei` templates, and custom risk-scoring logic (`src/risk_scoring_engine.py`).
- **Core Assets Profiled:**
  - `EXT-SVR-01`: SSL-VPN Gateway running outdated firmware with unauthenticated RCE risk (CVSS 9.8).
  - `EXT-API-02`: Legacy B2B Merchant Webhook running deprecated TLS 1.0 without brute-force protection (CVSS 7.5).
  - `EXT-DNS-03`: Dangling Route53 CNAME vulnerable to subdomain hijacking (CVSS 8.1).
  - `EXT-DEV-04`: Publicly exposed Jenkins staging orchestrator without forced SSO (CVSS 8.8).
  - `EXT-STR-05`: Publicly listable cloud archival backup bucket (CVSS 6.5).
  - `EXT-WEB-06`: Main consumer web application lacking hardened HTTP response headers (CVSS 4.3).

## 6. Testing & Validation
- Executed reconnaissance discovery scripts against target test ranges in an authorized sandbox.
- Verified DNS resolution states using `dig` and checked dangling alias records.
- Tested TLS handshake cipher suites using `testssl.sh` to confirm deprecated protocol exposures.
- Simulated credential brute-force and anonymous API calls to validate missing rate controls.

## 7. Evidence
- Full Tabulated Register: `evidence/attack_surface_register.csv`
- Raw Nmap Port Scan Output: `evidence/nmap_recon.log`
- Nuclei Scanner Telemetry: `evidence/nuclei_findings.json`
- Risk Heatmap Visualization: `screenshots/03_risk_heat_map.png`

## 8. Result
- Formulated an enterprise-grade Attack Surface Risk Register accounting for 6 core public assets.
- Identified 1 Critical, 3 High, 1 Medium, and 1 Low risk exposures.
- Reduced overall aggregate organizational inherent risk score from 75 to a residual score of 15 (80% risk reduction) post-control mapping.

## 9. Security Relevance
An Attack Surface Risk Register transforms raw vulnerability scan noise into prioritized business risk. It enables SecOps and GRC teams to establish strict remediation SLAs, enforce defensive accountability, and proactively eliminate initial access vectors mapped to **MITRE ATT&CK TA0001 (Initial Access)** and **TA0043 (Reconnaissance)**.

## 10. Limitations
- Passive and active network discovery only captures active, responsive interfaces; unrouted or IP-whitelisted private instances behind CDN origin shields require agent-based telemetry.
- Third-party SaaS dependencies (e.g., Salesforce integrations) are not fully profiled via basic external port scanning.

## 11. Learning
- Outdated perimeter VPN appliances and forgotten staging CI/CD servers present the highest initial access hazard compared to primary web applications.
- Calculating both Inherent and Residual risk scores is essential to demonstrate the defensive ROI of security controls to infrastructure owners.

## 12. Future Improvement
- Integrate continuous automated external attack surface management (EASM) scans triggered weekly via GitHub Actions.
- Automate ticket creation in Jira/ServiceNow directly when newly discovered assets exceed a CVSS threshold of 7.0.
