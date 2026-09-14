# Project 01: Security Architecture Threat Model

## 1. Problem
Modern enterprise cloud-native applications expose distributed trust boundaries across public networks, containerized microservices, third-party authentication providers, and sensitive backend data stores. Without a formal threat model, security controls are applied reactively, leaving critical blind spots in identity propagation, inter-service authentication, and data at rest/transit.

## 2. Objective
- Deconstruct the multi-tier cloud application into a Level-0 and Level-1 Data Flow Diagram (DFD).
- Identify system trust boundaries and analyze attack vectors using the **STRIDE** methodology.
- Prioritize identified threats using the **DREAD** qualitative risk scoring framework.
- Define actionable defensive mitigations mapped to **MITRE ATT&CK** techniques and zero-trust architectural principles.

## 3. Scenario
**System under review:** *FinPay Core Services*
- **Public Surface:** AWS API Gateway / Reverse Proxy handling TLS termination.
- **Compute:** Microservices running in an isolated EKS cluster (Customer Service, Payment Processing).
- **Identity & Access:** OpenID Connect (OIDC) / OAuth2 tokens issued by an enterprise IdP (Entra ID).
- **Data Persistence:** Amazon RDS PostgreSQL (stores transaction records and PII) and Amazon S3 (stores audit trails).
- **Network Boundaries:** Public DMZ, Private Application Subnet, Restricted Database VPC Subnet.

## 4. Approach
1. **Decomposition:** Map components, data stores, data flows, and trust boundaries.
2. **Threat Identification (STRIDE):**
   - **S**poofing: Impersonating users or inter-service calls.
   - **T**ampering: Modifying payloads in transit or altering database logs.
   - **R**epudiation: Denying financial transactions due to unauthenticated logging.
   - **I**nformation Disclosure: Leaking JWT secrets or PII in cleartext.
   - **D**enial of Service: Exhausting API Gateway worker pools or DB connection pools.
   - **E**levation of Privilege: Bypassing RBAC to perform unauthorized payment captures.
3. **Risk Scoring (DREAD):**
   - Score threats on a 1–10 scale across *Damage, Reproducibility, Exploitability, Affected Users, and Discoverability*.
4. **Countermeasure Architecture:** Define defensive controls for high-risk findings.

## 5. Implementation
- **Tooling:** OWASP Threat Dragon / Diagram.net for structural DFD generation; Python `pytm` for code-based validation.
- **Trust Boundaries Established:**
  - `TB-01`: Untrusted Internet vs. API Gateway (DMZ).
  - `TB-02`: API Gateway vs. Internal Kubernetes Pod Service Mesh.
  - `TB-03`: Microservices vs. Isolated Relational Database Subnet.

### Key Threats Identified
| Threat ID | Component | STRIDE Category | Threat Description | DREAD Score |
|---|---|---|---|---|
| **TH-01** | API Gateway | Spoofing | Weak JWT signature verification allows forged user tokens. | 8.6 (High) |
| **TH-02** | Service Mesh | Tampering | Unencrypted pod-to-pod traffic permits internal lateral snooping/tampering. | 7.2 (High) |
| **TH-03** | RDS Postgres | Information Disclosure | Unmasked customer PII exposed via over-privileged analytical queries. | 7.8 (High) |
| **TH-04** | Payment API | Elevation of Privilege | Broken Object Level Authorization (BOLA) enables unauthorized balance transfers. | 9.0 (Critical) |

## 6. Testing & Validation
- **Simulation/Verification:**
  - Validated JWT expiration, signature algorithm restrictions (`none` algorithm rejection), and claim checks against mock keys.
  - Audited network policies using Kubernetes security benchmarks (`cilium`/`calico` default-deny egress/ingress tests).
  - Executed BOLA/IDOR regression checks against Payment API endpoints.

## 7. Evidence
- Architectural DFD rendering: `evidence/dfd_diagram.png`
- Detailed STRIDE assessment workbook: `evidence/stride_matrix.csv`
- DREAD scoring breakdown: `screenshots/03_dread_risk_matrix.png`

## 8. Result
- Generated a formal Threat Modeling report identifying **14 distinct architectural flaws** (1 Critical, 3 High, 6 Medium, 4 Low).
- Produced an engineering-ready mitigation blueprint with assigned control owners.

## Repository Layout
Organize your repo exactly as required:
graysentinel-day1/
└── project-01/
├── README.md
├── report.md
├── src/
│   ├── threat_model.json        # Threat Dragon / PyTM / Threatspec export
│   └── dfd_diagram.png          # High-resolution architectural DFD
├── evidence/
│   ├── stride_matrix.csv        # Tabulated threats & risk ratings
│   └── mitigation_plan.md       # Implementation controls & verification
    └── screenshots/
        ├── 01_dfd_level1.png
        ├── 02_stride_analysis.png
        └── 03_dread_risk_matrix.png
