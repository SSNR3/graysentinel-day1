Project 01: Security Architecture Threat Model
1. Problem Statement
Modern enterprise cloud-native applications expose distributed trust boundaries across public networks, containerized microservices, third-party authentication providers, and sensitive backend data stores. Without a formal threat model, security controls are applied reactively, leaving critical blind spots in identity propagation, inter-service authentication, and data at rest/transit.

2. Objectives
Deconstruct Architecture: Map FinPay multi-tier cloud application into Level-0 and Level-1 Data Flow Diagrams (DFDs).
Threat Identification: Identify system trust boundaries and analyze attack vectors using STRIDE.
Risk Prioritization Quantify and prioritize threats using the DREA qualitative risk scoring framework.
Mitigation Blueprint: Formulate actionable defensive controls mapped to MITRE ATT&CK techniques and Zero Trust principles.

3. Scenario & Architecture Overview
Target Scope: FinPay Core Services
Public Attack Surface: AWS API Gateway / Reverse Proxy (TLS Termination).Workload Isolation: Isolated Amazon EKS cluster running `Customer Service` & `Payment Processing` pods.
Identity & Federation: OpenID Connect (OIDC) / OAuth 2.0 issued by Microsoft Entra ID.
Data Persistence: Amazon RDS PostgreSQL (PII & Transactions) + Amazon S3 (Audit Trails).

System Data Flow & Trust Boundaries mermaid
flowchart TD
    User([Untrusted Client])  
    subgraph TB01 ["Trust Boundary 1: Public DMZ"]
        GW["API Gateway / Reverse Proxy\n(TLS Termination)"]
    end
    subgraph TB02 ["Trust Boundary 2: Kubernetes Service Mesh"]
        Auth["IdP: Entra ID\n(OIDC/OAuth2)"]
        SVC1["Customer Microservice"]
        SVC2["Payment Processing Service"]
    end
    subgraph TB03 ["Trust Boundary 3: Data Tier Subnet"]
        DB[("Amazon RDS\nPostgreSQL (PII)")]
        S3[("Amazon S3\nAudit Bucket")]
    end
    User -->|HTTPS Request| GW
    GW -->|Validate Token| Auth
    GW -->|Internal Route| SVC1
    GW -->|Internal Route| SVC2
    SVC2 -->|mTLS| DB
    SVC2 -->|Write Logs| S3

4. Methodology & Approach

System Decomposition: Map all component interactions, data stores, and trust boundaries.
STRIDE Assessment: Spoofing: Identity forging on external APIs and internal pod-to-pod communications.
Tampering: In-flight payload manipulation and unauthorized database modifications.
Repudiation: Transaction repudiation due to inadequate audit trails or unauthenticated logging.
Information Disclosure: Cleartext PII exposure, unmasked telemetry, or leaked secrets.
Denial of Service: Worker pool exhaustion, resource starvation, and API rate-limit absence.
Elevation of Privilege: RBAC/ABAC bypass and BOLA (Broken Object Level Authorization).

3.DREAD Risk Scoring: Evaluate parameters from 1–10:

$$\text{Risk Score} = \frac{D + R + E + A + D}{5}$$

4. Mitigation Blueprint: 
Align architectural controls with Zero Trust Architecture (ZTA).
5. Key Threats Identified
| Threat ID | Target Component | STRIDE Category | Vector & Vulnerability Description | DREAD Score | Risk Level |
| `TH-01` | API Gateway | Spoofing | Weak JWT signature verification allows forged user tokens (`alg: none`). | 8.6| HIGH |
| `TH-02` | Service Mesh | Tampering | Unencrypted pod-to-pod traffic permits internal lateral snooping. | 7.2 | HIGH |
| `TH-03` | RDS Postgres | Info Disclosure | Unmasked customer PII exposed via over-privileged analytical queries. | 7.8| HIGH |
| `TH-04` | Payment API | Elevation of Privilege | BOLA (API1:2023) allows tampering with victim account balances. | 9.0 | CRITICAL |

TB-01 (Public Network ⇄ DMZ):Untrusted Internet crossing into API Gateway. Enforces TLS 1.3, AWS WAF, and DDoS rate-limiting.
TB-02 (DMZ ⇄ Compute Tier): Ingress to containerized microservices. Enforces mutual TLS (mTLS via Istio/Linkerd) and strict SPIFFE/SPIRE pod identities.
TB-03 (Compute Tier ⇄ Data Tier): Workload to database subnet. Enforces IAM database authentication, least-privilege KMS keys, and data-at-rest encryption.

6. Testing & Security Verification
bash
Example: Automated JWT Verification Check
curl -s -X POST [https://api.finpay.local/v1/payment](https://api.finpay.local/v1/payment) \
  -H "Authorization: Bearer eyJhbGciOiJub25lIn0..." \
  | jq '.status'
Expected: 401 Unauthorized (Rejecting alg=none)
Token Rigidity: Confirmed strict cryptographic verification on all claims, issuers, and key rotation interfaces.
Zero-Trust Network Policies: Enforced default-deny pod communication using Kubernetes network policies.
Access Control Regression: Validated context-aware object ownership checks to neutralize BOLA.

7. Artifacts & Evidence
text
├── evidence/
│   ├── dfd_diagram.png         # Structural Level-0 / Level-1 DFD
│   └── stride_matrix.csv       # Complete 14-threat assessment matrix
└── screenshots/
    └── 03_dread_risk_matrix.png # Quantitative scoring ledger

8. Findings & Security Impact
Discovered Flaws: Cataloged 14 distinct architectural flaws (1 Critical, 3 High, 6 Medium, 4 Low).
Control Delivery: Delivered engineering-ready mitigation tasks directly mapped to DevSecOps tickets.
> Limitations: This threat model reflects the current static topology. New third-party webhook integrations or microservice expansions will require continuous threat modeling reviews.
9. Future Improvements
[ ] Implement Threat-as-Code (using `pytm` or Deciduous) directly inside CI/CD pipelines.
[ ] Automate drift detection between Terraform infrastructure code and architectural threat profiles.

Why this renders well on GitHub:
1. GitHub Alert Blocks (`> [!NOTE]`, `> [!CAUTION]`): Displays highlighted callout banners.
2. Mermaid Diagrams (` ```mermaid `): GitHub natively converts this into an interactive, visual architecture flow diagram without needing an uploaded image.
3. Shields.io Badges: Gives the repository an enterprise open-source feel right at the top.
4. Collapsible Section (`<details>` / `<summary>`): Keeps the document clean and easy to skim.
5. Interactive Checklists (`- [x]`): Produces interactive check boxes.
