# FinPay Core Services: Architectural Threat Model Report

## 1. System Architecture Overview

The system under review is **FinPay Core Services**, a hybrid cloud-native financial transaction processing engine.

* **Untrusted Zone:** External Web/Mobile clients connecting over TLS 1.3.
* **DMZ Zone (Trust Boundary 01):** AWS API Gateway handling edge rate limiting, web application firewall (AWS WAF) rules, and basic TLS termination.
* **Application Compute (Trust Boundary 02):** Multi-tenant AWS EKS cluster running:
* `Auth-Proxy / Ingress`: Verifies OIDC JWT signatures via Entra ID public keys.
* `Customer-Service`: Handles user profile management and account metadata.
* `Payment-Engine`: Manages transaction processing, balance queries, and payment execution.


* **Data Persistence Zone (Trust Boundary 03):** Amazon RDS PostgreSQL (stores PII and transaction records) and Amazon S3 (immutable write-once audit logs), secured inside dedicated private subnets.

```text
[External Clients] 
       │ (HTTPS / TLS 1.3)
═══════╪══════════════════════════════════════════════════ [Trust Boundary 01: Perimeter]
       ▼
[AWS API Gateway / WAF]
       │ (Forward with Bearer Token)
═══════╪══════════════════════════════════════════════════ [Trust Boundary 02: Ingress/Mesh]
       ▼
[EKS Ingress / Envoy] ──(OIDC Validation)──► [Entra ID (External IdP)]
       │
       ├────────────────────────┐
       ▼ (Internal mTLS)        ▼ (Internal mTLS)
[Customer-Service Pod]    [Payment-Engine Pod]
       │                        │
═══════╪════════════════════════╪══════════════════════════ [Trust Boundary 03: Data Layer]
       ▼                        ▼
[Amazon RDS PostgreSQL]   [Amazon S3 Audit Bucket]

```

---

## 2. Quantitative DREAD Risk Matrix

The DREAD scoring model evaluates threats across five categories on a scale from 1 to 10:

* **D**amage Potential: Extent of harm if the vulnerability is exploited.
* **R**eproducibility: Ease with which the attack can be replicated.
* **E**xploitability: Technical effort and skill required to launch the attack.
* **A**ffected Users: Percentage of the user base impacted.
* **D**iscoverability: Ease of discovering the vulnerability.

**Overall Score Formula:**

$$\text{Risk Score} = \frac{D + R + E + A + D}{5}$$

*Severity Bands:* **Critical (8.5–10.0)** | **High (7.0–8.4)** | **Medium (5.0–6.9)** | **Low (1.0–4.9)**

| Threat ID | STRIDE | Threat Scenario & Target Component | D | R | E | A | D | Total | Severity |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **TH-01** | Spoofing | **Forged JWT via Key Confusion (`alg: none` / asymmetric flaw):** Attacker crafts unsigned or HMAC-signed tokens with public keys to impersonate arbitrary tenants at the API Gateway. | 9 | 8 | 8 | 9 | 7 | **8.2** | **High** |
| **TH-02** | Tampering | **Pod-to-Pod Traffic Snooping & Injection:** Compromised low-privilege pod performs ARP spoofing/lateral packet inspection to alter payment payloads in transit across the Kubernetes flat network. | 8 | 6 | 6 | 7 | 6 | **6.6** | **Medium** |
| **TH-03** | Repudiation | **Unsigned Transaction Audits:** Payment-Engine writes plain SQL insert logs without cryptographic hashing or write-once guarantees; rogue admins can truncate or alter audit trails. | 8 | 9 | 7 | 5 | 6 | **7.0** | **High** |
| **TH-04** | Info Disclosure | **Database Leakage via Over-Privileged Service Accounts:** Compromised Customer-Service pod credentials allow exfiltration of unencrypted cardholder PII and tax IDs directly from RDS. | 9 | 8 | 8 | 9 | 8 | **8.4** | **High** |
| **TH-05** | Denial of Service | **Connection Pool Starvation on RDS:** External attacker issues heavy unindexed ledger search queries, exhausting the PostgreSQL backend worker pool and halting all checkouts. | 7 | 9 | 9 | 8 | 8 | **8.2** | **High** |
| **TH-06** | Elevation of Privilege | **Broken Object Level Authorization (BOLA/IDOR):** Manipulating `account_id` in payment capture requests executes fund transfers on behalf of arbitrary users without object ownership verification. | 10 | 9 | 9 | 9 | 8 | **9.0** | **Critical** |

---

## 3. Defensive Mitigation Blueprint (MITRE ATT&CK & Architecture Mapping)

| Threat ID | Threat Category | Prescribed Security Control / Architecture Pattern | Relevant MITRE ATT&CK ID | Verification / Acceptance Criteria |
| --- | --- | --- | --- | --- |
| **TH-01** | Spoofing | **Strict JWKS Verification & Algorithm Whitelisting:** Enforce RS256/ES256 verification exclusively at the Ingress proxy. Reject tokens with `alg: none`, validate `iss`, `aud`, and verify against Entra ID JWKS endpoint with 15-minute key caching. | **T1589** (Gather Victim Identity Info)<br>

<br>**T1550.001** (Application Access Token) | Automated negative test suite attempts token execution using `alg: none` and self-signed symmetric keys; requests return HTTP `401 Unauthorized`. |
| **TH-02** | Tampering | **Zero-Trust Service Mesh (Istio / Cilium):** Enforce strict mutual TLS (mTLS) with SPIFFE/SPIRE cryptographic workload identities. Implement default-deny Cilium NetworkPolicies restricting traffic solely to explicit service-to-service ports. | **T1557** (Adversary-in-the-Middle)<br>

<br>**T1040** (Network Sniffing) | Pod-to-pod network traffic inspection shows 100% encrypted TLS streams; cross-namespace lateral connections are actively dropped by eBPF rules. |
| **TH-03** | Repudiation | **WORM Storage & Signed Audit Streams:** Forward all transaction state transitions to Amazon S3 Object Lock in Compliance Mode. Hash log batches using AWS KMS-backed HMAC before shipping to SIEM. | **T1565.001** (Stored Data Manipulation)<br>

<br>**T1070** (Indicator Removal) | `s3:DeleteObject` and `s3:PutLifecycleConfiguration` calls fail even for cluster administrative accounts; S3 Object Lock retains records for 7 years. |
| **TH-04** | Info Disclosure | **Field-Level Encryption & IAM Database Authentication:** Implement AWS KMS envelope encryption for sensitive database columns (PII/PAN). Replace hardcoded DB credentials with ephemeral AWS IAM RDS database authentication. | **T1552.001** (Credentials in Files)<br>

<br>**T1530** (Data from Cloud Storage) | Direct database dumps yield ciphertext for PII columns without authorized AWS KMS Decrypt permissions; IAM tokens expire after 15 minutes. |
| **TH-05** | Denial of Service | **Token-Bucket Rate Limiting & Read Replicas:** Configure AWS WAF rate-based rules per IP and API Gateway usage plans per API key. Offload heavy analytic and read queries to read-only Aurora replicas behind PgBouncer connection pooling. | **T1498** (Network DoS)<br>

<br>**T1499** (Endpoint DoS) | Stress testing at 5,000 req/sec returns HTTP `429 Too Many Requests` without degrading write latency on the primary RDS instance. |
| **TH-06** | Elevation of Privilege | **Contextual Policy Enforcement (OPA / Cedar):** Enforce attribute-based access control (ABAC) using Open Policy Agent (OPA). Evaluate user context claims (`sub`, `tenant_id`) against requested resource ownership before dispatching to the DB. | **T1078.004** (Cloud Accounts)<br>

<br>**T1548** (Abuse Elevation Mechanism) | API integration tests verifying cross-tenant ID execution (`GET /api/v1/accounts/TENANT_B` with `TENANT_A` token) explicitly trigger HTTP `403 Forbidden`. |

---

## 4. Verification and Testing Evidence

### Test Case 1: Cryptographic JWT Algorithm Confusion

* **Target:** API Ingress OIDC Authenticator (`TH-01`)
* **Test Command:**
```bash
# Attempting request with forged unsigned token (alg: none)
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://api.finpay.internal/v1/transactions \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInRlbmFudCI6IjAwMSJ9."

```


* **Observed Result:** `401 Unauthorized`
* **Evidence:** Ingress Envoy log flags: `jwt_verification_failed: unsupported_algorithm`.

### Test Case 2: Zero-Trust Network Policy Isolation

* **Target:** Inter-pod lateral movement (`TH-02`)
* **Test Command:**
```bash
# Attempting connection from Customer-Service to unauthorized internal analytics port
kubectl exec -n prod customer-service-7bb8c9-x291a -- nc -zv -w 3 internal-analytics.prod.svc.cluster.local 9000

```


* **Observed Result:** Connection timed out (`exit code 1`).
* **Evidence:** Cilium eBPF monitor dropped packet: `Policy dropped packet: source=customer-service target=internal-analytics:9000 action=DENY`.

---

## 5. Security Architecture Recommendations

1. **Adopt Threat-as-Code in CI/CD:** Commit the threat model definition as a Python `pytm` script to automatically detect newly introduced endpoints or data flows missing mTLS or authentication policies during pull request evaluations.
2. **Implement Ephemeral Credentials Across Services:** Eliminate long-lived static secrets in Kubernetes Secrets by adopting HashiCorp Vault or AWS Secrets Manager with dynamic 1-hour rotation cycles.
3. **Automate Continuous Threat Validation:** Pair the threat model with scheduled automated security testing (e.g., CI/CD-driven DAST and container posture scanning) to ensure runtime posture aligns continuously with the architectural assumptions documented here.
