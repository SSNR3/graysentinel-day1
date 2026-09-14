# FinPay Core Services: Mitigation Implementation & Verification Plan

This document details the architectural controls, configuration blueprints, and verification test cases designed to remediate the risks identified in the *FinPay Core Services Threat Model*.

---

## Control Implementation Matrix

| Threat ID | Threat Category | Target Component | Applied Security Control | Enforcement Mechanism |
| --- | --- | --- | --- | --- |
| **TH-01** | Spoofing | AWS API Gateway / Ingress | Strict JWT Algorithm Whitelisting & JWKS Validation | Envoy `jwt_authn` Filter |
| **TH-02** | Tampering | K8s Pod-to-Pod Traffic | Mutual TLS (mTLS) with SPIFFE Workload Identity | Cilium / Istio Strict PeerAuthentication |
| **TH-03** | Repudiation | Payment Transaction Logs | WORM Compliant Immutable Audit Streaming | AWS S3 Object Lock & KMS HMAC Signing |
| **TH-04** | Information Disclosure | Amazon RDS PostgreSQL | Column Envelope Encryption & Ephemeral IAM DB Auth | AWS KMS Client-Side Encryption + AWS IAM Auth |
| **TH-05** | Denial of Service | Ingress & Database Tier | Token-Bucket Edge Rate Limiting & PgBouncer Pool | AWS WAF Regional Rule + PgBouncer |
| **TH-06** | Elevation of Privilege | Payment-Engine Pod | Contextual Attribute-Based Authorization (ABAC) | Open Policy Agent (OPA) Gatekeeper |

---

## Detailed Control Specifications

### 1. Cryptographic JWT Ingress Validation (`TH-01`)

* **Objective:** Prevent authentication bypass via asymmetric/symmetric key confusion or `alg: none` payload tampering.
* **Architecture Control:** Configure Envoy Ingress to validate tokens strictly against the authorized JSON Web Key Set (JWKS) before routing traffic to backend microservices.
* **Envoy Filter Configuration Snippet:**
```yaml
apiVersion: networking.istio.io/v1beta1
kind: RequestAuthentication
metadata:
  name: jwt-ingress-auth
  namespace: prod
spec:
  selector:
    matchLabels:
      app: ingress-gateway
  jwtRules:
  - issuer: "https://login.microsoftonline.com/tenant-guid/v2.0"
    jwksUri: "https://login.microsoftonline.com/tenant-guid/discovery/v2.0/keys"
    audiences:
    - "api://finpay-core-prod"
    forwardOriginalToken: true
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: require-jwt-token
  namespace: prod
spec:
  selector:
    matchLabels:
      app: ingress-gateway
  action: ALLOW
  rules:
  - from:
    - source:
        requestPrincipals: ["https://login.microsoftonline.com/tenant-guid/v2.0/*"]

```



### 2. Zero-Trust Workload Identity & Inter-Pod Traffic Encryption (`TH-02`)

* **Objective:** Prevent cleartext sniffing, lateral movement, and unauthorized inter-service data alteration within the Kubernetes cluster.
* **Architecture Control:** Enforce cluster-wide strict mutual TLS (mTLS) combined with explicit L7 Layer Network Policies.
* **Cilium NetworkPolicy Implementation:**
```yaml
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: allow-payment-engine-db-access
  namespace: prod
spec:
  endpointSelector:
    matchLabels:
      app: payment-engine
  egress:
  - toEndpoints:
    - matchLabels:
        app: rds-egress-gateway
    toPorts:
    - ports:
      - port: "5432"
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        app: customer-service
    toPorts:
    - ports:
      - port: "8443"
        protocol: TCP
      rules:
        http:
        - method: "POST"
          path: "/v1/accounts/verify"

```



### 3. Immutable WORM Audit Storage (`TH-03`)

* **Objective:** Prevent rogue administrative tampering, backdating, or truncation of financial transaction audit trails.
* **Architecture Control:** Stream state transition records directly to an Amazon S3 bucket configured with Object Lock in Compliance Mode.
* **AWS S3 Bucket Policy Blueprint:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceObjectLockCompliance",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutLifecycleConfiguration"
      ],
      "Resource": "arn:aws:s3:::finpay-transaction-audit-prod/*"
    },
    {
      "Sid": "EnforceTlsOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::finpay-transaction-audit-prod",
        "arn:aws:s3:::finpay-transaction-audit-prod/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}

```



### 4. Database Envelope Encryption & Ephemeral IAM Authentication (`TH-04`)

* **Objective:** Prevent data extraction of cardholder PII and tax identifiers in the event of persistent storage dumps or unauthorized host access.
* **Architecture Control:**
* Application-level envelope encryption using AWS KMS Customer Master Keys (CMKs) prior to database insertion.
* Eliminate static database passwords using AWS IAM Database Authentication (generating 15-minute ephemeral tokens).



### 5. Multi-Layered Rate Limiting & Connection Pooling (`TH-05`)

* **Objective:** Mitigate denial of service and connection exhaustion across the API Gateway and PostgreSQL database.
* **Architecture Control:**
* AWS WAF rule: Limit incoming requests to 300 per 5-minute interval per IP address block.
* PgBouncer deployment: Implement transaction-level connection pooling (`default_pool_size = 50`, `max_client_conn = 2000`) to isolate internal microservices from backend DB thread exhaustion.



### 6. Attribute-Based Access Control / BOLA Protection (`TH-06`)

* **Objective:** Prevent cross-tenant transaction injection or execution via manipulated `account_id` payload fields.
* **Architecture Control:** Open Policy Agent (OPA) policy embedded inside the Payment-Engine API processing pipeline.
* **Rego Policy Implementation:**
```rego
package finpay.authz

default allow = false

# Decode claims from JWT
jwt_payload := payload {
    [_, payload, _] := io.jwt.decode(input.bearer_token)
}

# Validate that the authenticated sub matches the account ownership
allow {
    input.http_method == "POST"
    input.path == ["v1", "transactions", "transfer"]
    jwt_payload.sub == input.body.source_account_owner_id
    jwt_payload.tenant_id == input.body.tenant_id
}

```



---

## Verification & Validation Runbook

Execute these test cases to collect evidence confirming that the controls are operating as designed.

```bash
# -----------------------------------------------------------------------------
# Test 1: Verify TH-01 Mitigation (JWT Key Confusion / Alg None Rejection)
# -----------------------------------------------------------------------------
echo "[*] Testing Ingress Gateway Token Verification..."

# Case A: Request without token (Expect 401)
curl -s -o /dev/null -w "Anonymous Request HTTP Code: %{http_code}\n" \
  https://api.finpay.internal/v1/transactions

# Case B: Request with unsigned forged token (alg: none) (Expect 401)
FORGED_TOKEN="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInRlbmFudF9pZCI6IjAwMSJ9."
curl -s -o /dev/null -w "Forged Token Request HTTP Code: %{http_code}\n" \
  -H "Authorization: Bearer ${FORGED_TOKEN}" \
  https://api.finpay.internal/v1/transactions

# -----------------------------------------------------------------------------
# Test 2: Verify TH-02 Mitigation (Default-Deny Inter-Service Network Policy)
# -----------------------------------------------------------------------------
echo "[*] Testing Network Isolation from Unauthorized Pod..."

# Attempt connection from customer-service pod to an unlisted internal port
kubectl exec -n prod deployment/customer-service -c customer-service -- \
  nc -zvw2 payment-engine.prod.svc.cluster.local 9090 || \
  echo "[+] NetworkPolicy dropped unauthorized connection successfully."

# -----------------------------------------------------------------------------
# Test 3: Verify TH-06 Mitigation (BOLA / Cross-Tenant Execution Rejection)
# -----------------------------------------------------------------------------
echo "[*] Testing BOLA/IDOR Enforcement via OPA..."

# Authenticated as User 101, attempting transfer from User 999 account (Expect 403)
curl -s -o /dev/null -w "BOLA Cross-Tenant HTTP Code: %{http_code}\n" \
  -X POST https://api.finpay.internal/v1/transactions/transfer \
  -H "Authorization: Bearer ${VALID_USER_101_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"source_account_owner_id": "999", "tenant_id": "001", "amount": 500.00}'

```

---

## Rollout Phasing & Risk Assessment

1. **Phase 1 (Monitoring & Detection):** Deploy Envoy Ingress JWT authentication policies and OPA Rego rules in audit/log-only mode for 7 days to baseline valid production flows.
2. **Phase 2 (Strict Policy Enforcement):** Enable active denial on unauthenticated tokens (`TH-01`), activate mTLS strict mode across the Kubernetes mesh (`TH-02`), and enforce cross-tenant authorization checks (`TH-06`).
3. **Phase 3 (Data Layer Hardening):** Migrate database access to IAM ephemeral credentials and transition log archival buckets into strict AWS S3 Object Lock Compliance Mode (`TH-03`, `TH-04`).
