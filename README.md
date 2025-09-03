# luki-security-privacy  
*Security, consent, federated learning & privacy-preserving ML utilities for LUKi*  
**PRIVATE / PROPRIETARY – Internal use only**

---

## 1. Overview  
This repo centralises the **security and privacy layer** for the LUKi ecosystem. It provides:

- Cryptographic utilities (hashing, signing, key rotation)  
- Consent & policy enforcement helpers (GDPR/HIPAA alignment)  
- Differential Privacy (DP) primitives and dataset sanitisation tools  
- Federated Learning (FL) orchestration framework (roadmap - Flower/PySyft integration planned)  
- Anomaly detection hooks for data misuse and API abuse

All code here is **sensitive IP**. Do not expose externally.

---

## 2. Core Capabilities  
- **Consent Engine** – Parse/store user consent scopes; enforce at call-time.  
- **Policy Enforcement** – Role-based access (RBAC), attribute-based (ABAC) checks, audit logging.  
- **Crypto Toolkit** – JWT signing/verification, HMACs, encryption-at-rest helpers (AES-GCM), key derivation.  
- **Differential Privacy** – Noise mechanisms (Laplace/Gaussian), clipping, aggregation wrappers.  
- **Federated Learning Orchestration** – Framework for future FL implementation (Flower/PySyft integration planned).  
- **Anomaly Detection** – Simple unsupervised detectors to spot unusual access patterns or data drifts.

---

## 3. Tech Stack  
- **Security & Crypto:** `cryptography`, `pyjwt`, `hashlib`, `libsodium` (via pynacl)  
- **Privacy:** Opacus (for DP-SGD), PySyft / Flower for FL, custom DP utilities  
- **Policy:** Oso/oso-cloud optional, or custom Python RBAC/ABAC module  
- **Logging & Audit:** structlog, OpenTelemetry exporters  
- **Anomaly Detection:** scikit-learn (IsolationForest), PyOD (optional)

---

## 4. Repository Structure  
~~~text
luki_security_privacy/
├── README.md
├── requirements.txt
├── luki_sec/
│   ├── __init__.py
│   ├── config.py                 # toggle DP, FL, crypto backends
│   ├── consent/
│   │   ├── models.py             # ConsentRecord, Scope enums
│   │   ├── engine.py             # check_consent(), enforce_scope()
│   │   └── storage.py            # consent DB adapters
│   ├── policy/
│   │   ├── rbac.py               # roles, permissions
│   │   ├── abac.py               # attribute-based checks
│   │   └── audit.py              # write immutable audit logs
│   ├── crypto/
│   │   ├── keys.py               # key mgmt, rotation
│   │   ├── jwt.py                # JWT issue/verify
│   │   ├── encrypt.py            # AES-GCM wrappers
│   │   └── hash.py               # hashing, salting
│   ├── privacy/
│   │   ├── dp_mechanisms.py      # Laplace/Gaussian noise, clipping utils
│   │   ├── sanitisers.py         # PII redaction / tokenisation
│   │   └── k_anonymity.py        # simple k-anon/quasi-identifier checks
│   ├── federated/
│   │   ├── flower_server.py      # FL server launcher
│   │   ├── flower_client.py      # FL client wrapper
│   │   ├── secure_agg.py         # additive masking / SecAgg protocols
│   │   └── datasets/             # synthetic demo datasets
│   ├── anomaly/
│   │   ├── detectors.py          # access/log anomaly detection
│   │   └── training.py           # fit/refresh models
│   └── utils/
│       └── ids.py
├── scripts/
│   ├── run_fl_server.sh
│   ├── rotate_keys.py
│   └── backfill_consent.py
└── tests/
    ├── unit/
    └── integration/
~~~

---

## 5. Quick Start (Internal Dev)  
~~~bash
git clone git@github.com:REMELife/luki-security-privacy.git
cd luki-security-privacy
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
~~~

### Consent check example  
~~~python
from luki_sec.consent.engine import enforce_scope
from luki_sec.consent.models import ConsentScope

# Raises if not allowed
enforce_scope(
    user_id="user_123",
    requester_role="agent",
    requested_scopes=[ConsentScope.ELR_INTERESTS]
)
~~~

### Encrypt / decrypt blob  
~~~python
from luki_sec.crypto.encrypt import encrypt_bytes, decrypt_bytes
key = b"\x00"*32  # fetch from KMS in prod
cipher = encrypt_bytes(key, b"Sensitive text")
plain = decrypt_bytes(key, cipher)
assert plain == b"Sensitive text"
~~~

### Differential privacy noise  
~~~python
from luki_sec.privacy.dp_mechanisms import laplace_noise

true_stat = 42.0
noisy = true_stat + laplace_noise(scale=1.5)
print(noisy)
~~~

### Launch Flower FL server  
~~~bash
python -m luki_sec.federated.flower_server --rounds 5 --model_path models/base.pth
~~~

---

## 6. Key Management & Rotation  
- Keys stored in Vault/KMS; dev uses `.env` (never commit).  
- Rotate quarterly or on incident; use `scripts/rotate_keys.py`.  
- JWTs short-lived; refresh tokens stored server-side (httpOnly cookies or Redis).

---

## 7. Consent & Audit Principles  
- Consent is granular (per data field/category); store timestamps & IP.  
- Every access write/read is logged with trace ID & hashed parameters.  
- Provide `export_consent_history(user_id)` for compliance requests.  
- Auto-expire stale consents where laws require.

---

## 8. Federated Learning Guidelines  
- Only train on devices/sites with signed DPA agreements.  
- Secure aggregation masks gradients; server never sees raw updates.  
- DP-SGD wrapper (Opacus) optional for extra privacy.  
- Validate client models before merge (hash/size checks).

---

## 9. Anomaly Detection Hooks  
- IsolationForest on API call frequencies, scope requests, odd hours.  
- Threshold alerts to PagerDuty/Slack.  
- Periodically retrain with `anomaly/training.py`.

---

## 10. Testing & CI  
- Unit tests for crypto functions (test vectors), consent logic, DP noise stats.  
- Integration tests spin up mock FL sessions.  
- Run:  
  ~~~bash
  pytest -q
  ~~~

---

## 11. Roadmap  
- ZK-proof prototypes for consent attestation  
- Homomorphic encryption testbed (Paillier / CKKS)  
- Automated DPIA generator (Data Protection Impact Assessment)  
- ReBAC (relationship-based) policy engine for complex org hierarchies

---

## 12. Contributing (Internal Only)  
- Feature branches `sec/<feature>` or `privacy/<feature>`  
- Add threat model updates & DPIA notes when touching sensitive code  
- Mandatory code review by security lead

---

## 13. License  
**Proprietary – All Rights Reserved**  
Copyright 2025 Singularities Ltd / ReMeLife.  
Unauthorized copying, modification, distribution, or disclosure is strictly prohibited.

---

**Security first. Privacy always.**
