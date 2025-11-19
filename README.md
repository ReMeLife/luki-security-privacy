# luki-security-privacy  
*Security, consent, federated learning & privacy-preserving ML utilities for LUKi*  
**Security-critical module – review carefully before production use**

---

## 1. Overview  
This repo centralises the **security and privacy layer** for the LUKi ecosystem. It provides:

- Cryptographic utilities (hashing, signing, key rotation)  
- Consent & policy enforcement helpers (GDPR/HIPAA alignment)  
- Differential Privacy (DP) primitives and dataset sanitisation tools  
- Federated Learning (FL) orchestration framework (roadmap - Flower/PySyft integration planned)  
- Anomaly detection hooks for data misuse and API abuse

The code is designed to be **auditable and security-focused**. It should be safe to open‑source, **provided that real keys, secrets, and environment-specific configuration are never committed**. All secrets must be supplied via environment variables or a secret manager (e.g. Railway secrets, Vault, KMS).

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
Current MVP layout (actual code):

~~~text
luki-security-privacy/
├── Dockerfile
├── README.md
├── requirements.txt
├── luki_sec/
│   ├── __init__.py
│   ├── config.py                 # toggle DP, FL, crypto backends
│   ├── main.py                   # FastAPI app wiring consent, privacy, crypto, policy
│   ├── consent/
│   │   ├── models.py             # ConsentRecord, Scope enums
│   │   ├── engine.py             # check_consent(), enforce_scope()
│   │   ├── manager.py            # async update/get wrappers used by FastAPI
│   │   └── storage.py            # consent DB adapters (SQLite dev backend)
│   ├── policy/
│   │   ├── rbac.py               # roles, permissions
│   │   ├── abac.py               # attribute-based checks
│   │   └── audit.py              # write immutable audit logs
│   ├── crypto/
│   │   ├── keys.py               # key mgmt, rotation; master key via env/KMS
│   │   ├── jwt.py                # JWT issue/verify
│   │   ├── encrypt.py            # AES-GCM wrappers
│   │   └── hash.py               # hashing, salting
│   ├── privacy/
│   │   ├── controls.py           # PrivacySettings CRUD + FastAPI integration
│   │   ├── dp_mechanisms.py      # Laplace/Gaussian noise, clipping utils
│   │   ├── sanitisers.py         # PII redaction / tokenisation
│   │   └── k_anonymity.py        # simple k-anon/quasi-identifier checks
│   └── utils/
│       └── ids.py
├── tests/
│   ├── test_consent.py           # Consent models & engine
│   ├── test_consent_manager.py   # ConsentManager integration
│   ├── test_encrypt_endpoints.py # /encrypt + /decrypt HTTP endpoints
│   ├── test_policy_enforce.py    # /policy/enforce HTTP behaviour
│   └── test_privacy_controls.py  # PrivacyControls + /privacy endpoints
└── test_privacy_endpoints.db     # Local SQLite DB used in some tests (dev artefact)
~~~

Planned/roadmap modules (not yet implemented in this repo, but referenced in docs):

- `luki_sec/federated/` – Flower/PySyft integration, secure aggregation, demo datasets.  
- `luki_sec/anomaly/` – detectors and training utilities for unusual access/log patterns.  
- `scripts/*.py` – helpers for key rotation, consent backfill, and FL orchestration.

---

## 5. Quick Start (Internal Dev)  
~~~bash
git clone git@github.com:REMELife/luki-security-privacy.git
cd luki-security-privacy
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
~~~

### HTTP API overview (MVP)
- `/health` – Service health and component readiness (consent manager, privacy controls, encryption service).
- `/consent/{user_id}` – `POST` to update a user's consent bundle, `GET` to retrieve current consents and valid scopes.
- `/privacy/{user_id}/settings` – `POST` to update privacy settings (e.g. analytics/personalization flags), `GET` to read them.
- `/encrypt` – `POST` a JSON object (`{"key": "value"}`) and receive an `encrypted_data` blob (base64) for storage or transit.
- `/decrypt` – `POST` the `encrypted_data` string and receive the original JSON object back as `decrypted_data`.
- `/policy/enforce` – `POST` a policy request (`user_id`, `requester_role`, `requested_scopes`, optional `context`) and receive an
  allow/deny decision with a machine-readable reason (e.g. `consent_valid`, `consent_denied`, `no_scopes_requested`).

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
key = b"\x00" * 32  # placeholder; fetch from KMS or env in prod
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

## 12. Contributing  

This module is intended to be **auditable and community-reviewable**. Suggested workflow:

- Use feature branches such as `sec/<feature>` or `privacy/<feature>`.  
- When touching sensitive code (crypto, consent, policy, DP, FL), update threat models / DPIA notes where applicable.  
- Add or update tests for new behaviours (especially around `/policy/enforce`, `/consent`, `/privacy`, `/encrypt`, `/decrypt`).  
- Open a PR with a clear description of:
  - What changed.
  - Any new configuration or environment variables.
  - Any migration considerations (e.g. new DB tables or consent scopes).

---

## 13. License  

This project is licensed under the **Apache License, Version 2.0** ("Apache-2.0").  
You may not use this project except in compliance with the License.

You can obtain a copy of the License at:

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an **"AS IS" BASIS,**
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  
See the `LICENSE` file in this repository for the full text of the
Apache-2.0 license.

---

**Security first. Privacy always.**
