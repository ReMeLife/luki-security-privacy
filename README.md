# luki-security-privacy

> **This repository is archived.** Active development continues in a private repository. This public version reflects the ReMeLife integration era and is no longer maintained.

Security, consent, and privacy layer for the LUKi ecosystem. Centralises cryptographic operations, consent management, policy enforcement, and privacy controls.

## What It Does

- Manages per-user consent scopes (granular, per data category)
- Enforces access policies via RBAC and ABAC checks
- Provides AES-GCM encryption/decryption for data at rest
- Issues and verifies JWTs
- Applies differential privacy noise (Laplace/Gaussian) for aggregate queries
- Sanitises PII from text
- Logs all access decisions to an immutable audit trail

## Stack

- **Crypto:** `cryptography` (AES-GCM, key derivation), `pyjwt`
- **Privacy:** Custom DP mechanisms (Laplace, Gaussian), k-anonymity checks
- **Policy:** Custom RBAC/ABAC engine
- **Logging:** structlog
- **API:** FastAPI
- **Deployment:** Docker on Railway

## Structure

```
luki_sec/
├── main.py                  # FastAPI app, endpoint registration
├── config.py                # Security feature flags
├── middleware.py             # Request correlation and audit logging
├── consent/
│   ├── models.py            # ConsentRecord, ConsentScope enums
│   ├── engine.py            # check_consent(), enforce_scope()
│   ├── manager.py           # Async CRUD for consent records
│   └── storage.py           # Database adapter
├── policy/
│   ├── rbac.py              # Role-based access control
│   ├── abac.py              # Attribute-based access control
│   └── audit.py             # Immutable audit logging
├── crypto/
│   ├── keys.py              # Key management and rotation
│   ├── jwt.py               # JWT signing and verification
│   ├── encrypt.py           # AES-GCM encryption wrappers
│   └── hash.py              # Hashing and salting
├── privacy/
│   ├── controls.py          # PrivacySettings CRUD
│   ├── dp_mechanisms.py     # Laplace/Gaussian noise, clipping
│   ├── sanitisers.py        # PII redaction and tokenisation
│   └── k_anonymity.py       # Quasi-identifier checks
└── utils/
    └── ids.py               # ID generation
```

## Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET/POST | `/consent/{user_id}` | Read/update consent scopes |
| GET/POST | `/privacy/{user_id}/settings` | Read/update privacy settings |
| POST | `/encrypt` | Encrypt a JSON payload |
| POST | `/decrypt` | Decrypt an encrypted blob |
| POST | `/policy/enforce` | Evaluate access policy (allow/deny + reason) |
| GET | `/health` | Service health with component readiness |

## Setup

```bash
git clone git@github.com:ReMeLife/luki-security-privacy.git
cd luki-security-privacy
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

Set `LUKI_MASTER_KEY` via environment variable or secret manager.

```bash
uvicorn luki_sec.main:app --reload --port 8104
```

## Consent Model

Consent is granular per data category (interests, health, life events). Each consent record stores the scope, timestamp, and source. The policy engine checks consent at call-time and returns a machine-readable reason (`consent_valid`, `consent_denied`, `no_scopes_requested`).

## License

Apache License 2.0. Copyright 2025 Singularities Ltd / ReMeLife. See [LICENSE](LICENSE).
