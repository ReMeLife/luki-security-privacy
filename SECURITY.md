# Security Policy

LUKi Security & Privacy Module (`luki-security-privacy`) is a **security‑critical** component.  
We welcome responsible disclosure of any vulnerabilities that you may discover.

## Supported Versions

This project is currently in active development. We aim to:

- Keep the `main` branch in a **buildable and test‑passing** state.
- Tag releases as the module stabilises and as it is used in production deployments.

If you are reporting a vulnerability, please check that it reproduces against:

- The latest `main` branch, or
- The most recent tagged release (if available).

## Reporting a Vulnerability

If you believe you have found a security or privacy issue, **do not** open a public GitHub issue.

Instead, please contact the maintainers directly:

- Email: `security@remelife.com` (preferred)

When reporting, please include:

- A clear description of the issue and its potential impact.
- Steps to reproduce (including sample requests, configurations, or payloads if relevant).
- Any relevant logs, stack traces, or screenshots (redacted of personal data).

We ask that you:

- Give us a reasonable amount of time to investigate and remediate the issue before any public disclosure.
- Avoid accessing or exfiltrating any real user data. Use test accounts and synthetic data only.

## Scope

This security policy primarily covers:

- The `luki-security-privacy` repository:
  - Consent engine and storage.
  - Policy enforcement endpoints (`/policy/enforce`).
  - Privacy settings and storage (`/privacy/...`).
  - Cryptographic utilities (AES‑GCM, JWT, key management).

Issues in other LUKi / ReMeLife repositories (e.g. `luki-core-agent`, `luki-memory-service`, `luki-api-gateway`) should be reported via their respective security channels, or via the same email if none is specified.

## Non‑Security Issues

For non‑security bugs, feature requests, and questions:

- Please open a normal GitHub issue on the repository.
- Clearly label the issue as `bug` or `enhancement`.

## Acknowledgements

We appreciate the time and effort of security researchers and contributors who help make LUKi safer.  
Where appropriate, and with your consent, we may acknowledge your contribution in release notes or security advisories.
