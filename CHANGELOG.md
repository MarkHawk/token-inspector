# Changelog

## 0.2.0 (2026-10-22)

### Added

- Likely cause: **short token lifetime**. A JWT issued to live 120 s or less
  (`exp` minus `iat`) that expired in the last 15 minutes is put down to its
  lifetime instead of clock skew. The Expiry line shows the lifetime. The cause
  also appears when the expiry is only a WARN inside the skew allowance; the
  verdict and exit code do not change.
- Likely cause: **changed after signing** (`tampered-signature`), for a SAML
  digest mismatch or a JWT whose signature fails against the key its `kid`
  names.
- Likely cause: **SAML audience mismatch** (`saml-audience-mismatch`), naming
  the audience the assertion was issued for and the SP entity ID to set.
- Likely cause: **nonce mismatch** (`nonce-mismatch`), for an ID token from
  another login attempt.
- Links to identity-lab runbook 16 (API: 401 with a Bearer token) from the
  issued-to-another-client, old-token and short-lifetime causes.
- A Likely causes list in the README, and a runbook column in the patterns
  table in `docs/checks.md`.

### Changed

- The demo summary shows WARN, not FAIL, for a likely cause found behind a
  warning.

## 0.1.0

- First version.
