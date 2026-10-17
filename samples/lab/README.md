# Lab captures

Real SAML responses and tokens captured from a running
[identity-lab](https://github.com/MarkHawk/identity-lab) by
`scripts/capture_from_lab.sh`, one folder per capture label (for example
`baseline/`, or `clock-skew/` captured while that scenario was broken).

Each folder holds:

| File | What it is |
|---|---|
| `saml-response.xml` | The SAMLResponse Keycloak posted to the SAML SP, decoded |
| `jwt-id-token.txt`, `jwt-access-token.txt` | Tokens from the OIDC flow (only if captured with `--oidc`) |
| `idp-metadata.xml`, `jwks.json` | The realm's public SAML metadata and JWKS at capture time |
| `*.meta.json` | The token-inspector arguments for that sample, including `--now` set to the capture time |

Everything here has been through `scripts/sanitise.py`: no private IP
addresses, home directory paths, private keys or local personal patterns.
If sanitising had to change signed content, the sidecar says
`"signature_invalidated_by_sanitising": true` and the signature check is
expected to fail for that reason alone.

`tests/test_lab_samples.py` runs every capture here through the CLI.

## The `expired-signing-cert` capture

This capture caught Keycloak **mid-rotation**, which is worth knowing when
reading it:

- The SAML response and both JWTs were signed by Keycloak's auto-generated
  **fallback key** (self-signed `CN=idlab`, valid for ten years), not by the
  scenario's certificate. When the pinned CA-signed signing certificate reached
  its `notAfter`, Keycloak demoted it and minted a fallback to keep signing.
- The captured `idp-metadata.xml` and `jwks.json` still advertise only the
  **expired** CA-signed certificate (`notAfter` three seconds before the capture
  time); the fallback key's `kid` is in none of them. So the key that signed the
  artifacts is not among the keys the capture publishes.
- `capture_from_lab.sh` fetches the metadata and JWKS **before** it performs the
  logins (`capture_public` runs first, then `capture_saml`/`capture_oidc`), and
  the public documents are read with plain GETs that never sign a token. The
  first signing operation is the SAML login, which is where Keycloak minted the
  fallback. So the JWKS was fetched before the fallback key existed, which is
  exactly why it is absent from the captured JWKS and metadata.
- `sp-pinned-cert.pem` is the certificate the SP had pinned during the break:
  the expired CA-signed signing certificate (public cert only), extracted from
  this capture's `idp-metadata.xml`, where it is byte-identical to what the SP
  pinned. Run the SAML response against it with `--cert sp-pinned-cert.pem` to
  see the SP's view: the trusted certificate has expired and the IdP is signing
  with a different key.

## Troubleshooting

**`capture_from_lab.sh` can't connect to the lab host.** The capture talks to
the lab by its `LAB_HOST` name (for example `idlab.home`), the same name that
appears in the issuer and audience, so the signed URLs stay intact. If the
machine you capture from can't resolve that name, point it at wherever the lab
publishes its ports by adding a line to `/etc/hosts`. When the lab runs on the
same machine, that is loopback:

```
127.0.0.1 idlab.home
```

Use `--map-host` only if you must; it rewrites the host name and so breaks the
signatures.
