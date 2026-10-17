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
