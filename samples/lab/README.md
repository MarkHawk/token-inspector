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

## Troubleshooting

**`capture_from_lab.sh` can't connect to the lab host.** The capture talks to
the lab by its `LAB_HOST` name (for example `idlab.home`), the same name that
appears in the issuer and audience, so the signed URLs stay intact. If the
machine you capture from can't resolve that name, point it at wherever the lab
publishes its ports by adding a line to `/etc/hosts` — when the lab runs on the
same machine, that's loopback:

```
127.0.0.1 idlab.home
```

Use `--map-host` only if you must; it rewrites the host name and so breaks the
signatures.
