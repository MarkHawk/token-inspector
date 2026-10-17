"""Run committed identity-lab captures (samples/lab/<label>/) through the CLI.

Each capture records the time it was taken, so it is evaluated as at that
moment. Skipped when there are no captures, as in a fresh clone."""

import io
import json
import pathlib

import pytest

from conftest import ROOT
from token_inspector.cli import EXIT_ERROR, EXIT_FAIL, main

CAPTURES = sorted(pathlib.Path(ROOT / "samples" / "lab").glob("*/*.meta.json"))


@pytest.mark.skipif(not CAPTURES, reason="no lab captures committed yet")
@pytest.mark.parametrize("meta_path", CAPTURES, ids=[f"{p.parent.name}/{p.name[:-10]}" for p in CAPTURES])
def test_lab_capture(meta_path):
    meta = json.loads(meta_path.read_text())
    sample = meta_path.with_name(meta_path.name[: -len(".meta.json")])
    args = [a.replace("{dir}", str(meta_path.parent)) for a in meta["args"]]
    out = io.StringIO()
    code = main([str(sample), *args, "--json"], stdout=out, stderr=io.StringIO())
    assert code != EXIT_ERROR
    findings = {f["check_id"]: f["status"] for f in json.loads(out.getvalue())["findings"]}
    signature = findings.get("saml.signature.assertion") or findings.get("jwt.signature")
    if meta["signature_invalidated_by_sanitising"]:
        assert signature == "FAIL"
    elif meta["label"] == "baseline":
        assert code == 0, findings  # a healthy lab produces a clean report


def test_expired_signing_cert_capture_against_the_sp_pinned_cert():
    """The expired-signing-cert capture caught Keycloak mid-rotation: the SAML
    response is signed by a valid fallback key, while the certificate the SP had
    pinned (sp-pinned-cert.pem) has expired. Checked against that pinned cert,
    the signing-cert dates pass but the trusted-cert dates fail."""
    cap = ROOT / "samples" / "lab" / "expired-signing-cert"
    pinned, meta_path = cap / "sp-pinned-cert.pem", cap / "saml-response.xml.meta.json"
    if not pinned.exists() or not meta_path.exists():
        pytest.skip("expired-signing-cert capture not committed")
    meta = json.loads(meta_path.read_text())
    args, drop_next = [], False
    for a in meta["args"]:  # reuse the recorded args but trust the pinned cert, not the metadata
        if drop_next:
            drop_next = False
        elif a == "--metadata":
            drop_next = True
        else:
            args.append(a.replace("{dir}", str(cap)))
    args += ["--cert", str(pinned)]
    out = io.StringIO()
    code = main([str(cap / "saml-response.xml"), *args, "--json"], stdout=out, stderr=io.StringIO())
    findings = {f["check_id"]: f for f in json.loads(out.getvalue())["findings"]}
    assert code == EXIT_FAIL
    assert findings["saml.cert.trusted_validity"]["status"] == "FAIL"
    assert findings["saml.cert.trusted_validity"]["runbook"] == "01-expired-signing-cert"
    assert findings["saml.cert.validity"]["status"] == "PASS"  # the fallback key that signed it is still valid
