"""The lab capture script's parsing and writing, without a running lab.

The live HTTP flow can only be proved against identity-lab itself; these
tests cover everything around it."""

import base64
import json
import urllib.parse
import zlib

import pytest

from conftest import load_script

lab = load_script("lab_capture")

LOGIN_PAGE = """<html><form id="kc-form-login" onsubmit="return true;"
 action="https://idlab.example.com:8180/realms/idlab/login-actions/authenticate?session_code=abc&amp;execution=e1"
 method="post"><input id="username" name="username"/></form></html>"""


def test_login_form_action():
    assert lab.login_form_action(LOGIN_PAGE).endswith("session_code=abc&execution=e1")
    assert lab.login_form_action("<html>no form</html>") is None


def test_keycloak_error_message():
    page = '<span id="input-error" class="x" aria-live="polite">\n  Invalid username or password.\n</span>'
    assert lab.keycloak_error(page) == "Invalid username or password."
    assert lab.keycloak_error("<html/>") is None


def test_saml_response_from_auto_submit_page():
    page = '<form method="post"><input type="hidden" name="SAMLResponse" value="PHg+PC94Pg=="/></form>'
    assert lab.saml_response_from_page(page) == "PHg+PC94Pg=="
    assert lab.saml_response_from_page("<html/>") is None


def test_authn_request_id_from_redirect():
    xml = b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="ONELOGIN_abc123" Version="2.0"/>'
    deflated = base64.b64encode(zlib.compress(xml)[2:-4]).decode()
    url = "https://idlab.example.com:8180/realms/idlab/protocol/saml?SAMLRequest=" + urllib.parse.quote(deflated)
    assert lab.authn_request_id(url) == "ONELOGIN_abc123"
    assert lab.authn_request_id("https://x.example.com/") is None


def test_pkce_pair():
    import hashlib

    verifier, challenge = lab.pkce_pair()
    expected = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    assert challenge == expected and 43 <= len(verifier) <= 128


def test_code_from_redirect():
    assert lab.code_from_redirect("https://rp.example.com/cb?code=c1&state=s1", "s1") == "c1"
    with pytest.raises(lab.CaptureError, match="state"):
        lab.code_from_redirect("https://rp.example.com/cb?code=c1&state=other", "s1")
    with pytest.raises(lab.CaptureError, match="invalid_request"):
        lab.code_from_redirect("https://rp.example.com/cb?error=invalid_request&state=s1", "s1")


def _public(samples):
    return ("https://idp.example.com/realms/example", samples.read("idp-metadata.xml"), samples.read("jwks.json").decode())


def test_write_capture_produces_runnable_samples(samples, tmp_path):
    saml = (samples.read("saml-valid.xml"), "_req-4f1c2a9e", "https://sp.example.com/saml/metadata",
            "https://sp.example.com/saml/acs")
    oidc = (samples.read("jwt-valid.txt").decode().strip(), samples.read("jwt-access-token.txt").decode().strip(),
            "n-0S6_WzA2Mj", "example-rp")
    out = tmp_path / "baseline"
    summary = lab.write_capture(out, "2026-03-02T12:00:00Z", "baseline", _public(samples), saml, oidc, [])
    assert sorted(p.name for p in out.iterdir()) == [
        "idp-metadata.xml", "jwks.json", "jwt-access-token.txt", "jwt-access-token.txt.meta.json",
        "jwt-id-token.txt", "jwt-id-token.txt.meta.json", "saml-response.xml", "saml-response.xml.meta.json",
    ]
    assert summary["files"] == {"saml-response.xml": False, "jwt-id-token.txt": False, "jwt-access-token.txt": False}
    meta = json.loads((out / "saml-response.xml.meta.json").read_text())
    assert meta["signature_invalidated_by_sanitising"] is False
    assert meta["args"][-2:] == ["--now", "2026-03-02T12:00:00Z"]


def test_write_capture_refuses_private_keys(samples, tmp_path):
    key_header = "-----BEGIN " + "PRIVATE KEY-----"
    public = ("https://idp.example.com/realms/example", samples.read("idp-metadata.xml"), key_header)
    with pytest.raises(lab.sanitise.UnsafeContent):
        lab.write_capture(tmp_path / "x", "2026-03-02T12:00:00Z", "x", public, None, None, [])
    assert not (tmp_path / "x").exists()


def test_write_capture_records_invalidated_signatures(samples, tmp_path):
    private_ip = ".".join(["10", "0", "0", "7"])
    xml = samples.read("saml-valid.xml").replace(b"sp.example.com/saml/acs", f"{private_ip}/saml/acs".encode())
    saml = (xml, None, "https://sp.example.com/saml/metadata", f"https://{private_ip}/saml/acs")
    out = tmp_path / "dirty"
    lab.write_capture(out, "2026-03-02T12:00:00Z", "dirty", _public(samples), saml, None, [])
    meta = json.loads((out / "saml-response.xml.meta.json").read_text())
    assert meta["signature_invalidated_by_sanitising"] is True
    assert private_ip not in (out / "saml-response.xml").read_text() + json.dumps(meta)
