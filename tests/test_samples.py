"""The generated samples are the fixtures for every other test, so check the
generator itself produces what the tests rely on."""

import pytest
from cryptography import x509

from conftest import NOW, generator
from token_inspector.inputs import detect

ENCODINGS = {
    "saml-valid.xml": ("saml", "raw XML", "pasted value"),
    "saml-valid.b64": ("saml", "base64 (HTTP-POST binding)", "pasted value"),
    "saml-valid-redirect.txt": ("saml", "deflate + base64 (HTTP-Redirect binding)", "URL"),
    "saml-valid.har": ("saml", "base64 (HTTP-POST binding)", "HAR file"),
    "saml-valid.saml-tracer.json": ("saml", "base64 (HTTP-POST binding)", "SAML-tracer export"),
    "jwt-valid.txt": ("jwt", "compact JWS", "pasted value"),
    "jwt-valid.har": ("jwt", "compact JWS", "HAR file"),
    "jwt-encrypted.txt": ("jwe", "compact JWE", "pasted value"),
}


def test_every_sample_has_meta_and_is_detected(samples):
    names = samples.names()
    assert len(names) >= 40
    for name in names:
        meta = samples.meta(name)
        assert meta["description"] and meta["expect"], name
        assert len(detect(samples.read(name))) == 1, name


@pytest.mark.parametrize("name,expected", ENCODINGS.items())
def test_encodings(samples, name, expected):
    token = detect(samples.read(name))[0]
    assert (token.kind, token.encoding, token.container) == expected


def test_all_saml_encodings_carry_the_same_response(samples):
    payloads = {detect(samples.read(n))[0].payload for n in ENCODINGS if n.startswith("saml-")}
    assert len(payloads) == 1


def test_certificates_are_in_the_intended_states(samples):
    def load(name):
        return x509.load_pem_x509_certificate(samples.read(name))

    assert load("idp-current.pem").not_valid_before_utc < NOW < load("idp-current.pem").not_valid_after_utc
    assert load("idp-expired.pem").not_valid_after_utc < NOW
    assert load("idp-future.pem").not_valid_before_utc > NOW
    assert load("idp-rotated.pem").public_key() != load("idp-current.pem").public_key()
    ca = load("test-ca.pem")
    assert all(load(f"idp-{s}.pem").issuer == ca.subject for s in ("current", "expired", "future", "rotated"))


def test_sample_values_are_generic(samples):
    """Samples use example.com style values only."""
    for path in samples.dir.iterdir():
        text = path.read_bytes().decode("utf-8", errors="replace")
        for host in ("idp.", "sp.", "api."):
            for line in text.splitlines():
                if f"https://{host}" in line or f"http://{host}" in line:
                    assert f"{host}example.com" in line, (path.name, line[:120])


def test_index_lists_every_sample(samples):
    index = samples.read("INDEX.md").decode()
    for name in samples.names():
        assert f"`{name}`" in index


def test_cli_entry_point_writes_files(tmp_path, capsys):
    assert generator.main(["--out", str(tmp_path), "--now", "2026-03-02T12:00:00Z"]) == 0
    assert "samples" in capsys.readouterr().out
    assert (tmp_path / "saml-valid.xml").exists()
