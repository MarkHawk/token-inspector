import pytest

from token_inspector.inputs import detect
from token_inspector.keys import KeyFileError, cert_details, load_certs, load_jwks, load_metadata
from token_inspector.saml_parse import SamlParseError, parse_saml
from token_inspector.saml_verify import DIGEST_ERROR, KEY_ERROR, MALFORMED, verify_signatures


def message(samples, name):
    return parse_saml(detect(samples.read(name))[0].payload)


def trusted(samples, md="idp-metadata.xml"):
    return load_metadata(samples.path(md)).signing_certs


# ---------------------------------------------------------------- parsing


def test_parse_valid_response(samples):
    m = message(samples, "saml-valid.xml")
    a = m.assertion
    assert m.is_response and m.status_code.endswith(":Success")
    assert m.issuer == a.issuer == "https://idp.example.com/realms/example"
    assert m.destination == "https://sp.example.com/saml/acs"
    assert m.in_response_to == "_req-4f1c2a9e"
    assert a.name_id == "jo.bloggs@example.com" and a.name_id_format.endswith("emailAddress")
    assert a.audiences == ["https://sp.example.com/saml/metadata"]
    assert a.subject_confirmations[0].recipient == "https://sp.example.com/saml/acs"
    assert a.not_before.value < a.not_on_or_after.value
    assert a.attributes["role"] == ["app-user", "app-admin"]
    assert a.authn_context.endswith("PasswordProtectedTransport")


def test_parse_finds_every_assertion(samples):
    m = message(samples, "saml-xsw.xml")
    assert len(m.assertions) == 2
    assert m.assertion.name_id == "admin@example.com"  # the forged one comes first


def test_parse_bare_assertion(samples):
    m = message(samples, "saml-valid.xml")
    from lxml import etree

    bare = parse_saml(etree.tostring(m.assertion.element))
    assert not bare.is_response and bare.assertion.name_id == "jo.bloggs@example.com"


def test_parse_name_id_with_comment_keeps_full_value():
    xml = (
        b'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a">'
        b"<saml:Subject><saml:NameID>user@example.com<!-- x -->.evil.example</saml:NameID></saml:Subject>"
        b"</saml:Assertion>"
    )
    assert parse_saml(xml).assertion.name_id == "user@example.com.evil.example"


@pytest.mark.parametrize(
    "xml,match",
    [
        (b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>', "metadata"),
        (b'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>', "AuthnRequest"),
        (b'<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>', "LogoutResponse"),
        (b"<html/>", "not a SAML Response"),
    ],
)
def test_parse_rejects_other_documents(xml, match):
    with pytest.raises(SamlParseError, match=match):
        parse_saml(xml)


def test_duplicate_ids_are_recorded():
    xml = (
        b'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        b'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">'
        b'<saml:Assertion ID="_a"/><saml:Assertion ID="_a"/></samlp:Response>'
    )
    assert parse_saml(xml).duplicate_ids == ["_a"]


# ---------------------------------------------------------------- signatures


def test_valid_assertion_signature(samples):
    [r] = verify_signatures(message(samples, "saml-valid.xml"), trusted(samples))
    assert (r.location, r.valid, r.verified_with) == ("assertion", True, "trusted")
    assert r.signed_id == r.parent_id
    assert r.signature_method.endswith("rsa-sha256")


def test_response_and_assertion_reported_separately(samples):
    results = verify_signatures(message(samples, "saml-signed-both.xml"), trusted(samples))
    assert [(r.location, r.valid) for r in results] == [("response", True), ("assertion", True)]
    [only] = verify_signatures(message(samples, "saml-signed-response.xml"), trusted(samples))
    assert only.location == "response" and only.valid


def test_unsigned_has_no_signatures(samples):
    assert verify_signatures(message(samples, "saml-unsigned.xml"), trusted(samples)) == []


def test_tampered_is_a_digest_error(samples):
    [r] = verify_signatures(message(samples, "saml-tampered.xml"), trusted(samples))
    assert (r.valid, r.error_kind) == (False, DIGEST_ERROR)


def test_rotated_key_is_a_key_error_but_internally_consistent(samples):
    [r] = verify_signatures(message(samples, "saml-rotated-cert.xml"), trusted(samples))
    assert (r.valid, r.error_kind, r.embedded_valid) == (False, KEY_ERROR, True)


def test_expired_cert_still_verifies_mathematically(samples):
    [r] = verify_signatures(message(samples, "saml-expired-cert.xml"), trusted(samples, "idp-metadata-expired.xml"))
    assert r.valid


def test_sha1_signature_verifies_and_is_identified(samples):
    [r] = verify_signatures(message(samples, "saml-sha1.xml"), trusted(samples))
    assert r.valid and r.signature_method.endswith("rsa-sha1")
    assert all(d.endswith("#sha1") for d in r.digest_methods)


def test_without_trust_uses_embedded_cert(samples):
    [r] = verify_signatures(message(samples, "saml-valid.xml"), None)
    assert (r.valid, r.verified_with) == (True, "embedded")


def test_xsw_signature_covers_the_second_assertion(samples):
    m = message(samples, "saml-xsw.xml")
    [r] = verify_signatures(m, trusted(samples))
    assert r.valid and r.signed_id == m.assertions[1].id != m.assertion.id


def test_signature_without_any_cert_is_malformed(samples):
    m = message(samples, "saml-valid.xml")
    for el in m.root.iter("{http://www.w3.org/2000/09/xmldsig#}KeyInfo"):
        el.getparent().remove(el)
    [r] = verify_signatures(m, None)
    assert (r.valid, r.error_kind) == (False, MALFORMED)


# ---------------------------------------------------------------- key files


def test_load_metadata(samples):
    md = load_metadata(samples.path("idp-metadata.xml"))
    assert md.entity_id == "https://idp.example.com/realms/example" and len(md.signing_certs) == 1


def test_load_certs_pem_and_der(samples, tmp_path):
    [cert] = load_certs(samples.path("idp-current.pem"))
    der = tmp_path / "c.der"
    from cryptography.hazmat.primitives.serialization import Encoding

    der.write_bytes(cert.public_bytes(Encoding.DER))
    assert load_certs(der) == [cert]


def test_cert_details(samples):
    [cert] = load_certs(samples.path("idp-current.pem"))
    d = cert_details(cert)
    assert "CN=idp.example.com signing" in d["subject"] and "Test CA" in d["issuer"]
    assert len(d["sha256_fingerprint"].split(":")) == 32 and d["key"] == "RSA 2048"


@pytest.mark.parametrize(
    "loader,content,match",
    [
        (load_certs, b"hello", "does not contain"),
        (load_certs, b"<md:EntityDescriptor/>", "--metadata"),
        (load_metadata, b"<r/>", "not SAML metadata"),
        (load_jwks, b"[]", "not a JWKS"),
        (load_jwks, b"{nope", "not valid JSON"),
    ],
)
def test_bad_key_files(tmp_path, loader, content, match):
    p = tmp_path / "f"
    p.write_bytes(content)
    with pytest.raises(KeyFileError, match=match):
        loader(p)


def test_sp_metadata_is_explained(tmp_path):
    p = tmp_path / "sp.xml"
    p.write_bytes(
        b'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x">'
        b"<md:SPSSODescriptor/></md:EntityDescriptor>"
    )
    with pytest.raises(KeyFileError, match="SP metadata"):
        load_metadata(p)
