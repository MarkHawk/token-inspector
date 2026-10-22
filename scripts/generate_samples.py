#!/usr/bin/env python3
"""Build synthetic SAML and JWT samples with a throwaway test CA.

Every sample is created at run time, so the tests and the README work
without identity-lab and no private key is ever committed. Each sample has a
.meta.json sidecar recording what it demonstrates, the token-inspector
arguments to run it with, and the status expected from the key checks.

    python scripts/generate_samples.py                  # into samples/generated/
    python scripts/generate_samples.py --out DIR --now 2026-01-01T12:00:00Z

All names and hosts are example.com values. Private keys are written only
into the output directory (gitignored) so you can re-sign samples by hand.
"""

import argparse
import base64
import copy
import datetime as dt
import json
import pathlib
import sys
import urllib.parse
import uuid
import zlib

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import CanonicalizationMethod, DigestAlgorithm, SignatureMethod, XMLSigner

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"
MD = "urn:oasis:names:tc:SAML:2.0:metadata"

IDP_ENTITY = "https://idp.example.com/realms/example"
SP_ENTITY = "https://sp.example.com/saml/metadata"
ACS_URL = "https://sp.example.com/saml/acs"
REQUEST_ID = "_req-4f1c2a9e"
CLIENT_ID = "example-rp"
NONCE = "n-0S6_WzA2Mj"
API_AUDIENCE = "https://api.example.com"
SUBJECT_EMAIL = "jo.bloggs@example.com"
SUBJECT_UUID = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"

# The arguments a support engineer would pass for this IdP/SP pair.
SAML_EXPECT = [
    "--expect-issuer", IDP_ENTITY,
    "--expect-audience", SP_ENTITY,
    "--expect-destination", ACS_URL,
    "--expect-recipient", ACS_URL,
    "--expect-in-response-to", REQUEST_ID,
]
OIDC_EXPECT = [
    "--expect-issuer", IDP_ENTITY,
    "--expect-audience", CLIENT_ID,
    "--client-id", CLIENT_ID,
    "--nonce", NONCE,
    "--expect-alg", "RS256",
]


def iso(t):
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------- keys and certs


class TestPKI:
    """A throwaway CA plus IdP signing certificates in every state we need."""

    def __init__(self, now):
        self.now = now
        self.ca_key = _rsa()
        ca_name = _name("Token Inspector Test CA")
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=3650))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )
        day = dt.timedelta(days=1)
        self.signing = {
            "current": self._issue("idp.example.com signing", now - 30 * day, now + 335 * day),
            "expired": self._issue("idp.example.com signing", now - 400 * day, now - 35 * day),
            "future": self._issue("idp.example.com signing", now + 10 * day, now + 375 * day),
            "rotated": self._issue("idp.example.com signing (new)", now - 1 * day, now + 364 * day),
        }

    def _issue(self, cn, not_before, not_after):
        key = _rsa()
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn))
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(self.ca_key, hashes.SHA256())
        )
        return key, cert


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Ltd"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def cert_b64(cert):
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


# ---------------------------------------------------------------- SAML


class _LegacySHA1Signer(XMLSigner):
    """signxml refuses SHA-1 by design. Test fixtures only: allow it so we can
    build the legacy-algorithm sample that the tool must flag."""

    def check_deprecated_methods(self):
        pass


def _signer(sha1=False):
    c14n = CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0
    if sha1:
        return _LegacySHA1Signer(
            signature_algorithm=SignatureMethod.RSA_SHA1,
            digest_algorithm=DigestAlgorithm.SHA1,
            c14n_algorithm=c14n,
        )
    return XMLSigner(c14n_algorithm=c14n)


def build_response(now, **o):
    """Return an unsigned samlp:Response element. Keyword overrides:
    issued, lifetime, not_before, issuer, audience, destination, recipient,
    in_response_to, status."""
    issued = o.get("issued", now - dt.timedelta(seconds=5))
    lifetime = o.get("lifetime", dt.timedelta(minutes=5))
    not_before = o.get("not_before", issued - dt.timedelta(seconds=30))
    not_on_or_after = issued + lifetime
    issuer = o.get("issuer", IDP_ENTITY)
    in_response_to = o.get("in_response_to", REQUEST_ID)
    resp_id = "_" + uuid.uuid4().hex
    assertion_id = "_" + uuid.uuid4().hex
    status = o.get("status", "urn:oasis:names:tc:SAML:2.0:status:Success")

    attrs = "".join(
        f'<saml:Attribute Name="{n}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        + "".join(f"<saml:AttributeValue>{v}</saml:AttributeValue>" for v in vals)
        + "</saml:Attribute>"
        for n, vals in [
            ("email", [SUBJECT_EMAIL]),
            ("firstName", ["Jo"]),
            ("lastName", ["Bloggs"]),
            ("role", ["app-user", "app-admin"]),
        ]
    )
    xml = f"""<samlp:Response xmlns:samlp="{SAMLP}" xmlns:saml="{SAML}" ID="{resp_id}" Version="2.0"
 IssueInstant="{iso(issued)}" Destination="{o.get('destination', ACS_URL)}" InResponseTo="{in_response_to}">
<saml:Issuer>{issuer}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="{status}"/></samlp:Status>
<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{iso(issued)}">
<saml:Issuer>{issuer}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{SUBJECT_EMAIL}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{in_response_to}" NotOnOrAfter="{iso(not_on_or_after)}" Recipient="{o.get('recipient', ACS_URL)}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{iso(not_before)}" NotOnOrAfter="{iso(not_on_or_after)}">
<saml:AudienceRestriction><saml:Audience>{o.get('audience', SP_ENTITY)}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{iso(issued)}" SessionIndex="_session-{uuid.uuid4().hex[:12]}">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement>{attrs}</saml:AttributeStatement>
</saml:Assertion>
</samlp:Response>"""
    parser = etree.XMLParser(remove_blank_text=True)
    return etree.fromstring(xml.encode(), parser)


def _placeholder(parent, after_tag):
    """Insert a signxml placeholder straight after the Issuer, where the SAML
    schema requires ds:Signature to sit."""
    ph = etree.Element(f"{{{DS}}}Signature", nsmap={"ds": DS}, Id="placeholder")
    issuer = parent.find(after_tag)
    issuer.addnext(ph)


def sign_assertion(response, key, cert, sha1=False):
    assertion = response.find(f"{{{SAML}}}Assertion")
    _placeholder(assertion, f"{{{SAML}}}Issuer")
    signed = _signer(sha1).sign(assertion, key=key, cert=[cert], reference_uri="#" + assertion.get("ID"))
    response.replace(assertion, signed)
    return response


def sign_response(response, key, cert, sha1=False):
    _placeholder(response, f"{{{SAML}}}Issuer")
    return _signer(sha1).sign(response, key=key, cert=[cert], reference_uri="#" + response.get("ID"))


def xml_bytes(root):
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def metadata_xml(certs):
    keys = "".join(
        f'<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{cert_b64(c)}'
        "</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        for c in certs
    )
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n<md:EntityDescriptor xmlns:md="{MD}" xmlns:ds="{DS}" '
        f'entityID="{IDP_ENTITY}"><md:IDPSSODescriptor protocolSupportEnumeration="{SAMLP}">{keys}'
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
        'Location="https://idp.example.com/realms/example/protocol/saml"/>'
        "</md:IDPSSODescriptor></md:EntityDescriptor>\n"
    ).encode()


# ---------------------------------------------------------------- JWT


def _b64url(data):
    if not isinstance(data, bytes):
        data = json.dumps(data, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def id_token_claims(now, **overrides):
    claims = {
        "iss": IDP_ENTITY,
        "sub": SUBJECT_UUID,
        "aud": CLIENT_ID,
        "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
        "iat": int((now - dt.timedelta(seconds=5)).timestamp()),
        "auth_time": int((now - dt.timedelta(seconds=8)).timestamp()),
        "nonce": NONCE,
        "azp": CLIENT_ID,
        "typ": "ID",
        "email": SUBJECT_EMAIL,
        "email_verified": True,
        "name": "Jo Bloggs",
        "given_name": "Jo",
        "family_name": "Bloggs",
        "preferred_username": "jbloggs",
    }
    for k, v in overrides.items():
        if v is None:
            claims.pop(k, None)
        else:
            claims[k] = v
    return claims


def jwk_for(key, kid):
    pub = key.public_key().public_numbers()

    def b64int(n):
        return _b64url(n.to_bytes((n.bit_length() + 7) // 8, "big"))

    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": b64int(pub.n), "e": b64int(pub.e)}


# ---------------------------------------------------------------- the samples


class Writer:
    def __init__(self, out):
        self.out = out
        self.index = []

    def file(self, name, data):
        path = self.out / name
        path.write_bytes(data if isinstance(data, bytes) else data.encode())
        return path

    def sample(self, name, data, description, args, expect, runbook=None):
        self.file(name, data)
        meta = {"description": description, "args": args, "expect": expect}
        if runbook:
            meta["runbook"] = runbook
        self.file(name + ".meta.json", json.dumps(meta, indent=2) + "\n")
        self.index.append((name, description, args))


def generate(out, now):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    w = Writer(out)
    pki = TestPKI(now)
    cur_key, cur_cert = pki.signing["current"]

    # Trust material: what the SP has configured.
    w.file("test-ca.pem", pem(pki.ca_cert))
    for state, (key, cert) in pki.signing.items():
        w.file(f"idp-{state}.pem", pem(cert))
        w.file(f"idp-{state}.key.pem", key_pem(key))
    w.file("idp-metadata.xml", metadata_xml([cur_cert]))
    w.file("idp-metadata-expired.xml", metadata_xml([pki.signing["expired"][1]]))
    w.file("idp-metadata-future.xml", metadata_xml([pki.signing["future"][1]]))

    md = ["--metadata", "{dir}/idp-metadata.xml"]

    def signed(resp, assertion=True, response=False, state="current", sha1=False):
        key, cert = pki.signing[state]
        if assertion:
            sign_assertion(resp, key, cert, sha1)
        if response:
            resp = sign_response(resp, key, cert, sha1)
        return resp

    # Valid response in every input encoding.
    valid = xml_bytes(signed(build_response(now)))
    ok = {"saml.signature.assertion": "PASS", "saml.signature.coverage": "PASS", "saml.cert.validity": "PASS",
          "saml.time.not_on_or_after": "PASS", "saml.audience": "PASS"}
    w.sample("saml-valid.xml", valid, "Valid response, assertion signed, raw XML", md + SAML_EXPECT, ok)
    post = base64.b64encode(valid).decode()
    w.sample("saml-valid.b64", post + "\n", "Valid response, HTTP-POST binding (base64)", md + SAML_EXPECT, ok)
    deflated = base64.b64encode(zlib.compress(valid)[2:-4]).decode()
    w.sample(
        "saml-valid-redirect.txt",
        f"{ACS_URL}?SAMLResponse={urllib.parse.quote(deflated)}&RelayState=%2F\n",
        "Valid response, HTTP-Redirect binding (deflate) in a URL",
        md + SAML_EXPECT,
        ok,
    )
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "generate_samples.py", "version": "1"},
            "entries": [
                {
                    "startedDateTime": iso(now),
                    "request": {
                        "method": "GET",
                        "url": "https://idp.example.com/realms/example/protocol/saml?SAMLRequest=fZJNb4MwDIb%2F",
                        "headers": [],
                        "queryString": [],
                    },
                    "response": {"status": 200, "content": {"mimeType": "text/html", "text": "<html>login</html>"}},
                },
                {
                    "startedDateTime": iso(now),
                    "request": {
                        "method": "POST",
                        "url": ACS_URL,
                        "headers": [{"name": "Content-Type", "value": "application/x-www-form-urlencoded"}],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "text": "SAMLResponse=" + urllib.parse.quote(post, safe="") + "&RelayState=%2F",
                            "params": [
                                {"name": "SAMLResponse", "value": urllib.parse.quote(post, safe="")},
                                {"name": "RelayState", "value": "%2F"},
                            ],
                        },
                    },
                    "response": {"status": 302, "content": {"text": ""}},
                },
            ],
        }
    }
    w.sample("saml-valid.har", json.dumps(har, indent=1), "Valid response inside a browser HAR capture", md + SAML_EXPECT, ok)
    tracer = {
        "requests": [
            {"method": "POST", "url": ACS_URL, "post": [["SAMLResponse", post], ["RelayState", "/"]], "protocol": "SAML-P"}
        ],
        "timestamp": int(now.timestamp() * 1000),
    }
    w.sample("saml-valid.saml-tracer.json", json.dumps(tracer, indent=1), "Valid response in a SAML-tracer export", md + SAML_EXPECT, ok)

    # Signature placement.
    w.sample(
        "saml-signed-response.xml",
        xml_bytes(signed(build_response(now), assertion=False, response=True)),
        "Only the Response is signed (assertion unsigned); valid",
        md + SAML_EXPECT,
        {"saml.signature.response": "PASS", "saml.signature.assertion": "SKIP", "saml.signature.coverage": "PASS"},
    )
    w.sample(
        "saml-signed-both.xml",
        xml_bytes(signed(build_response(now), assertion=True, response=True)),
        "Response and assertion both signed; valid",
        md + SAML_EXPECT,
        {"saml.signature.response": "PASS", "saml.signature.assertion": "PASS", "saml.signature.coverage": "PASS"},
    )
    w.sample(
        "saml-unsigned.xml",
        xml_bytes(build_response(now)),
        "Neither Response nor assertion signed",
        md + SAML_EXPECT,
        {"saml.signature.assertion": "FAIL", "saml.signature.coverage": "FAIL"},
    )
    tampered = signed(build_response(now))
    tampered.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    w.sample(
        "saml-tampered.xml",
        xml_bytes(tampered),
        "Assertion edited after signing (NameID changed): digest mismatch",
        md + SAML_EXPECT,
        {"saml.signature.assertion": "FAIL", "saml.signature.coverage": "FAIL"},
    )

    # XML signature wrapping: an unsigned forged assertion is placed before the
    # genuinely signed one, so a naive SP reads the forgery.
    xsw = signed(build_response(now))
    genuine = xsw.find(f"{{{SAML}}}Assertion")
    forged = copy.deepcopy(genuine)
    forged.remove(forged.find(f"{{{DS}}}Signature"))
    forged.set("ID", "_" + uuid.uuid4().hex)
    forged.find(f".//{{{SAML}}}NameID").text = "admin@example.com"
    genuine.addprevious(forged)
    w.sample(
        "saml-xsw.xml",
        xml_bytes(xsw),
        "Signature wrapping: forged unsigned assertion placed before the signed one",
        md + SAML_EXPECT,
        {"saml.signature.assertion": "FAIL", "saml.signature.coverage": "FAIL"},
    )

    # Certificates.
    w.sample(
        "saml-expired-cert.xml",
        xml_bytes(signed(build_response(now), state="expired")),
        "Signed with an expired IdP certificate (metadata still lists it)",
        ["--metadata", "{dir}/idp-metadata-expired.xml"] + SAML_EXPECT,
        {"saml.signature.assertion": "PASS", "saml.cert.validity": "FAIL", "saml.cert.metadata_match": "PASS"},
        runbook="01-expired-signing-cert",
    )
    w.sample(
        "saml-future-cert.xml",
        xml_bytes(signed(build_response(now), state="future")),
        "Signed with a certificate that is not valid yet",
        ["--metadata", "{dir}/idp-metadata-future.xml"] + SAML_EXPECT,
        {"saml.cert.validity": "FAIL"},
    )
    w.sample(
        "saml-rotated-cert.xml",
        xml_bytes(signed(build_response(now), state="rotated")),
        "IdP signed with a new key; SP metadata still has the old certificate",
        md + SAML_EXPECT,
        {"saml.signature.assertion": "FAIL", "saml.cert.metadata_match": "FAIL"},
        runbook="01-expired-signing-cert",
    )
    w.sample(
        "saml-sha1.xml",
        xml_bytes(signed(build_response(now), sha1=True)),
        "Signed with RSA-SHA1 and a SHA-1 digest",
        md + SAML_EXPECT,
        {"saml.signature.assertion": "PASS", "saml.signature.algorithm": "WARN"},
    )

    # Timing.
    w.sample(
        "saml-expired-assertion.xml",
        xml_bytes(signed(build_response(now, issued=now - dt.timedelta(hours=3)))),
        "Assertion issued 3 hours ago (replayed or stale capture)",
        md + SAML_EXPECT,
        {"saml.time.not_on_or_after": "FAIL"},
    )
    w.sample(
        "saml-skew-expired.xml",
        xml_bytes(signed(build_response(now, issued=now - dt.timedelta(minutes=10)))),
        "Expired a few minutes ago: looks like the SP clock is ahead",
        md + SAML_EXPECT,
        {"saml.time.not_on_or_after": "FAIL"},
        runbook="02-clock-skew",
    )
    ahead = now + dt.timedelta(minutes=3)
    w.sample(
        "saml-skew-future.xml",
        xml_bytes(signed(build_response(now, issued=ahead, not_before=ahead))),
        "NotBefore 3 minutes in the future: IdP clock ahead of the SP",
        md + SAML_EXPECT,
        {"saml.time.not_before": "FAIL"},
        runbook="02-clock-skew",
    )
    slight = now + dt.timedelta(seconds=30)
    w.sample(
        "saml-skew-within.xml",
        xml_bytes(signed(build_response(now, issued=slight, not_before=slight))),
        "NotBefore 30 seconds in the future: inside the default 60 s skew allowance",
        md + SAML_EXPECT,
        {"saml.time.not_before": "WARN"},
    )

    # Values that do not match the SP's configuration.
    for name, override, check, desc in [
        ("saml-wrong-audience.xml", {"audience": "https://sp-old.example.com/saml/metadata"}, "saml.audience",
         "Audience is the SP's old entity ID"),
        ("saml-wrong-destination.xml", {"destination": "http://sp.example.com/saml/acs",
                                        "recipient": "http://sp.example.com/saml/acs"}, "saml.destination",
         "Destination and Recipient use http:// while the SP expects https://"),
        ("saml-wrong-issuer.xml", {"issuer": "https://idp.example.com/realms/other"}, "saml.issuer",
         "Issued by a different IdP realm"),
        ("saml-wrong-in-response-to.xml", {"in_response_to": "_req-stale0001"}, "saml.in_response_to",
         "InResponseTo refers to a different (stale) AuthnRequest"),
    ]:
        expect = {check: "FAIL"}
        if check == "saml.destination":
            expect["saml.recipient"] = "FAIL"
        w.sample(name, xml_bytes(signed(build_response(now, **override))), desc, md + SAML_EXPECT, expect)

    w.sample(
        "saml-status-responder.xml",
        xml_bytes(signed(build_response(now, status="urn:oasis:names:tc:SAML:2.0:status:Responder"))),
        "IdP returned a Responder error status",
        md + SAML_EXPECT,
        {"saml.status": "FAIL"},
    )

    # ------------------------------------------------------------ JWT / OIDC
    jwt_key = _rsa()
    old_key = _rsa()
    unknown_key = _rsa()
    kid, old_kid = "k-2026-04", "k-2025-10"
    jwks = {"keys": [jwk_for(jwt_key, kid), jwk_for(old_key, old_kid)]}
    w.file("jwks.json", json.dumps(jwks, indent=2) + "\n")
    w.file("jwt-signing.key.pem", key_pem(jwt_key))
    jw = ["--jwks", "{dir}/jwks.json"]

    def rs256(claims, key=jwt_key, headers=None):
        hdr = {"kid": kid} if headers is None else headers
        return jwt.encode(claims, key, algorithm="RS256", headers=hdr) + "\n"

    jok = {"jwt.signature": "PASS", "jwt.algorithm": "PASS", "jwt.kid": "PASS", "jwt.time.exp": "PASS",
           "jwt.issuer": "PASS", "jwt.audience": "PASS", "oidc.nonce": "PASS", "oidc.azp": "PASS"}
    valid_jwt = rs256(id_token_claims(now))
    w.sample("jwt-valid.txt", valid_jwt, "Valid RS256 ID token", jw + OIDC_EXPECT, jok)
    hours_ago = now - dt.timedelta(hours=3)
    w.sample(
        "jwt-expired.txt",
        rs256(id_token_claims(now, exp=int(hours_ago.timestamp()), iat=int((hours_ago - dt.timedelta(minutes=5)).timestamp()),
                              auth_time=int((hours_ago - dt.timedelta(minutes=5)).timestamp()))),
        "ID token that expired 3 hours ago",
        jw + OIDC_EXPECT,
        {"jwt.time.exp": "FAIL", "jwt.signature": "PASS"},
    )
    w.sample(
        "jwt-nbf-future.txt",
        rs256(id_token_claims(now, nbf=int((now + dt.timedelta(minutes=3)).timestamp()))),
        "nbf 3 minutes in the future: IdP clock ahead",
        jw + OIDC_EXPECT,
        {"jwt.time.nbf": "FAIL"},
        runbook="02-clock-skew",
    )
    w.sample(
        "jwt-iat-future.txt",
        rs256(id_token_claims(now, iat=int((now + dt.timedelta(minutes=3)).timestamp()),
                              exp=int((now + dt.timedelta(minutes=8)).timestamp()))),
        "iat 3 minutes in the future: IdP clock ahead",
        jw + OIDC_EXPECT,
        {"jwt.time.iat": "FAIL"},
        runbook="02-clock-skew",
    )
    w.sample(
        "jwt-short-lifetime.txt",
        rs256(id_token_claims(now, iat=int((now - dt.timedelta(seconds=15)).timestamp()),
                              exp=int((now - dt.timedelta(seconds=5)).timestamp()),
                              auth_time=int((now - dt.timedelta(seconds=16)).timestamp()))),
        "Issued with a 10 s lifetime, expired 5 s ago",
        jw + OIDC_EXPECT,
        {"jwt.time.exp": "WARN", "jwt.signature": "PASS"},
        runbook="16-api-bearer-401",
    )
    none_tok = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url(id_token_claims(now))}.\n"
    w.sample("jwt-alg-none.txt", none_tok, "Unsigned token with alg none", jw + OIDC_EXPECT,
             {"jwt.algorithm": "FAIL", "jwt.signature": "FAIL"})
    w.sample(
        "jwt-hs256.txt",
        jwt.encode(id_token_claims(now), "a-shared-secret-of-at-least-32-bytes!", algorithm="HS256") + "\n",
        "HS256 (shared secret) where RS256 is expected",
        jw + OIDC_EXPECT,
        {"jwt.algorithm": "FAIL"},
    )
    w.sample("jwt-no-kid.txt", rs256(id_token_claims(now), headers={}), "RS256 token with no kid header", jw + OIDC_EXPECT,
             {"jwt.kid": "WARN", "jwt.signature": "PASS"})
    w.sample(
        "jwt-unknown-kid.txt",
        rs256(id_token_claims(now), key=unknown_key, headers={"kid": "k-2026-10"}),
        "Signed with a new key whose kid is not in the JWKS file",
        jw + OIDC_EXPECT,
        {"jwt.kid": "FAIL", "jwt.signature": "FAIL"},
    )
    head, _, sig = valid_jwt.strip().split(".")
    forged = id_token_claims(now, sub="00000000-0000-0000-0000-000000000000", email="admin@example.com")
    w.sample("jwt-tampered.txt", f"{head}.{_b64url(forged)}.{sig}\n", "Claims edited after signing", jw + OIDC_EXPECT,
             {"jwt.signature": "FAIL"})
    w.sample("jwt-wrong-audience.txt", rs256(id_token_claims(now, aud="other-app", azp="other-app")),
             "Issued to a different client", jw + OIDC_EXPECT, {"jwt.audience": "FAIL", "oidc.azp": "SKIP"})
    w.sample("jwt-wrong-issuer.txt", rs256(id_token_claims(now, iss="https://idp.example.com:8443/realms/example")),
             "Issuer includes a port the RP does not expect", jw + OIDC_EXPECT, {"jwt.issuer": "FAIL"})
    w.sample("oidc-missing-nonce.txt", rs256(id_token_claims(now, nonce=None)), "ID token without a nonce",
             jw + OIDC_EXPECT, {"oidc.nonce": "FAIL"})
    w.sample("oidc-wrong-nonce.txt", rs256(id_token_claims(now, nonce="n-stale-value")),
             "ID token nonce does not match the login request", jw + OIDC_EXPECT, {"oidc.nonce": "FAIL"})
    w.sample("oidc-multi-aud-no-azp.txt", rs256(id_token_claims(now, aud=[CLIENT_ID, API_AUDIENCE], azp=None)),
             "Several audiences and no azp", jw + OIDC_EXPECT, {"oidc.azp": "WARN", "jwt.audience": "PASS"})
    w.sample("oidc-azp-mismatch.txt", rs256(id_token_claims(now, azp="other-app")),
             "azp names a different client", jw + OIDC_EXPECT, {"oidc.azp": "FAIL", "jwt.audience": "PASS"})
    w.sample("oidc-missing-claims.txt", rs256(id_token_claims(now, sub=None)),
             "ID token missing the required sub claim", jw + OIDC_EXPECT, {"oidc.required_claims": "FAIL"})
    access = rs256(
        {
            "iss": IDP_ENTITY,
            "sub": SUBJECT_UUID,
            "aud": API_AUDIENCE,
            "client_id": CLIENT_ID,
            "scope": "openid profile email",
            "exp": int((now + dt.timedelta(minutes=5)).timestamp()),
            "iat": int((now - dt.timedelta(seconds=5)).timestamp()),
            "jti": str(uuid.uuid4()),
        },
        headers={"kid": kid, "typ": "at+jwt"},
    )
    w.sample(
        "jwt-access-token.txt",
        access,
        "RFC 9068 access token (typ at+jwt) for an API",
        jw + ["--expect-issuer", IDP_ENTITY, "--expect-audience", API_AUDIENCE, "--expect-alg", "RS256"],
        {"jwt.signature": "PASS", "jwt.audience": "PASS", "oidc.nonce": "SKIP"},
    )
    jwe = ".".join([_b64url({"alg": "RSA-OAEP-256", "enc": "A256GCM", "kid": kid}),
                    _b64url(b"\x01" * 256), _b64url(b"\x02" * 12), _b64url(b"\x03" * 64), _b64url(b"\x04" * 16)])
    w.sample("jwt-encrypted.txt", jwe + "\n", "Encrypted ID token (JWE): cannot be decoded without the RP key",
             jw, {"jwt.encrypted": "WARN"})
    token_har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "generate_samples.py", "version": "1"},
            "entries": [
                {
                    "startedDateTime": iso(now),
                    "request": {"method": "POST", "url": "https://idp.example.com/realms/example/protocol/openid-connect/token",
                                "headers": []},
                    "response": {
                        "status": 200,
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"id_token": valid_jwt.strip(), "token_type": "Bearer", "expires_in": 300}),
                        },
                    },
                }
            ],
        }
    }
    w.sample("jwt-valid.har", json.dumps(token_har, indent=1), "Valid ID token inside a HAR token response",
             jw + OIDC_EXPECT, jok)

    _write_index(w, now)
    return out


def _write_index(w, now):
    lines = [
        "# Generated samples",
        "",
        f"Generated for {iso(now)} by scripts/generate_samples.py. Rebuild at any time;",
        "everything here is throwaway test material and is not committed.",
        "",
        "| Sample | What it shows | Command |",
        "|---|---|---|",
    ]
    for name, desc, args in w.index:
        cmd = " ".join(["token-inspector", f"samples/generated/{name}"] + [_shell(a) for a in args])
        cmd = cmd.replace("{dir}", "samples/generated")
        lines.append(f"| `{name}` | {desc} | `{cmd}` |")
    w.file("INDEX.md", "\n".join(lines) + "\n")


def _shell(arg):
    return arg if all(c.isalnum() or c in "-_./:{}" for c in arg) else f"'{arg}'"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out", default="samples/generated", help="output directory (default samples/generated)")
    parser.add_argument("--now", help="reference time, ISO 8601 UTC (default: current time)")
    args = parser.parse_args(argv)
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    if args.now:
        now = dt.datetime.fromisoformat(args.now.replace("Z", "+00:00")).astimezone(dt.UTC)
    out = generate(args.out, now)
    count = len(list(out.glob("*.meta.json")))
    print(f"wrote {count} samples to {out} (reference time {iso(now)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
