"""Load trust material from local files and describe certificates.

Everything here reads files the user names. Nothing is fetched: a JWKS URL
or a metadata URL is never followed, which keeps the tool usable on an
air-gapped support laptop and means a pasted token cannot trigger traffic.
"""

import base64
import binascii
import json
import re
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from token_inspector.xmlsafe import XMLRejected, parse_xml

MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"

_PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL)


class KeyFileError(ValueError):
    """A certificate, metadata or JWKS file could not be used."""


@dataclass
class Metadata:
    entity_id: str
    signing_certs: list = field(default_factory=list)
    path: str = ""


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise KeyFileError(f"cannot read {path}: {exc.strerror}") from None


def cert_from_base64(text):
    """Parse the base64 body of an X509Certificate element."""
    try:
        der = base64.b64decode(re.sub(r"\s+", "", text), validate=True)
        return x509.load_der_x509_certificate(der)
    except (binascii.Error, ValueError):
        return None


def load_certs(path):
    """Load one or more certificates from a PEM, DER or bare base64 file."""
    data = _read(path)
    blocks = _PEM_RE.findall(data)
    if not blocks and data.lstrip()[:1] == b"<":
        raise KeyFileError(f"{path} is XML; pass SAML metadata with --metadata instead of --cert")
    try:
        if blocks:
            return [x509.load_pem_x509_certificate(b) for b in blocks]
        try:
            return [x509.load_der_x509_certificate(data)]
        except ValueError:
            cert = cert_from_base64(data.decode("ascii", errors="replace"))
            if cert:
                return [cert]
            raise
    except ValueError:
        raise KeyFileError(f"{path} does not contain a PEM, DER or base64 X.509 certificate") from None


def load_metadata(path):
    """Load the IdP entity ID and signing certificates from SAML metadata."""
    try:
        root = parse_xml(_read(path))
    except XMLRejected as exc:
        raise KeyFileError(f"{path}: {exc}") from None
    if root.tag == f"{{{MD}}}EntitiesDescriptor":
        entities = root.findall(f".//{{{MD}}}EntityDescriptor")
        idps = [e for e in entities if e.find(f"{{{MD}}}IDPSSODescriptor") is not None]
        if not idps:
            raise KeyFileError(f"{path}: no IdP EntityDescriptor found")
        root = idps[0]
    if root.tag != f"{{{MD}}}EntityDescriptor":
        raise KeyFileError(f"{path} is not SAML metadata (root element is {etree_name(root)})")
    descriptor = root.find(f"{{{MD}}}IDPSSODescriptor")
    if descriptor is None:
        raise KeyFileError(
            f"{path} has no IDPSSODescriptor; this looks like SP metadata, but the IdP's metadata is needed"
        )
    certs = []
    for kd in descriptor.findall(f"{{{MD}}}KeyDescriptor"):
        if kd.get("use") not in (None, "signing"):
            continue
        for el in kd.iterfind(f".//{{{DS}}}X509Certificate"):
            cert = cert_from_base64(el.text or "")
            if cert is not None:
                certs.append(cert)
    if not certs:
        raise KeyFileError(f"{path} lists no signing certificates")
    return Metadata(entity_id=root.get("entityID", ""), signing_certs=certs, path=str(path))


def load_jwks(path):
    """Load a JWKS document (or a single JWK) from a JSON file."""
    try:
        doc = json.loads(_read(path))
    except ValueError:
        raise KeyFileError(f"{path} is not valid JSON") from None
    if isinstance(doc, dict) and "keys" in doc and isinstance(doc["keys"], list):
        return doc
    if isinstance(doc, dict) and "kty" in doc:
        return {"keys": [doc]}
    raise KeyFileError(f"{path} is not a JWKS (expected an object with a 'keys' list)")


def etree_name(el):
    tag = el.tag if isinstance(el.tag, str) else "?"
    return tag.split("}", 1)[-1]


def fingerprint(cert, algorithm=None):
    digest = cert.fingerprint(algorithm or hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def key_description(public_key):
    if isinstance(public_key, rsa.RSAPublicKey):
        return f"RSA {public_key.key_size}"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return f"EC {public_key.curve.name}"
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519"
    return type(public_key).__name__


def cert_details(cert):
    """A plain dict describing a certificate, for the report."""
    try:
        sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "none"
    except Exception:  # unsupported algorithm in an odd certificate
        sig_alg = "unknown"
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": f"{cert.serial_number:X}",
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "self_signed": cert.subject == cert.issuer,
        "key": key_description(cert.public_key()),
        "signature_hash": sig_alg,
        "sha256_fingerprint": fingerprint(cert),
        "sha1_fingerprint": fingerprint(cert, hashes.SHA1()),
    }


def same_cert(a, b):
    return a.fingerprint(hashes.SHA256()) == b.fingerprint(hashes.SHA256())
