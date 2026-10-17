"""Verify each XML signature in a SAML message on its own.

An SP cares which element is signed, not just whether "the signature" is
valid, so every ds:Signature is verified separately against its parent and
the result records what it actually covered. That makes it possible to say
"the Response is signed but the Assertion is not", or "the signature is fine
but it covers a different assertion from the one you would read".

Signature maths and certificate validity are kept apart on purpose: the
verification time is set inside the certificate's own validity window, so an
expired certificate shows up as "signature valid, certificate expired"
rather than a single confusing failure. saml_checks reports the expiry.
"""

import datetime as dt
from dataclasses import dataclass

from signxml import DigestAlgorithm, SignatureConfiguration, SignatureMethod, XMLVerifier
from signxml.exceptions import InvalidDigest, InvalidInput, InvalidSignature, SignXMLException

from token_inspector.keys import cert_from_base64, same_cert
from token_inspector.saml_parse import DS, SAML, SAMLP

ALL_SIGNATURE_METHODS = frozenset(SignatureMethod)
ALL_DIGESTS = frozenset(DigestAlgorithm)

DIGEST_ERROR = "digest"  # the signed content changed after signing
KEY_ERROR = "key"  # signature does not match the key tried
MALFORMED = "malformed"  # signature element is broken or unsupported


@dataclass
class SignatureResult:
    location: str  # "response", "assertion" or "other"
    parent_id: str
    reference_uri: str
    signature_method: str
    digest_methods: list
    embedded_cert: object = None
    valid: bool = False
    signed_id: str = None  # ID of the element the signature actually covers
    verified_with: str = None  # "trusted" or "embedded"
    trusted_cert: object = None  # the trusted certificate that verified it
    embedded_valid: bool = None  # does the embedded cert verify it (when trusted failed)?
    error: str = None
    error_kind: str = None


def verify_signatures(message, trusted_certs=None):
    """Return one SignatureResult per ds:Signature in the message."""
    results = []
    for sig in message.root.iter(f"{{{DS}}}Signature"):
        results.append(_verify_one(message.root, sig, trusted_certs or []))
    return results


def _location(root, parent):
    if parent is root and parent.tag == f"{{{SAMLP}}}Response":
        return "response"
    if parent.tag == f"{{{SAML}}}Assertion":
        return "assertion"
    return "other"


def _verify_one(root, sig, trusted):
    parent = sig.getparent()
    signed_info = sig.find(f"{{{DS}}}SignedInfo")
    method = signed_info.find(f"{{{DS}}}SignatureMethod") if signed_info is not None else None
    refs = signed_info.findall(f"{{{DS}}}Reference") if signed_info is not None else []
    embedded = None
    cert_el = sig.find(f"{{{DS}}}KeyInfo/{{{DS}}}X509Data/{{{DS}}}X509Certificate")
    if cert_el is not None:
        embedded = cert_from_base64(cert_el.text or "")

    result = SignatureResult(
        location=_location(root, parent),
        parent_id=parent.get("ID"),
        reference_uri=refs[0].get("URI") if refs else None,
        signature_method=method.get("Algorithm") if method is not None else None,
        digest_methods=[
            d.get("Algorithm") for r in refs for d in r.findall(f"{{{DS}}}DigestMethod") if d.get("Algorithm")
        ],
        embedded_cert=embedded,
    )

    if trusted:
        for cert in trusted:
            ok, err_kind, err, signed_id = _try(parent, cert)
            if ok:
                result.valid, result.signed_id, result.verified_with, result.trusted_cert = True, signed_id, "trusted", cert
                return result
            if err_kind != KEY_ERROR:
                # A digest or structural failure does not depend on which key
                # we tried, so trying more keys would only hide it.
                result.error, result.error_kind = err, err_kind
                return result
            result.error, result.error_kind = err, err_kind
        # No trusted key matched. Find out whether the signature is at least
        # internally consistent, which separates "key rotated" from "forged".
        if embedded is not None and not any(same_cert(embedded, c) for c in trusted):
            ok, _, _, signed_id = _try(parent, embedded)
            result.embedded_valid = ok
            if ok:
                result.signed_id = signed_id
        return result

    if embedded is None:
        result.error, result.error_kind = "no certificate supplied and none embedded in the signature", MALFORMED
        return result
    ok, err_kind, err, signed_id = _try(parent, embedded)
    result.valid, result.error, result.error_kind, result.signed_id = ok, err, err_kind, signed_id
    result.verified_with = "embedded" if ok else None
    result.embedded_valid = ok
    return result


def _try(parent, cert):
    """Verify the signature that is a direct child of parent with one cert."""
    when = cert.not_valid_before_utc + (cert.not_valid_after_utc - cert.not_valid_before_utc) / 2
    config = SignatureConfiguration(
        location="./",
        signature_methods=ALL_SIGNATURE_METHODS,
        digest_algorithms=ALL_DIGESTS,
        verification_time=when.astimezone(dt.UTC),
    )
    try:
        res = XMLVerifier().verify(parent, x509_cert=cert, expect_config=config)
    except InvalidDigest as exc:
        return False, DIGEST_ERROR, str(exc), None
    except InvalidSignature as exc:
        return False, KEY_ERROR, str(exc), None
    except (InvalidInput, SignXMLException, ValueError) as exc:
        return False, MALFORMED, str(exc), None
    signed = res.signed_xml
    return True, None, None, signed.get("ID") if signed is not None else None
