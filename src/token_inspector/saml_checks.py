"""SAML checks. Each returns a Finding with a plain-English summary and,
when something is wrong, what to check next."""

from token_inspector import runbooks
from token_inspector.common import expiry_finding, match_finding, not_before_finding
from token_inspector.findings import Finding, Status
from token_inspector.keys import cert_details, fingerprint, same_cert
from token_inspector.saml_parse import NAMEID_FORMATS
from token_inspector.saml_verify import DIGEST_ERROR, KEY_ERROR
from token_inspector.timefmt import duration, utc

STATUS_PREFIX = "urn:oasis:names:tc:SAML:2.0:status:"
STATUS_HELP = {
    "Requester": "the IdP says the SP's request was at fault",
    "Responder": "the IdP could not complete the login on its side",
    "VersionMismatch": "the IdP does not support the SAML version requested",
    "AuthnFailed": "the user did not authenticate successfully at the IdP",
    "InvalidNameIDPolicy": "the SP asked for a NameID format the IdP will not send for this app",
    "NoAuthnContext": "the SP asked for an authentication method (for example MFA) the IdP could not satisfy",
    "NoPassive": "the SP asked for a silent login but the user needed to sign in",
    "RequestDenied": "the IdP refused the request, often because the user is not assigned to this app",
    "RequestUnsupported": "the IdP does not support something in the request",
    "UnknownPrincipal": "the IdP does not know this user",
}

SHA1_URIS = (
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
    "http://www.w3.org/2000/09/xmldsig#sha1",
)
WEAK_URIS = ("http://www.w3.org/2001/04/xmldsig-more#rsa-md5", "http://www.w3.org/2001/04/xmldsig-more#md5")

EXPIRY_WARNING_DAYS = 30


def short_id(value):
    """Element IDs are long random strings; sentences show only the first
    8 characters after any leading underscore, e.g. _64da56e1..."""
    if value is None:
        return value
    keep = 8 + value.startswith("_")
    return value if len(value) <= keep + 1 else value[:keep] + "\u2026"


def short_alg(uri):
    return uri.rsplit("#", 1)[-1] if uri else "unknown"


def run_saml_checks(msg, sigs, opts):
    a = msg.assertion
    findings = [status_check(msg)]
    if msg.encrypted_assertions and a is None:
        findings.append(
            Finding(
                "saml.encrypted",
                Status.WARN,
                "Encrypted assertion",
                "The assertion is encrypted, so only the Response envelope can be checked here.",
                "Decrypting needs the SP's private key, which this tool does not take. Ask the IdP admin to "
                "turn off assertion encryption temporarily, or check the SP's own logs after decryption.",
            )
        )
    findings += signature_checks(msg, sigs, opts)
    findings += cert_checks(sigs, opts)
    if a is not None:
        findings += time_checks(a, msg, opts)
    findings += value_checks(msg, opts)
    return findings


# ---------------------------------------------------------------- status


def status_check(msg):
    title = "Response status"
    if not msg.is_response:
        return Finding("saml.status", Status.SKIP, title, "Not a Response (a bare Assertion), so there is no status.")
    code = (msg.status_code or "").replace(STATUS_PREFIX, "")
    if code == "Success":
        return Finding("saml.status", Status.PASS, title, "Success.")
    sub = (msg.status_subcode or "").replace(STATUS_PREFIX, "")
    reason = STATUS_HELP.get(sub) or STATUS_HELP.get(code) or "the IdP reported an error"
    shown = f"{code or 'missing'}" + (f" / {sub}" if sub else "")
    message = f" Message: {msg.status_message!r}." if msg.status_message else ""
    return Finding(
        "saml.status",
        Status.FAIL,
        title,
        f"The IdP returned {shown}: {reason}.{message}",
        "The login failed at the IdP, so the SP is not at fault. Check the IdP's event log for this user and "
        "time, and the app's settings there (user assignment, NameID format, required authentication).",
        details={"code": msg.status_code, "subcode": msg.status_subcode, "message": msg.status_message},
    )


# ---------------------------------------------------------------- signatures


def _sig_for(sigs, location, parent_id):
    for s in sigs:
        if s.location == location and s.parent_id == parent_id:
            return s
    return None


def signature_checks(msg, sigs, opts):
    a = msg.assertion
    response_sig = _sig_for(sigs, "response", msg.id) if msg.is_response else None
    assertion_sig = _sig_for(sigs, "assertion", a.id) if a is not None else None
    findings = []
    if msg.is_response:
        findings.append(_signature_finding("saml.signature.response", "Response signature", "Response",
                                           response_sig, assertion_sig is not None, len(sigs), opts))
    if a is not None:
        response_covers = response_sig is not None and response_sig.valid and response_sig.signed_id == msg.id
        if assertion_sig is None and not response_covers:
            # Nothing valid covers what the SP reads: that is a failure, not a skip.
            findings.append(Finding(
                "saml.signature.assertion",
                Status.FAIL,
                "Assertion signature",
                "The assertion an SP would read is not signed.",
                "A signature elsewhere in the message covers a different element: see Signature coverage."
                if any(s.valid for s in sigs)
                else "Turn on assertion signing for this app in the IdP.",
                details={"assertion_id": a.id},
            ))
        else:
            findings.append(_signature_finding("saml.signature.assertion", "Assertion signature", "Assertion",
                                               assertion_sig, response_sig is not None, len(sigs), opts))
    findings.append(_coverage_finding(msg, sigs, response_sig, assertion_sig))
    findings.append(_algorithm_finding(sigs))
    return findings


def _signature_finding(check_id, title, what, sig, other_signed, signature_count, opts):
    if sig is None:
        if other_signed:
            note = "That is normal when the " + ("Assertion" if what == "Response" else "Response") + " is signed."
        elif signature_count:
            note = "A signature elsewhere in the message covers a different element (see signature coverage)."
        else:
            note = "Nothing else is signed either (see signature coverage)."
        return Finding(check_id, Status.SKIP, title, f"The {what} is not signed. {note}")
    alg = short_alg(sig.signature_method)
    if sig.valid and sig.verified_with == "trusted":
        return Finding(check_id, Status.PASS, title,
                       f"Valid {alg} signature, verified with the certificate from {opts.trust_source}.",
                       details={"algorithm": sig.signature_method})
    if sig.valid:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"The {alg} signature is mathematically valid, but only against the certificate embedded in the "
            "message, which anyone can put there.",
            "Pass --metadata (the IdP's metadata) or --cert (the certificate the SP trusts) to check it "
            "against the IdP's real certificate.",
            details={"algorithm": sig.signature_method},
        )
    if sig.error_kind == DIGEST_ERROR:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The {what} was changed after it was signed (digest mismatch).",
            "Something modified the XML between the IdP and the SP: a proxy or WAF rewriting the body, or a "
            "manual edit. Reformatting or pretty-printing the XML before pasting it breaks the digest too, so "
            "use the original base64 SAMLResponse value.",
            details={"error": sig.error, "tampered": True},
        )
    if sig.error_kind == KEY_ERROR and sig.embedded_valid:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The signature does not match the certificate from {opts.trust_source}. It was made with a different "
            "certificate (included in the message), so the IdP has most likely rotated its signing certificate "
            "and the SP still trusts the old one.",
            "Compare the SHA-256 fingerprints below. Give the SP the IdP's current certificate or refresh its "
            "copy of the IdP metadata.",
            runbooks.EXPIRED_SIGNING_CERT,
            details={"error": sig.error},
        )
    if sig.error_kind == KEY_ERROR:
        trusted_note = f"the certificate from {opts.trust_source}" if opts.trust_source else "the embedded certificate"
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The signature does not verify with {trusted_note}"
            + (" or with the certificate embedded in the message." if opts.trust_source else "."),
            "Treat the message as forged or corrupted. Capture it again directly at the SP and check nothing "
            "in between rewrites it.",
            details={"error": sig.error},
        )
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"The signature could not be checked: {sig.error}.",
        "The ds:Signature element is malformed or uses an unsupported algorithm. Check the IdP's signing "
        "settings for this app.",
        details={"error": sig.error},
    )


def _coverage_finding(msg, sigs, response_sig, assertion_sig):
    check_id, title = "saml.signature.coverage", "Signature coverage"
    a = msg.assertion
    if not sigs:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            "Neither the Response nor the Assertion is signed. An SP must reject this.",
            "Turn on assertion signing (or response signing) for this app in the IdP. If the IdP says it is "
            "already signing, check this capture really came from the IdP and was not rebuilt by a proxy.",
        )
    if msg.duplicate_ids:
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"Several elements share the ID {short_id(msg.duplicate_ids[0])}, so a signature reference is ambiguous. "
            "This is a known signature wrapping technique.",
            "Treat the message as forged. No IdP produces duplicate IDs.",
            details={"duplicate_ids": msg.duplicate_ids},
        )
    if a is None:
        if response_sig is not None and response_sig.valid:
            return Finding(check_id, Status.PASS, title, "The Response is covered by a valid signature.")
        return Finding(check_id, Status.FAIL, title, "No valid signature covers the Response.",
                       "See the signature results above.")

    covered_by = []
    if response_sig is not None and response_sig.valid and response_sig.signed_id == msg.id:
        covered_by.append("Response")
    if assertion_sig is not None and assertion_sig.valid and assertion_sig.signed_id == a.id:
        covered_by.append("Assertion")
    other_valid = [s for s in sigs if s.valid and s not in (response_sig, assertion_sig)]
    extra = len(msg.assertions) - 1

    if not covered_by:
        if other_valid:
            target = other_valid[0].signed_id
            return Finding(
                check_id,
                Status.FAIL,
                title,
                f"The assertion an SP would read (ID {short_id(a.id)}, NameID {a.name_id!r}) is not covered by any "
                f"valid signature; the only valid signature covers a different element (ID {short_id(target)}). "
                "This is the "
                "shape of an XML Signature Wrapping (XSW) attack.",
                "Treat this as a forgery attempt and escalate it as a security incident. Check the SP's SAML "
                "library is current: patched libraries only read the element the signature covers.",
                details={"read_assertion_id": a.id, "signed_ids": [s.signed_id for s in sigs if s.valid]},
            )
        return Finding(check_id, Status.FAIL, title,
                       "No valid signature covers the assertion, so an SP must reject it.",
                       "See the signature results above for why each signature failed.")
    covered = " and ".join(covered_by)
    if extra:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"The assertion is covered by the {covered} signature, but the Response holds "
            f"{len(msg.assertions)} assertions. IdPs normally send exactly one.",
            "Check which assertion the SP actually reads. Unexpected extra assertions can be a wrapping attempt.",
        )
    return Finding(check_id, Status.PASS, title,
                   f"The assertion you read (ID {short_id(a.id)}) is covered by a valid {covered} signature.",
                   details={"assertion_id": a.id, "covered_by": covered_by})


def _algorithm_finding(sigs):
    check_id, title = "saml.signature.algorithm", "Signature algorithm"
    if not sigs:
        return Finding(check_id, Status.SKIP, title, "No signatures to check.")
    uris = []
    for s in sigs:
        uris += [s.signature_method] + list(s.digest_methods)
    weak = [u for u in uris if u in WEAK_URIS]
    sha1 = [u for u in uris if u in SHA1_URIS]
    used = ", ".join(sorted({short_alg(u) for u in uris if u}))
    if weak:
        return Finding(check_id, Status.FAIL, title, f"Uses MD5 ({used}), which is broken.",
                       "Set the IdP's signature algorithm for this app to RSA-SHA256.", details={"algorithms": uris})
    if sha1:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"Uses SHA-1 ({used}). SHA-1 is deprecated and many SPs and SAML libraries now reject it by default.",
            "Set the IdP's signature and digest algorithm for this app to SHA-256. If logins broke after an SP "
            "upgrade, this is a likely cause.",
            details={"algorithms": uris},
        )
    return Finding(check_id, Status.PASS, title, f"Uses {used}.", details={"algorithms": uris})


# ---------------------------------------------------------------- certificates


def signing_cert(sigs):
    """The certificate the IdP actually signed with: embedded, else the trusted one that verified."""
    for s in sigs:
        if s.embedded_cert is not None:
            return s.embedded_cert
    for s in sigs:
        if s.trusted_cert is not None:
            return s.trusted_cert
    return None


def cert_checks(sigs, opts):
    cert = signing_cert(sigs)
    return [_validity_finding(cert, opts), _trusted_validity_finding(cert, opts), _metadata_match_finding(cert, sigs, opts)]


def _validity_finding(cert, opts):
    check_id, title = "saml.cert.validity", "Signing certificate dates"
    if cert is None:
        return Finding(check_id, Status.SKIP, title, "No signing certificate to check.")
    d = cert_details(cert)
    nb, na = d["not_before"], d["not_after"]
    details = {"not_before": nb, "not_after": na, "sha256_fingerprint": d["sha256_fingerprint"]}
    if opts.now >= na:
        ago = (opts.now - na).total_seconds()
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The signing certificate expired on {utc(na)}, {duration(ago)} ago. SPs that check certificate "
            "dates reject every login signed with it.",
            "The IdP must sign with a current certificate and the SP must trust that new certificate. "
            "Check when logins started failing: if it matches the expiry time, this is the cause.",
            runbooks.EXPIRED_SIGNING_CERT,
            details,
        )
    if opts.now < nb:
        ahead = (nb - opts.now).total_seconds()
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The signing certificate is not valid until {utc(nb)}, {duration(ahead)} from now.",
            "The IdP has switched to a new certificate before its start date, or this machine's clock is wrong. "
            "Check the IdP's active signing key.",
            details=details,
        )
    left = (na - opts.now).total_seconds()
    if left < EXPIRY_WARNING_DAYS * 86400:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"The signing certificate expires on {utc(na)}, in {duration(left)}.",
            "Plan the rollover now: publish the new certificate in the IdP metadata and update every SP "
            "before this date.",
            runbooks.EXPIRED_SIGNING_CERT,
            details,
        )
    return Finding(check_id, Status.PASS, title, f"Valid until {utc(na)} (another {duration(left)}).",
                   details=details)


def _trusted_validity_finding(cert, opts):
    """The dates on the certificate(s) the SP trusts, independent of what signed
    this message. A pinned IdP certificate that has lapsed makes the SP reject
    every login, even one signed with a perfectly good new key."""
    check_id, title = "saml.cert.trusted_validity", "Trusted certificate dates"
    if not opts.trusted_certs:
        return Finding(check_id, Status.SKIP, title,
                       "Not checked: pass --metadata or --cert with the certificate the SP trusts.")
    described = [cert_details(t) for t in opts.trusted_certs]
    current = [d for d in described if d["not_before"] <= opts.now < d["not_after"]]
    if current:
        soonest = min(current, key=lambda d: d["not_after"])
        left = (soonest["not_after"] - opts.now).total_seconds()
        return Finding(check_id, Status.PASS, title,
                       f"The certificate the SP trusts is valid until {utc(soonest['not_after'])} "
                       f"(another {duration(left)}).",
                       details={"not_after": soonest["not_after"], "sha256_fingerprint": soonest["sha256_fingerprint"]})
    # Nothing the SP trusts is valid right now: an SP that checks dates has no usable IdP certificate.
    signer_differs = cert is not None and all(not same_cert(cert, t) for t in opts.trusted_certs)
    expired = [d for d in described if opts.now >= d["not_after"]]
    if expired:
        newest = max(expired, key=lambda d: d["not_after"])
        ago = (opts.now - newest["not_after"]).total_seconds()
        rotated = (" The IdP is now signing with a different certificate, so the SP must be given the IdP's "
                   "current certificate." if signer_differs
                   else " SPs that check certificate dates reject every login signed with it.")
        return Finding(
            check_id,
            Status.FAIL,
            title,
            f"The certificate the SP trusts (from {opts.trust_source}) expired on {utc(newest['not_after'])}, "
            f"{duration(ago)} ago.{rotated}",
            "Give the SP the IdP's current signing certificate, or refresh its copy of the IdP metadata, so it "
            "trusts the key the IdP signs with now.",
            runbooks.EXPIRED_SIGNING_CERT,
            details={"not_after": newest["not_after"], "sha256_fingerprint": newest["sha256_fingerprint"],
                     "signer_differs": signer_differs},
        )
    soonest = min(described, key=lambda d: d["not_before"])
    ahead = (soonest["not_before"] - opts.now).total_seconds()
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"The certificate the SP trusts (from {opts.trust_source}) is not valid until "
        f"{utc(soonest['not_before'])}, {duration(ahead)} from now.",
        "The SP was given a certificate before its start date, or this machine's clock is wrong. Check the SP's "
        "trusted IdP certificate and the clock.",
        details={"not_before": soonest["not_before"], "sha256_fingerprint": soonest["sha256_fingerprint"]},
    )


def _metadata_match_finding(cert, sigs, opts):
    check_id, title = "saml.cert.metadata_match", "Certificate matches trusted"
    if not opts.trusted_certs:
        return Finding(check_id, Status.SKIP, title,
                       "Not checked: pass --metadata or --cert to compare the signing certificate with the trusted one.")
    if cert is None:
        return Finding(check_id, Status.SKIP, title, "No signing certificate in the message to compare.")
    for i, trusted in enumerate(opts.trusted_certs, start=1):
        if same_cert(cert, trusted):
            which = f" (certificate {i} of {len(opts.trusted_certs)})" if len(opts.trusted_certs) > 1 else ""
            return Finding(check_id, Status.PASS, title, f"The signing certificate is the one in {opts.trust_source}{which}.")
    verified = any(s.valid and s.verified_with == "trusted" for s in sigs)
    trusted_fps = [fingerprint(c) for c in opts.trusted_certs]
    details = {"signing_sha256": fingerprint(cert), "trusted_sha256": trusted_fps}
    if verified:
        return Finding(
            check_id,
            Status.WARN,
            title,
            f"The certificate embedded in the message is not the one in {opts.trust_source}, but the signature "
            "still verifies with the trusted one (the same key in a reissued certificate).",
            "Usually harmless. Update the SP's copy so the two match before the old certificate expires.",
            details=details,
        )
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"The IdP signed with a certificate that is not in {opts.trust_source} "
        f"(signing SHA-256 {fingerprint(cert)[:23]}..., trusted {trusted_fps[0][:23]}...).",
        "The IdP has a new signing certificate the SP does not know about. Download the IdP's current metadata "
        "or certificate and update the SP.",
        runbooks.EXPIRED_SIGNING_CERT,
        details,
    )


# ---------------------------------------------------------------- timing


def time_checks(a, msg, opts):
    not_before = a.not_before.value if a.not_before else None
    attr = "Conditions NotBefore"
    if not_before is None and a.issue_instant:
        not_before, attr = a.issue_instant.value, "IssueInstant"
    findings = []
    for tv, name in ((a.not_before, "Conditions NotBefore"), (a.not_on_or_after, "Conditions NotOnOrAfter")):
        if tv is not None and not tv:
            findings.append(Finding(
                "saml.time.format",
                Status.FAIL,
                "Timestamp format",
                f"{name} is {tv.raw!r}, which is not a valid xs:dateTime.",
                "SAML times must look like 2026-03-02T12:00:00Z. Check the IdP's configuration or any custom "
                "assertion template.",
            ))
    if not_before is None:
        findings.append(Finding("saml.time.not_before", Status.SKIP, "Not before", "No NotBefore is set (it is optional)."))
    else:
        findings.append(not_before_finding("saml.time.not_before", "Not before", not_before, attr, opts,
                                           subject="The assertion"))

    # The earliest of the Conditions and bearer SubjectConfirmation expiries is the one that bites.
    candidates = []
    if a.not_on_or_after:
        candidates.append((a.not_on_or_after.value, "Conditions NotOnOrAfter"))
    for sc in a.subject_confirmations:
        if sc.not_on_or_after:
            candidates.append((sc.not_on_or_after.value, "SubjectConfirmationData NotOnOrAfter"))
    when, name = min(candidates, key=lambda c: c[0]) if candidates else (None, "NotOnOrAfter")
    issued = a.issue_instant.value if a.issue_instant else None
    findings.append(expiry_finding("saml.time.not_on_or_after", "Not on or after", when, name, opts,
                                   issued=issued, subject="The assertion", noun="the response"))
    return findings


# ---------------------------------------------------------------- values


def value_checks(msg, opts):
    a = msg.assertion
    findings = []

    expected_issuer, issuer_source = opts.expect_issuer, None
    if expected_issuer is None and opts.metadata_entity_id:
        expected_issuer, issuer_source = opts.metadata_entity_id, "the metadata entityID"
    issuers = [i for i in [msg.issuer if msg.is_response else None, a.issuer if a else None] if i]
    issuer_values = sorted(set(issuers)) if len(set(issuers)) > 1 else (issuers[0] if issuers else None)
    issuer = match_finding(
        "saml.issuer", "Issuer", issuer_values, expected_issuer, "--expect-issuer (or --metadata)", "the issuer",
        "The SP's configured IdP entity ID must exactly match the IdP's Issuer. Check which IdP (or realm or "
        "tenant) the user was sent to, and the IdP entity ID in the SP's settings.",
        issuer_source,
    )
    if issuer.status == Status.PASS and isinstance(issuer_values, list):
        issuer = Finding("saml.issuer", Status.FAIL, "Issuer",
                         f"The Response and Assertion issuers differ: {issuer_values}.",
                         "An IdP never does this. Check the message was not assembled from two sources.")
    findings.append(issuer)

    if a is not None:
        aud = match_finding(
            "saml.audience", "Audience", a.audiences, opts.expect_audience, "--expect-audience", "the audience",
            "The audience must be the SP's entity ID exactly. Check the SP entity ID (sometimes called Audience "
            "URI or Identifier) configured for this app at the IdP.",
        )
        if not a.audiences and opts.expect_audience is not None:
            aud.status = Status.WARN
            aud.summary = "The assertion has no AudienceRestriction, so it is not limited to this SP."
            aud.next_step = "Most SPs require an audience. Check the IdP's settings for this app."
        findings.append(aud)

    if msg.is_response:
        expected_dest = opts.expect_destination or opts.expect_recipient
        source = "--expect-recipient" if opts.expect_destination is None and opts.expect_recipient else None
        dest = match_finding(
            "saml.destination", "Destination", msg.destination, expected_dest, "--expect-destination",
            "the Destination", "The Destination must be the SP's ACS URL exactly, as the SP sees it. Check the "
            "ACS URL configured at the IdP, and whether a load balancer or proxy changes the scheme, host or port.",
            source,
        )
        if msg.destination is None and expected_dest is not None:
            dest.status = Status.WARN
            dest.summary = "The Response has no Destination attribute. Signed responses should include one."
            dest.next_step = "Some SPs reject this. Check the IdP's settings for this app."
        findings.append(dest)

    if a is not None:
        recipients = [sc.recipient for sc in a.subject_confirmations if sc.recipient]
        expected_rec = opts.expect_recipient or opts.expect_destination
        source = "--expect-destination" if opts.expect_recipient is None and opts.expect_destination else None
        findings.append(match_finding(
            "saml.recipient", "Recipient", recipients, expected_rec, "--expect-recipient",
            "the SubjectConfirmationData Recipient", "The Recipient must be the SP's ACS URL. Check the ACS URL "
            "configured at the IdP against the URL the browser actually posted to.",
            source,
        ))

    findings.append(_in_response_to_finding(msg, opts))
    return findings


def _in_response_to_finding(msg, opts):
    check_id, title = "saml.in_response_to", "InResponseTo"
    a = msg.assertion
    values = []
    if msg.is_response and msg.in_response_to:
        values.append(msg.in_response_to)
    if a is not None:
        values += [sc.in_response_to for sc in a.subject_confirmations if sc.in_response_to]
    if not values:
        return Finding(
            check_id,
            Status.SKIP if opts.expect_in_response_to is None else Status.FAIL,
            title,
            "No InResponseTo: this is an IdP-initiated login (started at the IdP, not the SP).",
            "SPs that only allow SP-initiated logins reject this. Start the login from the app instead, or "
            "allow IdP-initiated SSO at the SP." if opts.expect_in_response_to is not None else None,
        )
    if opts.expect_in_response_to is None:
        return Finding(check_id, Status.SKIP, title,
                       f"Not checked: InResponseTo is {values[0]!r}. Pass --expect-in-response-to with the "
                       "AuthnRequest ID from the SP's log to compare.")
    wrong = [v for v in values if v != opts.expect_in_response_to]
    if not wrong:
        return Finding(check_id, Status.PASS, title, f"Matches the AuthnRequest ID {opts.expect_in_response_to!r}.")
    return Finding(
        check_id,
        Status.FAIL,
        title,
        f"InResponseTo is {wrong[0]!r}, but the SP's request ID was {opts.expect_in_response_to!r}. "
        "The response answers a different login attempt.",
        "Usually the user started two logins (two tabs, the back button) or the SP lost the session that held "
        "the request ID: a blocked or SameSite cookie, or a load balancer without sticky sessions.",
    )


# ---------------------------------------------------------------- decoded view


def describe_saml(msg, sigs):
    """Sections of (label, value) pairs for the decoded part of the report."""
    sections = []
    if msg.is_response:
        status = (msg.status_code or "missing").replace(STATUS_PREFIX, "")
        if msg.status_subcode:
            status += " / " + msg.status_subcode.replace(STATUS_PREFIX, "")
        sections.append(("Response", [
            ("ID", msg.id),
            ("Issuer", msg.issuer),
            ("IssueInstant", msg.issue_instant.value if msg.issue_instant else None),
            ("Destination", msg.destination),
            ("InResponseTo", msg.in_response_to),
            ("Status", status),
            ("Assertions", f"{len(msg.assertions)}" + (f" (+{msg.encrypted_assertions} encrypted)"
                                                       if msg.encrypted_assertions else "")),
        ]))
    a = msg.assertion
    if a is not None:
        fmt = NAMEID_FORMATS.get(a.name_id_format, a.name_id_format)
        rows = [
            ("ID", a.id),
            ("Issuer", a.issuer),
            ("IssueInstant", a.issue_instant.value if a.issue_instant else None),
            ("NameID", a.name_id),
            ("NameID format", fmt),
        ]
        for sc in a.subject_confirmations:
            rows += [
                ("Confirmation", (sc.method or "").rsplit(":", 1)[-1]),
                ("  Recipient", sc.recipient),
                ("  InResponseTo", sc.in_response_to),
                ("  NotOnOrAfter", sc.not_on_or_after.value if sc.not_on_or_after else None),
            ]
        rows += [
            ("NotBefore", a.not_before.value if a.not_before else None),
            ("NotOnOrAfter", a.not_on_or_after.value if a.not_on_or_after else None),
            ("Audience", ", ".join(a.audiences) or None),
            ("AuthnInstant", a.authn_instant.value if a.authn_instant else None),
            ("AuthnContext", (a.authn_context or "").rsplit(":", 1)[-1] or None),
            ("SessionIndex", a.session_index),
        ]
        title = "Assertion" if len(msg.assertions) == 1 else f"Assertion (first of {len(msg.assertions)})"
        sections.append((title, rows))
        if a.attributes:
            sections.append(("Attributes", [(k, ", ".join(v)) for k, v in a.attributes.items()]))
    for s in sigs:
        rows = [
            ("Signed element", f"{s.location} (ID {s.parent_id})"),
            ("Covers", s.signed_id or "unknown"),
            ("Algorithm", ", ".join([short_alg(s.signature_method)] + [short_alg(d) for d in s.digest_methods])),
            ("Result", "valid" if s.valid else f"invalid ({s.error_kind})"),
        ]
        if s.embedded_cert is not None:
            d = cert_details(s.embedded_cert)
            rows += [
                ("Cert subject", d["subject"]),
                ("Cert issuer", d["issuer"] + (" (self-signed)" if d["self_signed"] else "")),
                ("Cert valid from", d["not_before"]),
                ("Cert valid until", d["not_after"]),
                ("Cert key", d["key"]),
                ("Cert SHA-256", d["sha256_fingerprint"]),
                ("Cert SHA-1", d["sha1_fingerprint"]),
            ]
        sections.append((f"Signature on {s.location}", rows))
    return sections
