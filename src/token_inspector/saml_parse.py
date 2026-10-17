"""Turn a SAML Response (or a bare Assertion) into a plain data model.

Parsing never decides whether something is right or wrong; saml_checks does
that. Parsing only records what the message says, including oddities such as
a second Assertion, so the checks can report on them.
"""

import datetime as dt
from dataclasses import dataclass, field

from token_inspector.xmlsafe import parse_xml

SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"

NAMEID_FORMATS = {
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress": "email address",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified": "unspecified",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent": "persistent (opaque, stable per SP)",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient": "transient (changes every login)",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName": "X.509 subject name",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos": "Kerberos principal",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:entity": "entity",
}


class SamlParseError(ValueError):
    """The XML is not a SAML Response we can report on."""


@dataclass
class TimeValue:
    raw: str
    value: object = None  # datetime, or None if the attribute was unparseable

    def __bool__(self):
        return self.value is not None


@dataclass
class SubjectConfirmation:
    method: str
    recipient: str = None
    in_response_to: str = None
    not_before: TimeValue = None
    not_on_or_after: TimeValue = None


@dataclass
class Assertion:
    element: object
    id: str
    issuer: str = None
    issue_instant: TimeValue = None
    name_id: str = None
    name_id_format: str = None
    subject_confirmations: list = field(default_factory=list)
    not_before: TimeValue = None
    not_on_or_after: TimeValue = None
    audiences: list = field(default_factory=list)
    authn_instant: TimeValue = None
    session_index: str = None
    session_not_on_or_after: TimeValue = None
    authn_context: str = None
    attributes: dict = field(default_factory=dict)


@dataclass
class SamlMessage:
    root: object
    is_response: bool
    id: str = None
    issuer: str = None
    issue_instant: TimeValue = None
    destination: str = None
    in_response_to: str = None
    status_code: str = None
    status_subcode: str = None
    status_message: str = None
    assertions: list = field(default_factory=list)
    encrypted_assertions: int = 0
    duplicate_ids: list = field(default_factory=list)

    @property
    def assertion(self):
        """The assertion a typical SP would read: the first one."""
        return self.assertions[0] if self.assertions else None


def parse_time(raw):
    if raw is None:
        return None
    text = raw.strip()
    try:
        value = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return TimeValue(raw)
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return TimeValue(raw, value.astimezone(dt.UTC))


def _text(el):
    return el.text.strip() if el is not None and el.text else None


def _q(ns, name):
    return f"{{{ns}}}{name}"


def parse_saml(xml_bytes):
    root = parse_xml(xml_bytes)
    tag = root.tag if isinstance(root.tag, str) else ""
    if tag == _q(SAMLP, "Response"):
        msg = _parse_response(root)
    elif tag == _q(SAML, "Assertion"):
        msg = SamlMessage(root=root, is_response=False)
        msg.assertions = [_parse_assertion(root)]
    elif tag in (_q(MD, "EntityDescriptor"), _q(MD, "EntitiesDescriptor")):
        raise SamlParseError("this is SAML metadata, not a response; pass it with --metadata FILE")
    elif tag == _q(SAMLP, "AuthnRequest"):
        raise SamlParseError(
            "this is an AuthnRequest (SP to IdP), not a Response; capture the IdP's POST back to the SP's ACS URL"
        )
    elif tag.startswith(f"{{{SAMLP}}}"):
        raise SamlParseError(f"this is a SAML {tag.split('}')[1]}, not a Response; only Responses are supported")
    else:
        raise SamlParseError(f"XML root element is {tag.split('}')[-1] or 'unknown'}, not a SAML Response")
    msg.duplicate_ids = _duplicate_ids(root)
    return msg


def _parse_response(root):
    msg = SamlMessage(
        root=root,
        is_response=True,
        id=root.get("ID"),
        issuer=_text(root.find(_q(SAML, "Issuer"))),
        issue_instant=parse_time(root.get("IssueInstant")),
        destination=root.get("Destination"),
        in_response_to=root.get("InResponseTo"),
    )
    status = root.find(_q(SAMLP, "Status"))
    if status is not None:
        code = status.find(_q(SAMLP, "StatusCode"))
        if code is not None:
            msg.status_code = code.get("Value")
            sub = code.find(_q(SAMLP, "StatusCode"))
            if sub is not None:
                msg.status_subcode = sub.get("Value")
        msg.status_message = _text(status.find(_q(SAMLP, "StatusMessage")))
    # Every Assertion anywhere in the document, in document order, so a
    # wrapped or hidden assertion is visible to the checks.
    msg.assertions = [_parse_assertion(a) for a in root.iter(_q(SAML, "Assertion"))]
    msg.encrypted_assertions = len(list(root.iter(_q(SAML, "EncryptedAssertion"))))
    return msg


def _parse_assertion(el):
    a = Assertion(
        element=el,
        id=el.get("ID"),
        issuer=_text(el.find(_q(SAML, "Issuer"))),
        issue_instant=parse_time(el.get("IssueInstant")),
    )
    subject = el.find(_q(SAML, "Subject"))
    if subject is not None:
        name_id = subject.find(_q(SAML, "NameID"))
        if name_id is not None:
            # itertext() so a comment inside the value cannot truncate it silently.
            a.name_id = "".join(name_id.itertext()).strip()
            a.name_id_format = name_id.get("Format")
        for sc in subject.findall(_q(SAML, "SubjectConfirmation")):
            data = sc.find(_q(SAML, "SubjectConfirmationData"))
            conf = SubjectConfirmation(method=sc.get("Method"))
            if data is not None:
                conf.recipient = data.get("Recipient")
                conf.in_response_to = data.get("InResponseTo")
                conf.not_before = parse_time(data.get("NotBefore"))
                conf.not_on_or_after = parse_time(data.get("NotOnOrAfter"))
            a.subject_confirmations.append(conf)
    conditions = el.find(_q(SAML, "Conditions"))
    if conditions is not None:
        a.not_before = parse_time(conditions.get("NotBefore"))
        a.not_on_or_after = parse_time(conditions.get("NotOnOrAfter"))
        a.audiences = [_text(x) for x in conditions.iter(_q(SAML, "Audience")) if _text(x)]
    authn = el.find(_q(SAML, "AuthnStatement"))
    if authn is not None:
        a.authn_instant = parse_time(authn.get("AuthnInstant"))
        a.session_index = authn.get("SessionIndex")
        a.session_not_on_or_after = parse_time(authn.get("SessionNotOnOrAfter"))
        a.authn_context = _text(authn.find(f"{_q(SAML, 'AuthnContext')}/{_q(SAML, 'AuthnContextClassRef')}"))
    for attr in el.iter(_q(SAML, "Attribute")):
        name = attr.get("FriendlyName") or attr.get("Name")
        values = ["".join(v.itertext()).strip() for v in attr.findall(_q(SAML, "AttributeValue"))]
        a.attributes.setdefault(name, []).extend(values)
    return a


def _duplicate_ids(root):
    seen, dupes = set(), []
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        value = el.get("ID")
        if value is None:
            continue
        if value in seen and value not in dupes:
            dupes.append(value)
        seen.add(value)
    return dupes
