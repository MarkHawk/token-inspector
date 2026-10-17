"""--redact: mask personal values so a report is safe to paste into a ticket.

The checks always run on the real values; masking is applied to the
finished report. Emails keep their domain, because the domain often
matters ("the user is in the wrong tenant"). Other values keep only their
first character.
"""

import copy
import re

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")

JWT_PERSONAL_CLAIMS = {
    "sub", "oid", "email", "name", "given_name", "family_name", "middle_name", "nickname",
    "preferred_username", "upn", "unique_name", "phone_number", "address", "birthdate",
}
SAML_PERSONAL_FIELDS = {"NameID"}
# Substrings of SAML attribute names (including claim URIs) that hold personal data.
ATTRIBUTE_MARKERS = ("mail", "name", "surname", "phone", "mobile", "upn", "uid", "employee", "user")
ATTRIBUTE_EXACT = {"sn", "cn"}


def mask(value):
    text = str(value)
    if EMAIL_RE.fullmatch(text):
        return EMAIL_RE.sub(r"\1***@\2", text)
    if len(text) <= 1:
        return "***"
    return text[0] + "***"


def _personal(section, label):
    label = label.strip()
    if section in ("Claims",):
        return label in JWT_PERSONAL_CLAIMS
    if section.startswith("Assertion"):
        return label in SAML_PERSONAL_FIELDS
    if section == "Attributes":
        low = label.lower()
        return low in ATTRIBUTE_EXACT or any(m in low for m in ATTRIBUTE_MARKERS)
    return False


def redact_report(report):
    """Return a copy of the report with personal values masked everywhere."""
    report = copy.deepcopy(report)
    replacements = {}
    sections = []
    for title, rows in report.sections:
        new_rows = []
        for label, value in rows:
            if value is not None and _personal(title, label):
                parts = [p.strip() for p in str(value).split(",")] if title == "Attributes" else [str(value)]
                masked = [mask(p) for p in parts]
                replacements.update({p: m for p, m in zip(parts, masked) if len(p) > 1})
                value = ", ".join(masked)
            new_rows.append((label, value))
        sections.append((title, new_rows))
    report.sections = sections
    # Whole words only, longest first, so "Jo Bloggs" goes before "Jo" and
    # "Jo" never eats the start of "Journey".
    patterns = [
        (re.compile(r"(?<!\w)" + re.escape(raw) + r"(?!\w)"), replacements[raw])
        for raw in sorted(replacements, key=len, reverse=True)
    ]

    def scrub(obj):
        if isinstance(obj, str):
            obj = EMAIL_RE.sub(r"\1***@\2", obj)
            for pattern, masked in patterns:
                obj = pattern.sub(masked, obj)
            return obj
        if isinstance(obj, list):
            return [scrub(x) for x in obj]
        if isinstance(obj, tuple):
            return tuple(scrub(x) for x in obj)
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        return obj

    report.sections = [(title, [(label, scrub(value)) for label, value in rows]) for title, rows in report.sections]
    for f in report.findings:
        f.summary = scrub(f.summary)
        f.next_step = scrub(f.next_step)
        f.details = scrub(f.details)
    report.redacted = True
    return report
