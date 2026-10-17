#!/usr/bin/env python3
"""Make lab captures safe to commit, and check that they are.

Generic patterns only: private (RFC 1918) IPv4 addresses, home directory
paths other than /home/pi, and private key blocks. Extra personal strings
(a name, a hostname) come from a local, gitignored .personal-patterns file:
one string per line, matched as a whole word and case-sensitively (so a first
name does not match ordinary words that contain it); lines starting with
"re:" are regular expressions, so "re:(?i)..." ignores case; "#" starts a
comment. The committed .personal-patterns.example is deliberately empty.

Tokens are base64, so a private address can hide inside a SAMLResponse or a
JWT payload. The sanitiser therefore works on the decoded XML or JSON, and
the checker decodes base64 and JWT segments before scanning.

A change to signed content breaks the signature. Callers record that, so a
sanitised sample is never mistaken for a broken IdP.

    python scripts/sanitise.py --check samples/lab        # exit 1 if anything is found
"""

import argparse
import base64
import binascii
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PERSONAL_FILE = ROOT / ".personal-patterns"

RFC1918 = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?![\d.])"
)
HOME_DIR = re.compile(r"/home/(?!pi(?![A-Za-z0-9_.-]))[A-Za-z_][A-Za-z0-9_.-]*")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")

IP_REPLACEMENT = "192.0.2.10"  # RFC 5737 documentation range
HOME_REPLACEMENT = "~"
PERSONAL_REPLACEMENT = "redacted"

_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")


class UnsafeContent(ValueError):
    """Content that must never be written, such as a private key."""


def load_personal_patterns(path=PERSONAL_FILE):
    """Compiled patterns from the local file; an absent file means none."""
    path = pathlib.Path(path)
    if not path.exists():
        return []
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            patterns.append(re.compile(line[3:]))
        else:
            patterns.append(re.compile(r"(?<![A-Za-z0-9])" + re.escape(line) + r"(?![A-Za-z0-9])"))
    return patterns


def find_problems(text, personal=()):
    """Names of the pattern kinds found; never the matched values themselves."""
    found = []
    if RFC1918.search(text):
        found.append("private IPv4 address")
    if HOME_DIR.search(text):
        found.append("home directory path")
    if PRIVATE_KEY.search(text):
        found.append("private key")
    if any(p.search(text) for p in personal):
        found.append("personal pattern from .personal-patterns")
    return found


def sanitise_text(text, personal=(), host_map=None):
    """Return (text, changed). Raises UnsafeContent for private keys."""
    if PRIVATE_KEY.search(text):
        raise UnsafeContent("content contains a private key; refusing to write it")
    original = text
    for old, new in (host_map or {}).items():
        text = re.sub(re.escape(old), new, text, flags=re.IGNORECASE)
    text = RFC1918.sub(IP_REPLACEMENT, text)
    text = HOME_DIR.sub(HOME_REPLACEMENT, text)
    for p in personal:
        text = p.sub(PERSONAL_REPLACEMENT, text)
    return text, text != original


def sanitise_saml(xml_bytes, personal=(), host_map=None):
    """Sanitise a SAML message's XML. Unchanged input keeps its exact bytes,
    and therefore its signature."""
    text, changed = sanitise_text(xml_bytes.decode("utf-8"), personal, host_map)
    return (text.encode("utf-8") if changed else xml_bytes), changed


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def sanitise_jwt(compact, personal=(), host_map=None):
    """Sanitise a JWT's header and payload JSON. Unchanged input is returned
    as it was, so the signature stays valid."""
    parts = compact.strip().split(".")
    changed = False
    for i in (0, 1):
        decoded = _b64url_decode(parts[i]).decode("utf-8")
        clean, part_changed = sanitise_text(decoded, personal, host_map)
        if part_changed:
            json.loads(clean)  # still valid JSON
            parts[i] = _b64url(clean.encode("utf-8"))
            changed = True
    return ".".join(parts), changed


def decoded_views(text):
    """The text plus decoded forms of any base64 or JWT content inside it."""
    views = [text]
    for blob in _B64_BLOB.findall(text):
        for decoder in (base64.b64decode, _b64url_decode):
            try:
                raw = decoder(blob + "=" * (-len(blob) % 4)) if decoder is base64.b64decode else decoder(blob)
            except (binascii.Error, ValueError):
                continue
            try:
                views.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                pass
    for token in re.findall(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", text):
        for segment in token.split(".")[:2]:
            try:
                views.append(_b64url_decode(segment).decode("utf-8"))
            except (binascii.Error, ValueError, UnicodeDecodeError):
                pass
    return views


def check_paths(paths, personal=None):
    """Return a list of (file, problem kind) for everything under paths."""
    personal = load_personal_patterns() if personal is None else personal
    problems = []
    for root in paths:
        root = pathlib.Path(root)
        files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
        for f in files:
            text = f.read_bytes().decode("utf-8", errors="replace")
            kinds = set()
            for view in decoded_views(text):
                kinds.update(find_problems(view, personal))
            problems += [(str(f), k) for k in sorted(kinds)]
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check files contain nothing private before committing them.")
    parser.add_argument("--check", nargs="+", metavar="PATH", required=True, help="files or directories to scan")
    args = parser.parse_args(argv)
    problems = check_paths(args.check)
    for path, kind in problems:
        print(f"sanitise: {path}: contains a {kind}", file=sys.stderr)
    if problems:
        print("sanitise: refusing: fix or delete the files above before committing", file=sys.stderr)
        return 1
    print(f"sanitise: clean ({', '.join(args.check)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
