"""Read the input and work out what it is.

A support ticket rarely contains a clean token. People paste the raw
SAMLResponse form value, a whole URL, a HAR file, a SAML-tracer export, the
auto-submit HTML page, or a bare JWT. This module unwraps all of those into
one or more Token objects and records how each was encoded, because "they
pasted the redirect binding value where a POST value was expected" is a real
diagnosis in its own right.
"""

import base64
import binascii
import html
import json
import re
import sys
import urllib.parse
import zlib
from dataclasses import dataclass

MAX_INPUT_BYTES = 50 * 1024 * 1024

ENC_RAW_XML = "raw XML"
ENC_POST = "base64 (HTTP-POST binding)"
ENC_REDIRECT = "deflate + base64 (HTTP-Redirect binding)"
ENC_JWT = "compact JWS (JWT)"
ENC_JWE = "compact JWE (encrypted JWT)"

TOKEN_PARAMS = ("SAMLResponse", "id_token", "access_token")

_JWS_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")
_JWE_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")
_HIDDEN_INPUT_RE = re.compile(
    r"""<input[^>]*name=["'](SAMLResponse|SAMLRequest)["'][^>]*value=["']([^"']+)["']""",
    re.IGNORECASE,
)
_B64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_\-\s]+$")


class InputError(ValueError):
    """The input could not be read or no token was found in it."""


@dataclass
class Token:
    kind: str  # "saml", "jwt" or "jwe"
    encoding: str  # one of the ENC_* labels
    payload: object  # XML bytes for SAML, compact string for JWT/JWE
    location: str  # where in the input it was found
    container: str = "pasted value"  # "HAR file", "SAML-tracer export", "URL", ...


def read_input(path=None, token=None, stdin=None):
    """Return the raw input bytes from --token, a file path, or stdin."""
    if token is not None:
        data = token.encode("utf-8")
    elif path and path != "-":
        try:
            with open(path, "rb") as fh:
                data = fh.read(MAX_INPUT_BYTES + 1)
        except OSError as exc:
            raise InputError(f"cannot read {path}: {exc.strerror}") from None
    else:
        stream = stdin if stdin is not None else sys.stdin
        if stream.isatty():
            raise InputError("no input: give a file, --token VALUE, or pipe a value on stdin")
        data = stream.buffer.read(MAX_INPUT_BYTES + 1) if hasattr(stream, "buffer") else stream.read().encode()
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"input is larger than {MAX_INPUT_BYTES // (1024 * 1024)} MB")
    if not data.strip():
        raise InputError("input is empty")
    return data


def detect(data):
    """Return every distinct token found in the input, in the order found."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    text = text.lstrip("﻿").strip()

    found = []
    container = "pasted value"
    if text[:1] in "{[":
        try:
            obj = json.loads(text)
        except ValueError:
            obj = None
        if obj is not None:
            container, raw = _from_json_document(obj)
            found.extend(raw)
            if not found:
                raise InputError(_nothing_in_json_message(container))
    if not found:
        if "SAMLRequest" in text and "SAMLResponse" not in text and not text.startswith("<"):
            raise InputError(
                "this contains a SAMLRequest (the SP's AuthnRequest), not a SAMLResponse; "
                "capture the IdP's POST back to the SP's ACS URL instead"
            )
        found.extend(_from_text(text, "input", bare_ok=True))

    tokens = []
    seen = set()
    errors = []
    for name, value, location, cont in found:
        try:
            token = classify(value, location)
        except InputError as exc:
            errors.append(str(exc))
            continue
        token.container = cont or container
        key = (token.kind, token.payload)
        if key in seen:
            continue
        seen.add(key)
        tokens.append(token)
    if not tokens:
        if errors:
            raise InputError(errors[0])
        raise InputError("no SAML response or JWT found in the input")
    return tokens


def classify(value, location="input"):
    """Decode a single value into a Token, or raise InputError."""
    value = value.strip()
    if "%" in value and re.search(r"%[0-9A-Fa-f]{2}", value):
        value = urllib.parse.unquote(value)
    compact = re.sub(r"\s+", "", value)

    if _JWE_RE.match(compact):
        return Token("jwe", ENC_JWE, compact, location)
    if _JWS_RE.match(compact) and _looks_like_jose_header(compact.split(".", 1)[0]):
        return Token("jwt", ENC_JWT, compact, location)
    if value.startswith("<"):
        return Token("saml", ENC_RAW_XML, value.encode("utf-8"), location)
    if _B64_CHARS_RE.match(value):
        raw = _b64decode(compact)
        if raw is not None:
            if raw.lstrip()[:1] == b"<":
                return Token("saml", ENC_POST, raw.lstrip(), location)
            try:
                inflated = zlib.decompress(raw, -15)
            except zlib.error:
                inflated = None
            if inflated is not None and inflated.lstrip()[:1] == b"<":
                return Token("saml", ENC_REDIRECT, inflated.lstrip(), location)
    raise InputError(
        f"{location}: not a SAML response (XML, base64 or deflated) or a JWT "
        "(three dot-separated base64url parts)"
    )


def _looks_like_jose_header(segment):
    raw = _b64decode(segment)
    if raw is None:
        return False
    try:
        header = json.loads(raw)
    except ValueError:
        return False
    return isinstance(header, dict) and "alg" in header


def _b64decode(value):
    padded = value + "=" * (-len(value) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(padded, validate=True) if decoder is base64.b64decode else decoder(padded)
        except (binascii.Error, ValueError):
            continue
    return None


def _from_text(text, location, bare_ok):
    """Find token values inside a piece of text: URL, form body, HTML or bare."""
    results = []
    for match in _HIDDEN_INPUT_RE.finditer(text):
        name, value = match.group(1), html.unescape(match.group(2))
        if name == "SAMLResponse":
            results.append((name, value, f"{location} (auto-submit form)", "HTML page"))
    if results:
        return results

    if any(f"{p}=" in text for p in TOKEN_PARAMS):
        parts = re.split(r"[?#]", text, maxsplit=2)
        query = "&".join(parts[1:]) if len(parts) > 1 else parts[0]
        container = "URL" if len(parts) > 1 else "form body"
        for name, value in urllib.parse.parse_qsl(query, keep_blank_values=False):
            if name in TOKEN_PARAMS:
                results.append((name, value, f"{location} ({name} parameter)", container))
        if results:
            return results

    if bare_ok:
        results.append(("value", text, location, None))
    elif _JWS_RE.match(text.strip()):
        results.append(("value", text.strip(), location, None))
    return results


def _from_json_document(obj):
    """Return (container label, found values) for a HAR, SAML-tracer or other JSON."""
    found = []
    if isinstance(obj, dict) and isinstance(obj.get("log"), dict) and "entries" in obj["log"]:
        for i, entry in enumerate(obj["log"].get("entries") or [], start=1):
            req = entry.get("request", {}) if isinstance(entry, dict) else {}
            where = f"HAR entry {i} ({req.get('method', '?')} {_strip_query(req.get('url', ''))})"
            _walk_json(entry, where, found, "HAR file")
        return "HAR file", found
    if isinstance(obj, dict) and isinstance(obj.get("requests"), list):
        for i, req in enumerate(obj["requests"], start=1):
            if not isinstance(req, dict):
                continue
            where = f"SAML-tracer request {i} ({req.get('method', '?')} {_strip_query(req.get('url', ''))})"
            _walk_json(req, where, found, "SAML-tracer export")
        return "SAML-tracer export", found
    _walk_json(obj, "JSON", found, "JSON document")
    return "JSON document", found


def _walk_json(node, where, found, container, depth=0):
    if depth > 40:
        return
    if isinstance(node, dict):
        name = node.get("name")
        if isinstance(name, str) and isinstance(node.get("value"), str):
            if name in TOKEN_PARAMS:
                found.append((name, node["value"], f"{where} ({name})", container))
            elif name.lower() == "authorization" and node["value"].lower().startswith("bearer "):
                found.append(("access_token", node["value"][7:], f"{where} (Authorization header)", container))
        for key, value in node.items():
            if key in TOKEN_PARAMS and isinstance(value, str):
                found.append((key, value, f"{where} ({key})", container))
            elif key == "saml" and isinstance(value, str) and value.lstrip().startswith("<"):
                found.append(("SAMLResponse", value, f"{where} (decoded message)", container))
            else:
                _walk_json(value, where, found, container, depth + 1)
    elif isinstance(node, list):
        if len(node) == 2 and node[0] in TOKEN_PARAMS and isinstance(node[1], str):
            found.append((node[0], node[1], f"{where} ({node[0]})", container))
            return
        for item in node:
            _walk_json(item, where, found, container, depth + 1)
    elif isinstance(node, str) and len(node) > 20:
        stripped = node.strip()
        if stripped[:1] in "{[":
            try:
                _walk_json(json.loads(stripped), where, found, container, depth + 1)
                return
            except ValueError:
                pass
        for name, value, location, _ in _from_text(stripped, where, bare_ok=False):
            found.append((name, value, location, container))


def _strip_query(url):
    return url.split("?", 1)[0].split("#", 1)[0]


def _nothing_in_json_message(container):
    if container == "HAR file":
        return (
            "no SAMLResponse, id_token or access_token found in this HAR file; check the "
            "capture covers the whole login (enable 'Preserve log') and includes the POST "
            "to the SP's ACS URL or the token response"
        )
    return f"no SAMLResponse, id_token or access_token found in this {container}"
