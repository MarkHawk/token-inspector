"""Render a Report as readable text."""

import datetime as dt
import json
import os
import textwrap

from token_inspector import __version__, runbooks
from token_inspector.findings import Status
from token_inspector.timefmt import utc, utc_relative

WIDTH = 100
KIND_LABEL = {"saml": "SAML Response", "jwt": "JWT", "jwe": "Encrypted JWT (JWE)"}
COLOURS = {Status.PASS: "32", Status.WARN: "33", Status.FAIL: "31;1", Status.SKIP: "2"}


def use_colour(stream):
    return hasattr(stream, "isatty") and stream.isatty() and "NO_COLOR" not in os.environ


def _value(v, now):
    if v is None:
        return "-"
    if isinstance(v, dt.datetime):
        return utc_relative(v, now)
    return str(v)


def render_text(report, colour=False):
    def paint(text, status):
        return f"\033[{COLOURS[status]}m{text}\033[0m" if colour else text

    out = [f"token-inspector {__version__}"]
    where = report.container if report.container != "pasted value" else "pasted value"
    out.append(f"Input:      {report.label or KIND_LABEL.get(report.kind, report.kind)}, {report.encoding}, {where}")
    if report.location not in ("input",):
        out.append(f"Found in:   {report.location}")
    if report.other_tokens:
        out.append(f"Note:       the input holds {report.other_tokens} more token(s); use --pick N to choose another")
    out.append(f"Checked at: {utc(report.now)}, clock skew allowance {report.skew} s")
    if report.redacted:
        out.append("Redacted:   emails, names, NameID and sub are masked")

    for title, rows in report.sections:
        out += ["", f"== {title} =="]
        width = max((len(label) for label, _ in rows), default=0)
        for label, value in rows:
            text = _value(value, report.now)
            lines = textwrap.wrap(text, WIDTH - width - 4, break_long_words=False, break_on_hyphens=False) or [text]
            out.append(f"  {label:<{width}}  {lines[0]}")
            out += [f"  {'':<{width}}  {line}" for line in lines[1:]]

    out += ["", "== Checks =="]
    width = max((len(f.title) for f in report.findings), default=0)
    indent = " " * (2 + 4 + 2 + width + 2)
    for f in report.findings:
        head = f"  {paint(f.status.value, f.status)}  {f.title:<{width}}  "
        body = textwrap.wrap(f.summary, WIDTH - len(indent), break_long_words=False, break_on_hyphens=False)
        out.append(head + body[0])
        out += [indent + line for line in body[1:]]
        if f.next_step and f.status in (Status.FAIL, Status.WARN):
            out += textwrap.wrap(f.next_step, WIDTH, initial_indent=indent + "Next: ", subsequent_indent=indent + "      ")
        if f.runbook:
            out.append(f"{indent}Runbook: identity-lab {f.runbook}")

    out += ["", verdict_line(report)]
    return "\n".join(out) + "\n"


def _plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def verdict_line(report):
    fails, warns = report.count(Status.FAIL), report.count(Status.WARN)
    counts = ", ".join(f"{report.count(s)} {s.value}" for s in (Status.FAIL, Status.WARN, Status.PASS, Status.SKIP))
    if fails:
        verdict = _plural(fails, "problem") + " to fix"
        if warns:
            verdict += ", " + _plural(warns, "warning") + " to review"
    elif warns:
        verdict = "no failures, " + _plural(warns, "warning") + " to review"
    else:
        verdict = "no problems found"
    return f"Verdict: {verdict} ({counts})"


def _json_value(v):
    if isinstance(v, dt.datetime):
        return v.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(v, Status):
        return v.value
    if isinstance(v, dict):
        return {str(k): _json_value(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_json_value(x) for x in v]
    if v is None or isinstance(v, (str, int, float, bool)):
        return v
    return str(v)


def report_dict(report):
    """A stable, machine-readable form of the report for --json."""
    return {
        "tool": "token-inspector",
        "version": __version__,
        "input": {
            "kind": report.kind,
            "label": report.label,
            "encoding": report.encoding,
            "container": report.container,
            "location": report.location,
            "other_tokens": report.other_tokens,
        },
        "checked_at": _json_value(report.now),
        "skew_seconds": report.skew,
        "redacted": report.redacted,
        "decoded": [
            {"section": title, "fields": [{"name": label.strip(), "value": _json_value(value)} for label, value in rows]}
            for title, rows in report.sections
        ],
        "findings": [
            {
                "check_id": f.check_id,
                "status": f.status.value,
                "title": f.title,
                "summary": f.summary,
                "next_step": f.next_step,
                "runbook": f.runbook,
                "runbook_url": runbooks.url(f.runbook) if f.runbook else None,
                "details": _json_value(f.details),
            }
            for f in report.findings
        ],
        "summary": {
            "fail": report.count(Status.FAIL),
            "warn": report.count(Status.WARN),
            "pass": report.count(Status.PASS),
            "skip": report.count(Status.SKIP),
            "verdict": verdict_line(report).removeprefix("Verdict: "),
            "exit_code": report.exit_code,
        },
    }


def render_json(report):
    return json.dumps(report_dict(report), indent=2, ensure_ascii=False) + "\n"
