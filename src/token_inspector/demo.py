"""`token-inspector demo`: run the bundled samples and summarise each in a line.

The samples live in demo_samples/ (built by scripts/build_demo_samples.py).
Each is evaluated as at a fixed time, so the verdicts never change. Nothing
here touches the network: it is the normal CLI run over packaged files.
"""

import argparse
import contextlib
import importlib.resources
import io
import json
import os

from token_inspector.findings import Status

INTRO = "token-inspector demo: {n} bundled samples, checked offline as at the time each was captured"


def build_parser():
    p = argparse.ArgumentParser(
        prog="token-inspector demo",
        description="Run token-inspector on bundled samples. No network, no flags needed.",
    )
    p.add_argument("name", nargs="?", help="show the full report for one sample (valid, expired, rotation or xsw)")
    p.add_argument("--json", action="store_true", help="with a sample name, print its report as JSON")
    p.add_argument("--redact", action="store_true", help="with a sample name, mask personal data in its report")
    return p


@contextlib.contextmanager
def sample_dir():
    with importlib.resources.as_file(importlib.resources.files("token_inspector") / "demo_samples") as path:
        yield path


def load_samples(folder):
    return json.loads((folder / "demo.json").read_text())["samples"]


def sample_argv(folder, sample):
    where = folder / sample["name"]
    return [str(where / sample["file"]), *(a.replace("{dir}", str(where)) for a in sample["args"])]


def shown_command(sample):
    """The command a user would type in the sample's folder: file names, not install paths."""
    args = [a.replace("{dir}/", "") for a in sample["args"]]
    words = [w if w and " " not in w else repr(w) for w in ["token-inspector", sample["file"], *args]]
    return " ".join(words)


def one_line(report):
    """(status, text) summarising a report: its likely cause, or else the count and the first problem."""
    if report.likely_cause:
        failed = any(f.status == Status.FAIL for f in report.findings)
        return (Status.FAIL if failed else Status.WARN).value, f"likely cause: {report.likely_cause.label}"
    for status, noun in ((Status.FAIL, "problem"), (Status.WARN, "warning")):
        titles = [f.title for f in report.findings if f.status == status]
        if titles:
            more = f" +{len(titles) - 1} more" if len(titles) > 1 else ""
            return status.value, f"{len(titles)} {noun}{'s' if len(titles) != 1 else ''}: {titles[0]}{more}"
    return "PASS", "no problems found"


def run_demo(argv, stdout, stderr, cli):
    """cli is the token_inspector.cli module, passed in to avoid an import cycle."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if (args.json or args.redact) and not args.name:
        parser.error("--json and --redact need a sample name, for example: token-inspector demo xsw --json")
    with sample_dir() as folder:
        samples = load_samples(folder)
        names = [s["name"] for s in samples]
        if args.name:
            if args.name not in names:
                print(f"token-inspector demo: no sample {args.name!r}; choose from {', '.join(names)}", file=stderr)
                return cli.EXIT_ERROR
            sample = samples[names.index(args.name)]
            extra = (["--json"] if args.json else []) + (["--redact"] if args.redact else [])
            if not args.json:
                stdout.write(f"Demo sample {sample['name']}: {sample['title']}\n")
                stdout.write(f"Same as: {shown_command(sample)}\n\n")
            return cli.main([*sample_argv(folder, sample), *extra], stdout=stdout, stderr=stderr)

        stdout.write(INTRO.format(n=len(samples)) + "\n\n")
        width = max(len(n) for n in names)
        title_width = max(len(s["title"]) for s in samples)
        for sample in samples:
            report = cli.inspect(cli.build_parser().parse_args(sample_argv(folder, sample)))
            status, text = one_line(report)
            stdout.write(f"  {sample['name']:<{width}}  {sample['title']:<{title_width}}  {status}  {text}\n")
        stdout.write(f"\nFull report for one sample:  token-inspector demo <name>   e.g. token-inspector demo {names[-1]}\n")
        stdout.write("Try your own file:           token-inspector <file>\n")
    return cli.EXIT_OK
