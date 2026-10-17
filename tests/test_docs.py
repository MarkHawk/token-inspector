"""The README's quick start works as written, and docs/usage.md lists every flag."""

import io
import re
import shlex

from conftest import ROOT
from token_inspector import demo
from token_inspector.cli import build_parser, main

README = (ROOT / "README.md").read_text()
USAGE = (ROOT / "docs" / "usage.md").read_text()


def section(text, heading):
    return text.split(f"## {heading}\n", 1)[1].split("\n## ", 1)[0]


def code_blocks(text):
    return re.findall(r"```\n(.*?)```", text, re.S)


def test_quick_start_comes_first():
    assert re.findall(r"^## .*", README, re.M)[0] == "## Try it in 1 minute"


def test_quick_start_install_is_three_commands():
    install = code_blocks(section(README, "Try it in 1 minute"))[0]
    assert len(install.strip().splitlines()) == 3


def test_quick_start_shows_the_demo_first_with_its_real_output():
    blocks = code_blocks(section(README, "Try it in 1 minute"))
    assert blocks[1] == "token-inspector demo\n"
    out = io.StringIO()
    main(["demo"], stdout=out, stderr=io.StringIO())
    assert blocks[2] == out.getvalue()


def test_lab_example_uses_the_suggested_now_and_shows_real_output():
    quick = section(README, "Try it in 1 minute")
    lab = quick.split("### Try a real lab capture\n", 1)[1]
    command, shown = code_blocks(lab)[:2]
    words = shlex.split(command)
    assert words[0] == "token-inspector" and words[2:] == ["--now", words[3]]
    report = io.StringIO()
    main([str(ROOT / words[1])], stdout=report, stderr=io.StringIO())
    assert f"add --now {words[3]}." in " ".join(report.getvalue().split())  # the value the report suggests
    out = io.StringIO()
    main([str(ROOT / words[1]), *words[2:]], stdout=out, stderr=io.StringIO())
    out = out.getvalue()
    assert shown.splitlines()[0] in out  # the Note line
    likely = shown[shown.index("== Likely cause =="):]
    assert likely in out  # the whole Likely cause section and the verdict, verbatim
    explanation = lab.split("```")[2].strip()  # the text between the command and its output
    assert explanation.startswith("`--now`") and explanation.count(". ") == 0  # one sentence


def test_usage_lists_every_option():
    options = [o for a in build_parser()._actions for o in a.option_strings if o.startswith("--")]
    options += [o for a in demo.build_parser()._actions for o in a.option_strings if o.startswith("--")]
    missing = [o for o in options if o not in ("--help",) and f"`{o}" not in USAGE]
    assert not missing


def test_usage_lists_every_demo_sample():
    for s in demo.load_samples(ROOT / "src" / "token_inspector" / "demo_samples"):
        assert f"| `{s['name']}` |" in USAGE


def test_no_em_dashes_in_docs():
    for path in [ROOT / "README.md", *(ROOT / "docs").glob("*.md")]:
        assert "\u2014" not in path.read_text(), path.name
