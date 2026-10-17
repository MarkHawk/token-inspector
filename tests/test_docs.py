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


def test_quick_start_command_has_no_flags_and_shows_what_the_readme_says():
    blocks = code_blocks(section(README, "Try it in 1 minute"))
    words = shlex.split(blocks[1])
    assert words[0] == "token-inspector" and len(words) == 2 and not words[1].startswith("-")
    out = io.StringIO()
    main([str(ROOT / words[1])], stdout=out, stderr=io.StringIO())
    shown = [line for line in blocks[2].splitlines() if line.startswith(("Note:", "Verdict:"))]
    assert len(shown) == 2
    for line in shown:
        assert line in out.getvalue()


def test_quick_start_mentions_the_demo():
    assert "token-inspector demo\n" in section(README, "Try it in 1 minute")


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
