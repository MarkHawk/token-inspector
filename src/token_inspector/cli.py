"""Command-line entry point."""

import argparse

from token_inspector import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(prog="token-inspector")
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(argv)
    return 0
