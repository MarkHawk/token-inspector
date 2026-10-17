#!/usr/bin/env bash
# Capture sanitised SAML (and optionally OIDC) samples from a running
# identity-lab into samples/lab/<label>/. Read only: it signs in as a lab
# user like a browser would; it never changes the lab or reads its .env.
#
#   LAB_HOST=localhost scripts/capture_from_lab.sh [--label NAME] [--oidc] [--map-host]
#
# Environment:
#   LAB_HOST            the lab's LAB_HOST (required)
#   LAB_DIR             the lab checkout, for its CA certificate (default ~/identity-lab)
#   LAB_PASSWORD        the lab user's password (prompted for if unset)
#   OIDC_CLIENT_SECRET  the oidc-rp client secret, only with --oidc (prompted for if unset)
#
# To capture a broken scenario, break the lab yourself first (in the lab:
# scripts/break.sh <scenario>), then run this with --label <scenario>.
set -euo pipefail

cd "$(dirname "$0")/.."
LAB_DIR="${LAB_DIR:-$HOME/identity-lab}"
CA="$LAB_DIR/certs/ca.crt"
PY="venv/bin/python"

if [[ -z "${LAB_HOST:-}" ]]; then
  echo "capture_from_lab: set LAB_HOST to the lab's host name, e.g. LAB_HOST=localhost" >&2
  exit 2
fi
if [[ ! -x "$PY" ]]; then
  echo "capture_from_lab: no venv; run: python3 -m venv venv && venv/bin/pip install -r requirements-dev.txt" >&2
  exit 2
fi
if [[ ! -r "$CA" ]]; then
  echo "capture_from_lab: cannot read the lab CA certificate at $CA (set LAB_DIR)" >&2
  exit 2
fi

label="baseline"
args=("$@")
for ((i = 0; i < ${#args[@]}; i++)); do
  if [[ "${args[$i]}" == "--label" && $((i + 1)) -lt ${#args[@]} ]]; then
    label="${args[$((i + 1))]}"
  fi
done

"$PY" scripts/lab_capture.py --lab-host "$LAB_HOST" --ca "$CA" "$@"
# Belt and braces: scan what was written, decoding base64 and JWTs first.
"$PY" scripts/sanitise.py --check "samples/lab/$label"
echo "capture_from_lab: done. Review samples/lab/$label, then run the tests before committing it."
