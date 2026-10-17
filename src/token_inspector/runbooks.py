"""identity-lab runbooks that a finding can point to.

https://github.com/MarkHawk/identity-lab reproduces these failures on
purpose; each runbook explains symptom, diagnosis, fix and prevention.
"""

LAB_URL = "https://github.com/MarkHawk/identity-lab"

RUNBOOKS = {
    "01-expired-signing-cert": "Expired IdP signing certificate (SAML)",
    "02-clock-skew": "Clock skew between IdP and SP",
}

EXPIRED_SIGNING_CERT = "01-expired-signing-cert"
CLOCK_SKEW = "02-clock-skew"


def url(name):
    return f"{LAB_URL}/blob/main/runbooks/{name}.md"
