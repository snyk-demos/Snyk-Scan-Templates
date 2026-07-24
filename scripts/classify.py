#!/usr/bin/env python3
"""Turn a Snyk CLI log plus exit code into an actionable diagnosis.

Env:
  CLASSIFY_LOG   path to the captured CLI output (stdout+stderr)
  CLASSIFY_EXIT  Snyk CLI exit code
  CLASSIFY_SCAN  scan label, e.g. "IaC", used in messages

Outputs (to $GITHUB_OUTPUT):
  reason   short machine code: auth | forbidden | quota | parse | network |
           nothing-to-scan | findings | clean | unknown
  message  one-line human summary
  hint     the concrete next action
  quota    "true" if the org test limit was hit (can fire on a SUCCESSFUL
           scan, and is the reason the next one will fail, so it is reported
           independently of the exit code)
"""
import os
import re

# The most specific and most actionable causes are checked first before the vaguer ones.
PATTERNS = [
    ("misconfig", [r"command not found", r"No such file or directory.*snyk",
                   r"snyk: not found"],
     "The scan step itself is broken, not the scan.",
     "The shell failed before or instead of running Snyk (typically a broken "
     "line continuation or a missing binary). Fix the step script; the target "
     "was never actually scanned, so treat any 'clean' result as void."),

    # Listed before "parse": SNYK-CLI-0012 covers both a genuine parse
    # failure and "no valid IaC files".
    ("unsupported", [r"SNYK-CODE-0006", r"Project not supported",
                     r"unable to find supported files",
                     r"Could not find any valid IaC files"],
     "Snyk found no supported files at the scanned path.",
     "Check working-directory points at real source code and that the "
     "language is supported by this scan type. A wrong or literal path "
     "argument (e.g. a stray backslash) also produces this."),

    ("auth", [r"SNYK-0005", r"Authentication error", r"401 Unauthorized",
              r"Not authorised", r"authentication credentials not recognized"],
     "Snyk rejected the credentials (401).",
     "Check the SNYK_TOKEN secret exists, is not expired, and belongs to an "
     "account with access to this org. Re-create it as a service account token."),

    ("forbidden", [r"403 Forbidden", r"\bForbidden\b"],
     "Snyk returned 403 Forbidden.",
     "The token authenticated but lacks permission for this org or product, "
     "or the org has hit a plan limit. Check the org's entitlement for this "
     "scan type and the token's org access."),

    ("parse", [r"SNYK-CLI-0012", r"Failed to parse (JSON|YAML) file"],
     "The scan hit files it could not parse.",
     "Almost always non-IaC JSON/YAML swept in from vendored directories "
     "such as node_modules. Run this scan in a job that does NOT install "
     "dependencies, or scope it with detection-depth or an explicit path. "
     "Snyk IaC has no --exclude flag."),

    ("network", [r"ENOTFOUND", r"ECONNRESET", r"ETIMEDOUT", r"EAI_AGAIN",
                 r"socket hang up", r"getaddrinfo"],
     "Network failure reaching the Snyk API.",
     "Usually transient; re-run the job. If it persists, check runner egress "
     "and any proxy or firewall rules for *.snyk.io."),

    ("server", [r"50[0-9] (Internal Server Error|Bad Gateway|Service Unavailable)"],
     "Snyk API returned a server error.",
     "Transient on Snyk's side. Re-run, and check https://status.snyk.io."),
]

QUOTA = [r"reached your monthly limit", r"monthly limit of \d+ (private )?tests",
         r"test limit", r"upgrade your plan"]


def find(text, patterns):
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False


def main():
    log = ""
    path = os.environ.get("CLASSIFY_LOG", "")
    if path and os.path.exists(path):
        try:
            with open(path, errors="replace") as f:
                log = f.read()
        except OSError:
            log = ""

    code = os.environ.get("CLASSIFY_EXIT", "")
    scan = os.environ.get("CLASSIFY_SCAN", "Scan")

    quota = find(log, QUOTA)
    reason, message, hint = "unknown", "", ""

    if code == "0":
        reason, message = "clean", f"{scan}: no findings at the threshold."
    elif code == "1":
        reason, message = "findings", f"{scan}: findings at the threshold."
    elif code == "3":
        reason, message = ("nothing-to-scan",
                           f"{scan}: no supported files found, nothing to scan.")
    else:
        for name, pats, msg, tip in PATTERNS:
            if find(log, pats):
                reason, message, hint = name, f"{scan}: {msg}", tip
                break
        else:
            # Quota alone can be the cause of an otherwise unexplained failure.
            if quota:
                reason = "quota"
                message = f"{scan}: the Snyk org has hit its test limit."
                hint = ("Scans are being refused until the limit resets or the "
                        "plan is upgraded. See https://snyk.io/plans.")
            else:
                message = (f"{scan}: the Snyk CLI failed (exit {code or '?'}) "
                           "with no recognised error signature.")
                hint = ("Open the scan step log for the raw CLI output. Re-run "
                        "with the -d flag via extra-args for debug output.")

    # Quota can fire on a successful scan; it is why the NEXT one will fail,
    # so it is always reported, never folded into the exit-code branch above.
    if quota and reason not in ("quota",):
        print(f"::warning::{scan}: the Snyk org has reached its test limit. "
              "Scans will start failing until it resets or the plan is upgraded.")

    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(f"reason={reason}\n")
            f.write(f"message={message}\n")
            f.write(f"hint={hint}\n")
            f.write(f"quota={'true' if quota else 'false'}\n")


if __name__ == "__main__":
    main()
