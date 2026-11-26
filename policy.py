"""
policy.py
---------
Pre-call allow-list enforcement -- v2's second security layer.

Two checks live here, both driven by allowlist.json:

1. Tool-name allow-list -- the original check. Anything not explicitly
   allowed gets flagged (warn mode) or blocked outright (enforce mode),
   instead of being silently run.

2. Destination-aware argument check -- added after mapping this
   design against the real WhatsApp MCP exfiltration case (Invariant
   Labs, April 2025). In that incident the tool being called
   (send a message) was completely legitimate -- the attack was in
   *who* the message went to, not *which* tool ran. A tool-name-only
   allow-list is blind to that. So for tools listed in
   allowlist.json's "sensitive_fields", this checks the named argument
   (e.g. a "to" or "recipient" field) against a "trusted_destinations"
   list, and flags/blocks the same way as an unlisted tool would.
"""

import json
from pathlib import Path

ALLOWLIST_FILE = Path(__file__).parent / "allowlist.json"

DEFAULT_ALLOWLIST = {
    "mode": "warn",
    "allowed_tools": [],
    "sensitive_fields": {},
    "trusted_destinations": [],
}


def load_allowlist() -> dict:
    if not ALLOWLIST_FILE.exists():
        return dict(DEFAULT_ALLOWLIST)
    with open(ALLOWLIST_FILE, encoding="utf-8") as f:
        data = json.load(f)
    data.setdefault("mode", "warn")
    data.setdefault("allowed_tools", [])
    data.setdefault("sensitive_fields", {})
    data.setdefault("trusted_destinations", [])
    return data


def check_tool_call(tool_name: str, arguments: dict, allowlist: dict) -> tuple:
    """Returns (verdict, reason). verdict is one of ALLOW / BLOCK / FLAG.

    - ALLOW: tool (and, if applicable, its destination argument) checks
             out clean -- forward normally.
    - FLAG:  something's off the allow-list, but mode is 'warn' --
             forwarded anyway, logged loudly, so the operator can see
             what would have been blocked before flipping to enforce.
    - BLOCK: something's off the allow-list and mode is 'enforce' --
             the call is refused before it ever reaches the downstream
             server.
    """
    allowed = set(allowlist.get("allowed_tools", []))
    mode = allowlist.get("mode", "warn")
    arguments = arguments or {}

    # Check-1
    if tool_name not in allowed:
        if mode == "enforce":
            return "BLOCK", f"'{tool_name}' is not on the allow-list (enforce mode)"
        return "FLAG", f"'{tool_name}' is not on the allow-list (warn mode: forwarded, logged)"

    # Tool name is fine -- now check any sensitive/destination fields
    # this specific tool is configured to watch.
    # check-2  
    watched_fields = allowlist.get("sensitive_fields", {}).get(tool_name, [])
    trusted = set(allowlist.get("trusted_destinations", []))
    for field in watched_fields:
        if field not in arguments:
            continue
        value = str(arguments[field])
        if trusted and value not in trusted:
            reason = (
                f"'{tool_name}' argument '{field}'={value!r} is not in "
                f"trusted_destinations"
            )
            if mode == "enforce":
                return "BLOCK", reason
            return "FLAG", reason

    return "ALLOW", "tool is on the allow-list"
