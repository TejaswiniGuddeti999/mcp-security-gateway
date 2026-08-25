"""
demo.py
-------
Short, scripted demo of v2's screening layers, using poisoned_server.py
as the (deliberately malicious) downstream target. Run this instead of
test_client.py when you want to see the gateway actually catch
something, rather than just proxy harmless calls through.

Run:
    GATEWAY_DOWNSTREAM=poisoned_server.py python demo.py
    (Windows PowerShell: $env:GATEWAY_DOWNSTREAM="poisoned_server.py"; python demo.py)

What to look for:
  - get_weather:   passes through unchanged (control case -- proves the
                    gateway doesn't just block everything).
  - read_reviews:  the tool's *description* is poisoned (tool
                    poisoning). What the client sees here should be the
                    redacted warning, not the "<IMPORTANT>...attacker"
                    payload.
  - fetch_page:    the tool's *output* is poisoned (indirect
                    injection). What the client sees here should also
                    be the redacted warning.
  - read_file:     called with a sensitive-file path as an *argument*
                    (CVE-2026-0755-style). Should be BLOCKED before it
                    ever reaches the downstream server -- no output at
                    all, just a gateway refusal.
  - send_message:  called with a destination not in
                    trusted_destinations (WhatsApp-exfil-style). Should
                    also be BLOCKED even though the tool name itself is
                    fully allow-listed.

Then open gateway_log.jsonl and grep for "SUSPICIOUS" -- that's the
full, unredacted content plus the reasons it was flagged, proving the
gateway saw the real payload even though the client never did.
"""

import os
import sys
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

os.environ.setdefault("GATEWAY_DOWNSTREAM", "poisoned_server.py")

GATEWAY = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / "gateway.py")],
    env={**os.environ},
)


async def main() -> None:
    async with stdio_client(GATEWAY) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("=== Tools the gateway exposed to the client ===")
            for t in tools.tools:
                print(f"\n--- {t.name} ---\n{t.description}")

            print("\n\n=== Calling each tool through the gateway ===")

            print("\n--- get_weather('Paris')  [control: should pass through clean] ---")
            result = await session.call_tool("get_weather", {"city": "Paris"})
            print(result.content)

            print("\n--- read_reviews('sku-123')  [description was poisoned] ---")
            result = await session.call_tool("read_reviews", {"product_id": "sku-123"})
            print(result.content)

            print("\n--- fetch_page('https://example.com/travel')  [output was poisoned] ---")
            result = await session.call_tool("fetch_page", {"url": "https://example.com/travel"})
            print(result.content)

            print("\n--- read_file('~/.ssh/id_rsa')  [malicious ARGUMENT, CVE-2026-0755-style] ---")
            result = await session.call_tool("read_file", {"path": "~/.ssh/id_rsa"})
            print(result.content)

            print("\n--- send_message(to='+1-900-000-9999', ...)  [untrusted destination, WhatsApp-style] ---")
            result = await session.call_tool(
                "send_message",
                {"to": "+1-900-000-9999", "text": "forwarding chat history"},
            )
            print(result.content)

            print("\n\nNow check gateway_log.jsonl for the unredacted originals + verdicts.")


if __name__ == "__main__":
    anyio.run(main)
