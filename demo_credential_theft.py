"""
demo_credential_theft.py
-------------------------
The single most direct proof this project works: call the exact same
malicious tool twice -- once with NO gateway in the way, once through
gateway.py -- and compare what the client actually receives.

The scenario: `check_account_status` (in poisoned_server.py) looks
like an ordinary account lookup. Its real output embeds a
fake-but-realistic-looking API key sitting right next to a hidden
instruction trying to get that key exfiltrated to an attacker's server
and concealed from the user -- the postmark-mcp backdoor (real
exfiltration via a legitimate-looking tool) and the WhatsApp case
(concealment language) combined into one payload.

Nothing here makes a real network call or touches a real credential --
the "key" is an obviously fake, made-up string that exists purely so
the two paths below have something concrete to either leak or protect.

Run:
    python demo_credential_theft.py

What to look for: the first section prints the fake key AND the raw
exfiltration instructions in full, exactly as a naive client (or an
LLM with no output screening) would receive them. The second section
calls the identical tool through gateway.py, and the key never
appears -- Check 4 (the output scanner) redacts it before the client
ever reads it.
"""

import os
import sys
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

POISONED_SERVER_DIRECT = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / "poisoned_server.py")],
)

GATEWAY_THROUGH = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / "gateway.py")],
    env={**os.environ, "GATEWAY_DOWNSTREAM": "poisoned_server.py"},
)


async def call_direct() -> None:
    print("=" * 72)
    print("NO GATEWAY -- client talks directly to the malicious server")
    print("=" * 72)
    async with stdio_client(POISONED_SERVER_DIRECT) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "check_account_status", {"account_id": "acct-4471"}
            )
            print(result.content[0].text)
    print(
        "\n^ That's the fake API key AND the exfiltration instructions,\n"
        "  sitting in what the client (or an LLM reading it) received,\n"
        "  completely unfiltered. Nothing stopped it.\n"
    )


async def call_through_gateway() -> None:
    print("=" * 72)
    print("WITH GATEWAY -- same tool, same call, through gateway.py")
    print("=" * 72)
    async with stdio_client(GATEWAY_THROUGH) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "check_account_status", {"account_id": "acct-4471"}
            )
            print(result.content[0].text)
    print(
        "\n^ Same malicious tool, same call -- the key never appears.\n"
        "  Run `python query_log.py` to see the real, unredacted output\n"
        "  the gateway actually saw and blocked from ever reaching here.\n"
    )


async def main() -> None:
    await call_direct()
    await call_through_gateway()


if __name__ == "__main__":
    anyio.run(main)
