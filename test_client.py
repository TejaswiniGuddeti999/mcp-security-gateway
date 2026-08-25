"""
test_client.py
---------------
Stands in for "the AI client" (Claude Desktop, Claude Code, etc.)
so you can prove the gateway works end-to-end without needing a
real AI app installed. This is also exactly the shape your eval
harness will grow out of later -- send a request, capture what
comes back, assert on it.

Run:
    python test_client.py
"""

import sys
from pathlib import Path

import anyio
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

GATEWAY = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / "gateway.py")],
)


async def main() -> None:
    async with stdio_client(GATEWAY) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            tools = await session.list_tools()
            print("Tools the gateway exposed:")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description}")

            print("\nCalling add_numbers(3, 4) through the gateway...")
            result = await session.call_tool("add_numbers", {"a": 3, "b": 4})
            print(f"  Result: {result.content}")

            print("\nCalling get_time() through the gateway...")
            result = await session.call_tool("get_time", {})
            print(f"  Result: {result.content}")


if __name__ == "__main__":
    anyio.run(main)
