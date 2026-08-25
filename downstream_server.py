"""
downstream_server.py
---------------------
A minimal "real" MCP server. This stands in for any MCP server you'd
normally connect an AI client to directly (filesystem, database, API
wrapper, whatever). It exposes two harmless tools so we have something
real to proxy and log.

This has ZERO security logic. That's intentional -- this file
represents "some server someone else wrote" that your gateway sits in
front of. You don't control or trust this code; you only control the
gateway.

Run it directly to sanity check it in isolation:
    python downstream_server.py
(it will just sit waiting for stdio input -- that's expected, stdio
servers are meant to be launched by a client/gateway, not run
standalone in a terminal)
"""

from datetime import datetime, timezone
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(name="downstream-demo-server")


@mcp.tool()
def get_time() -> str:
    """Return the current UTC time."""
    return datetime.now(timezone.utc).isoformat()


@mcp.tool()
def add_numbers(a: float, b: float) -> float:
    """Add two numbers together and return the result."""
    return a + b


if __name__ == "__main__":
    mcp.run(transport="stdio")
