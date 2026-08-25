"""
gateway.py
----------
v2: the pass-through proxy from v1, now with five security checks
wired in across the request/response lifecycle:

  1. list_tools -> tool poisoning scanner (scanners.scan_text) runs on
     every tool description before it ever reaches the AI client.
     High-confidence hits get their description redacted in place --
     the poisoned text never enters the client's context window.

  2. call_tool (pre) -> policy.check_tool_call enforces the tool-name
     allow-list from allowlist.json. Non-allow-listed tools are
     blocked (enforce mode) or flagged-and-forwarded (warn mode).

  3. call_tool (pre) -> policy.check_tool_call ALSO checks
     "sensitive_fields" -- e.g. a tool named send_message can be fully
     allow-listed by name and still get flagged/blocked if its "to"
     argument isn't in trusted_destinations. Modeled directly on the
     WhatsApp MCP exfiltration case (Invariant Labs, April 2025),
     where the tool being called was legitimate and only the
     destination was malicious -- a name-only allow-list is blind to
     that shape of attack.

  4. call_tool (pre) -> scanners.scan_text ALSO runs over the call's
     *arguments* before they're forwarded. Modeled on CVE-2026-0755
     (gemini-mcp-tool): an unsanitized argument like "@/etc/passwd"
     reached a shell exec downstream and exfiltrated the file. This
     layer exists because the first three checks all assume the
     attack lives in a description, a tool name, or a destination
     field -- this one catches it when it's sitting in a plain
     argument value instead.

  5. call_tool (post) -> scanners.scan_text runs on the downstream
     server's *response* content. This is the layer that catches
     indirect prompt injection -- poison riding in on tool output
     (a fetched webpage, a file, an API response) rather than the
     request. High-confidence hits get the content redacted before
     it's returned to the client.

Every decision at every layer is written to gateway_log.db (SQLite --
see storage.py and query_log.py), including the raw, unredacted
content, so an operator can audit or query what the gateway actually
saw even though the client never does. A short human-readable line
for each event also prints to the terminal in real time via Python's
`logging` module. Redaction and block messages sent to the client also
carry the specific matched reasons inline, not just a pointer to the
log.

Architecture (unchanged from v1):

    AI client  <--stdio-->  gateway.py  <--stdio (subprocess)-->  downstream_server.py

Run it with the MCP Inspector to test interactively:

    npx @modelcontextprotocol/inspector python gateway.py

Or point Claude Desktop / Claude Code at it once you're ready -- same
command works as an MCP server entry.
"""

import json
import os
import sys
from pathlib import Path

import anyio
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server

from policy import load_allowlist, check_tool_call
from scanners import scan_text
from storage import init_db, log_event

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv is optional; GROQ_API_KEY can also come from the real env

# The downstream server this gateway is protecting. Defaults to the
# harmless demo server; set GATEWAY_DOWNSTREAM=poisoned_server.py to
# point the gateway at the deliberately malicious demo server instead
# (see poisoned_server.py's docstring for the full demo walkthrough).
# Later this becomes a config file so the gateway can front multiple
# servers at once.
DOWNSTREAM_SCRIPT = os.environ.get("GATEWAY_DOWNSTREAM", "downstream_server.py")
DOWNSTREAM = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / DOWNSTREAM_SCRIPT)],
)


def _extract_text(content_items) -> str:
    """Pull plain text out of a list of MCP content blocks (TextContent
    has a .text attribute; other content types are stringified) so the
    scanner has something to scan."""
    parts = []
    for item in content_items:
        text = getattr(item, "text", None)
        parts.append(text if text is not None else str(item))
    return "\n".join(parts)


def _redacted_description(reasons: list) -> str:
    return (
        "[GATEWAY WARNING: original description withheld -- flagged for: "
        f"{', '.join(reasons)}. Full text in gateway_log.db (see query_log.py).]"
    )


def _redacted_output(reasons: list) -> str:
    return (
        "[GATEWAY WARNING: tool output withheld -- flagged for: "
        f"{', '.join(reasons)}. Full original output in gateway_log.db (see query_log.py).]"
    )


def _blocked_message(tool_name: str, reasons: list) -> str:
    return (
        f"[GATEWAY BLOCKED] Call to '{tool_name}' refused -- flagged for: "
        f"{', '.join(reasons)}."
    )


async def main() -> None:
    init_db()
    app = Server("mcp-security-gateway")
    allowlist = load_allowlist()

    async with stdio_client(DOWNSTREAM) as (downstream_read, downstream_write):
        async with ClientSession(downstream_read, downstream_write) as downstream:
            await downstream.initialize()  

            @app.list_tools()
            async def handle_list_tools() -> list[types.Tool]:
                result = await downstream.list_tools()

                # --- SECURITY CHECK: tool poisoning scan ---
                safe_tools = []
                for tool in result.tools:
                    scan = scan_text(tool.description or "")
                    log_event(
                        {
                            "event": "list_tools_scan",
                            "tool": tool.name,
                            "description": tool.description,
                            "verdict": "SUSPICIOUS" if scan.suspicious else "CLEAN",
                            **scan.to_dict(),
                        }
                    )
                    if scan.suspicious and scan.confidence == "high":
                        tool = tool.model_copy(
                            update={"description": _redacted_description(scan.reasons)}
                        )
                    safe_tools.append(tool)

                log_event(
                    {
                        "event": "list_tools",
                        "tool_names": [t.name for t in safe_tools],
                    }
                )
                return safe_tools

            @app.call_tool()
            async def handle_call_tool(
                name: str, arguments: dict
            ) -> types.CallToolResult:
                log_event(
                    {
                        "event": "call_tool_request",
                        "tool": name,
                        "arguments": arguments,
                    }
                )

                # --- SECURITY CHECK: pre-call allow-list + destination policy ---
                verdict, reason = check_tool_call(name, arguments, allowlist)
                log_event(
                    {
                        "event": "policy_check",
                        "tool": name,
                        "arguments": arguments,
                        "verdict": verdict,
                        "reason": reason,
                    }
                )
                if verdict == "BLOCK":
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text", text=_blocked_message(name, [reason])
                            )
                        ],
                        isError=True,
                    )

                # --- SECURITY CHECK: argument content scan ---
                # Catches attacks sitting in a plain argument value --
                # e.g. a path-traversal or sensitive-file reference like
                # CVE-2026-0755's "@/etc/passwd" -- rather than in a
                # description, a tool name, or a destination field.
                arg_text = json.dumps(arguments, default=str)
                arg_scan = scan_text(arg_text)
                log_event(
                    {
                        "event": "call_tool_argument_scan",
                        "tool": name,
                        "arguments": arguments,
                        "verdict": "SUSPICIOUS" if arg_scan.suspicious else "CLEAN",
                        **arg_scan.to_dict(),
                    }
                )
                if arg_scan.suspicious and arg_scan.confidence == "high":
                    return types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text=_blocked_message(name, arg_scan.reasons),
                            )
                        ],
                        isError=True,
                    )

                result = await downstream.call_tool(name, arguments)

                # --- SECURITY CHECK: post-call output scan ---
                # This is the layer that catches indirect prompt
                # injection -- poison riding in on tool *output*, not
                # the request.
                output_text = _extract_text(result.content)
                scan = scan_text(output_text)
                log_event(
                    {
                        "event": "call_tool_result_scan",
                        "tool": name,
                        "content_preview": output_text[:500],
                        "verdict": "SUSPICIOUS" if scan.suspicious else "CLEAN",
                        **scan.to_dict(),
                    }
                )
                if scan.suspicious and scan.confidence == "high":
                    result = result.model_copy(
                        update={
                            "content": [
                                types.TextContent(
                                    type="text", text=_redacted_output(scan.reasons)
                                )
                            ]
                        }
                    )

                log_event(
                    {
                        "event": "call_tool_result",
                        "tool": name,
                        "is_error": result.isError,
                        "content_preview": str(result.content)[:200],
                    }
                )
                return result

            async with stdio_server() as (in_stream, out_stream):
                await app.run(
                    in_stream, out_stream, app.create_initialization_options()
                )


if __name__ == "__main__":
    anyio.run(main)
