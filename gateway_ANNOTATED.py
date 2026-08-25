"""
gateway_ANNOTATED.py
---------------------
THIS IS A TEACHING COPY, NOT PART OF THE REAL PROJECT.

It's a line-by-line explained version of gateway.py, for reading only --
don't run this one, don't copy it over the real gateway.py. The actual
gateway.py stays clean (normal amount of comments, like real production
code) so it reads well in a portfolio. This file exists purely so you
can go slowly through every single line once and know exactly what it
does, including the plain Python mechanics that have nothing to do with
security and everything to do with just being unfamiliar syntax.

Read it top to bottom, once, without running anything. That's the
whole task for tonight.
"""

# --- IMPORTS: these lines just pull in code other people already wrote ---

import json
# ^ Python's built-in library for reading/writing JSON (the {"key": "value"}
#   text format). We use it to write log lines and to turn a dict of
#   arguments into a plain string so we can scan it for suspicious text.

import os
# ^ Built-in library for talking to the operating system -- here, just
#   used to read environment variables (like GATEWAY_DOWNSTREAM).

import sys
# ^ Built-in library that gives us sys.executable -- the path to the
#   Python interpreter currently running this file, so we can launch
#   the downstream server using the SAME Python installation.

from datetime import datetime, timezone
# ^ "from X import Y" means: go into the datetime library, and pull out
#   just these two specific things (a class called datetime, and the
#   timezone helper), instead of importing the whole library.
#   Used once, to stamp every log line with the current UTC time.

from pathlib import Path
# ^ Path is a class that represents a file/folder location in a way
#   that works on Windows AND Mac/Linux without you writing separate
#   code for each. We use it below to build file paths.

import anyio
# ^ A library for running "async" code (see the explanation of `async`
#   further down). MCP servers are built on async code because a
#   server needs to be able to wait for network/process messages
#   without freezing the whole program.

from mcp import types
# ^ The official MCP library. `types` contains the data shapes MCP
#   uses -- e.g. types.Tool (what a tool description looks like),
#   types.CallToolResult (what a tool's answer looks like).

from mcp.client.session import ClientSession
# ^ ClientSession is the object our gateway uses to TALK TO the
#   downstream server, pretending to be an AI client itself.

from mcp.client.stdio import StdioServerParameters, stdio_client
# ^ "stdio" means "standard input/output" -- the same channel a
#   terminal uses. MCP servers can communicate over stdio instead of
#   the network. StdioServerParameters describes HOW to launch a
#   server process (what command, what arguments). stdio_client is
#   the function that actually launches it and opens a channel to it.

from mcp.server.lowlevel import Server
# ^ Server is the class our gateway uses to BE an MCP server itself --
#   i.e. the thing the real AI client connects to, thinking it's
#   talking to a normal tool server.

from mcp.server.stdio import stdio_server
# ^ Sets up OUR side of the stdio channel, the one the real AI client
#   will connect to (as opposed to stdio_client above, which is us
#   connecting to the downstream server).

# --- our own code, from the other files in this project ---

from policy import load_allowlist, check_tool_call
# ^ Pulls in the two functions from policy.py: one that reads
#   allowlist.json into a Python dict, one that decides ALLOW/BLOCK/FLAG
#   for a given tool call.

from scanners import scan_text
# ^ Pulls in the one function from scanners.py that actually looks at
#   a piece of text and decides if it's suspicious.

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
# ^ "try/except" means: attempt the code in `try`, and if it raises an
#   error, do whatever's in `except` instead of crashing the whole
#   program. Here: try to load a .env file (a text file with
#   GROQ_API_KEY=xxxx in it) into the environment. If the `dotenv`
#   package isn't installed, ImportError happens, and we just `pass`
#   (do nothing) -- the gateway still works, it just won't have picked
#   up a Groq key from a .env file.

LOG_FILE = Path(__file__).parent / "gateway_log.jsonl"
# ^ __file__ is a special variable Python fills in automatically: the
#   path to the CURRENT file (gateway.py). .parent means "the folder
#   this file is in." The "/" here isn't division -- Path overloads
#   the "/" operator to mean "join this path with this next piece."
#   So this line means: "the gateway_log.jsonl file, sitting in the
#   same folder as gateway.py."

DOWNSTREAM_SCRIPT = os.environ.get("GATEWAY_DOWNSTREAM", "downstream_server.py")
# ^ os.environ is a dict-like object of all environment variables.
#   .get("KEY", default) means "give me the value of GATEWAY_DOWNSTREAM
#   if it's set, otherwise give me the string 'downstream_server.py'."
#   This is how demo.py can say "point the gateway at poisoned_server.py
#   instead" without editing this file at all.

DOWNSTREAM = StdioServerParameters(
    command=sys.executable,
    args=[str(Path(__file__).parent / DOWNSTREAM_SCRIPT)],
)
# ^ Building the "instructions for how to launch the downstream server."
#   command=sys.executable means "run it using this same Python."
#   args=[...] is the list of command-line arguments -- here, just one:
#   the full path to whichever script we're pointing at.

# --- FUNCTIONS: reusable blocks of code, defined once, used many times ---

def log_event(event: dict) -> None:
    # ^ "def" defines a function named log_event. It takes one input,
    #   named `event`, which the ": dict" says SHOULD be a dictionary
    #   (this is just a hint for humans/tools -- Python doesn't enforce
    #   it). "-> None" says this function doesn't return anything useful.
    """Append one JSON line per event. Deliberately dead simple --
    grep-able, diff-able, and needs zero setup. Swap for SQLite later
    if/when you need to query it instead of just read it."""
    # ^ A string right after a function definition is a "docstring" --
    #   documentation that tools (and humans) can read about what this
    #   function does.
    event["ts"] = datetime.now(timezone.utc).isoformat()
    # ^ Add a new key "ts" (timestamp) to the event dict, set to the
    #   current time in UTC, formatted as text (isoformat = the
    #   standard "2026-07-18T12:00:00" style).
    with open(LOG_FILE, "a") as f:
        # ^ "with" is a context manager -- it opens the file, and
        #   GUARANTEES it gets closed afterward even if something goes
        #   wrong inside the block. "a" means "append" -- add to the
        #   end of the file instead of overwriting it. `f` is the
        #   variable we use to refer to "the open file" inside the block.
        f.write(json.dumps(event) + "\n")
        # ^ json.dumps() turns the Python dict into a JSON-formatted
        #   string. We add "\n" (a newline character) so each event
        #   becomes its own line in the file.


def _extract_text(content_items) -> str:
    # ^ Functions starting with an underscore (_extract_text) are a
    #   convention meaning "internal helper, not meant to be used from
    #   outside this file."
    """Pull plain text out of a list of MCP content blocks (TextContent
    has a .text attribute; other content types are stringified) so the
    scanner has something to scan."""
    parts = []
    # ^ Start with an empty list -- we'll fill it up piece by piece.
    for item in content_items:
        # ^ "for X in Y" loops over every item in a list (or anything
        #   list-like), running the indented code once per item.
        text = getattr(item, "text", None)
        # ^ getattr(object, "attribute_name", default) means: "if this
        #   object has a .text property, give me its value; if not,
        #   give me None instead of crashing."
        parts.append(text if text is not None else str(item))
        # ^ "A if condition else B" is a one-line if/else. Meaning:
        #   if we found real text, use it; otherwise, just convert
        #   whatever this item is into a plain string.
    return "\n".join(parts)
    # ^ "\n".join(list) glues all the list's strings together with a
    #   newline between each one, producing one big string.


def _redacted_description(reasons: list) -> str:
    return (
        "[GATEWAY WARNING: original description withheld -- flagged for: "
        f"{', '.join(reasons)}. Full text in gateway_log.jsonl.]"
    )
    # ^ An f-string (the f before the quote) lets you drop a Python
    #   expression directly into a string using {curly braces}.
    #   ', '.join(reasons) turns a list like ["a", "b"] into the text
    #   "a, b". So this whole function builds the exact warning
    #   message the CLIENT sees when a tool description gets redacted.


def _redacted_output(reasons: list) -> str:
    return (
        "[GATEWAY WARNING: tool output withheld -- flagged for: "
        f"{', '.join(reasons)}. Full original output in gateway_log.jsonl.]"
    )
    # ^ Same idea as above, but for the message shown when a tool's
    #   OUTPUT (not its description) gets redacted.


def _blocked_message(tool_name: str, reasons: list) -> str:
    return (
        f"[GATEWAY BLOCKED] Call to '{tool_name}' refused -- flagged for: "
        f"{', '.join(reasons)}."
    )
    # ^ The message shown when a call gets blocked entirely (never even
    #   reaches the downstream server), rather than redacted after the
    #   fact.


async def main() -> None:
    # ^ "async def" defines a function that's allowed to PAUSE and let
    #   other things happen while it's waiting (e.g. waiting for a
    #   message to arrive over the network/process). A normal function
    #   ("def") can't do that -- it blocks everything until it's done.
    #   MCP servers need this because they're constantly waiting for
    #   messages from two different directions at once (the client and
    #   the downstream server).
    app = Server("mcp-security-gateway")
    # ^ Create the Server object -- this IS our gateway, from the point
    #   of view of whatever connects to it. "mcp-security-gateway" is
    #   just its name, shown during the MCP handshake.
    allowlist = load_allowlist()
    # ^ Read allowlist.json into a Python dict, once, when the gateway
    #   starts up (not on every single call -- that would be wasteful).

    async with stdio_client(DOWNSTREAM) as (downstream_read, downstream_write):
        # ^ "async with" is like "with" above, but for things that need
        #   to be awaited when opening/closing. This line launches the
        #   downstream server as a subprocess and opens a two-way pipe
        #   to it. downstream_read/downstream_write  are the two ends of
        #   that pipe (one for receiving, one for sending).
        async with ClientSession(downstream_read, downstream_write) as downstream:
            # ^ Wrap that raw pipe in a ClientSession object, which
            #   knows how to speak the actual MCP protocol over it.
            #   `downstream` is now "our connection to the real server,
            #   as if we were an AI client talking to it."
            await downstream.initialize()
            # ^ "await" means "pause here until this finishes, but let
            #   other async code run in the meantime." This performs
            #   the MCP handshake with the downstream server.

            @app.list_tools()
            # ^ This is a DECORATOR -- a line starting with @ that
            #   modifies the function defined right below it. In plain
            #   English: "register the function below as THE function
            #   that runs whenever someone asks this gateway for its
            #   list of tools."
            async def handle_list_tools() -> list[types.Tool]:
                result = await downstream.list_tools()
                # ^ Ask the REAL downstream server what tools it has,
                #   and wait for its answer.

                # --- SECURITY CHECK: tool poisoning scan ---
                safe_tools = []
                for tool in result.tools:
                    # ^ Loop over every tool the downstream server
                    #   reported having.
                    scan = scan_text(tool.description or "")
                    # ^ "X or Y" means "use X if it's truthy (not empty/
                    #   None), otherwise use Y." So: scan the tool's
                    #   description, or an empty string if it has none.
                    log_event(
                        {
                            "event": "list_tools_scan",
                            "tool": tool.name,
                            "description": tool.description,
                            "verdict": "SUSPICIOUS" if scan.suspicious else "CLEAN",
                            **scan.to_dict(),
                            # ^ "**dict" spreads all of that dict's
                            #   key/value pairs directly into THIS dict,
                            #   instead of nesting it inside one key.
                        }
                    )
                    if scan.suspicious and scan.confidence == "high":
                        tool = tool.model_copy(
                            update={"description": _redacted_description(scan.reasons)}
                        )
                        # ^ tool.model_copy(update={...}) makes a COPY
                        #   of the tool object with just the description
                        #   field replaced -- the original scanned data
                        #   is never mutated in place, a new object is
                        #   made instead. This is how the poisoned text
                        #   gets swapped for the warning message.
                    safe_tools.append(tool)
                    # ^ Add this tool (redacted or not) to the list we'll
                    #   actually hand back to the client.

                log_event(
                    {
                        "event": "list_tools",
                        "tool_names": [t.name for t in safe_tools],
                        # ^ A "list comprehension" -- shorthand for
                        #   "build a new list by taking t.name for every
                        #   t in safe_tools."
                    }
                )
                return safe_tools
                # ^ This is what actually gets sent back to whatever
                #   client asked for the tool list.

            @app.call_tool()
            # ^ Same idea as @app.list_tools() above: register the next
            #   function as THE function that runs whenever a client
            #   wants to actually CALL a tool.
            async def handle_call_tool(
                name: str, arguments: dict
            ) -> types.CallToolResult:
                # ^ MCP automatically calls this function with two
                #   pieces of info every time a client calls a tool:
                #   which tool (name), and what arguments it was called
                #   with (arguments).
                log_event(
                    {
                        "event": "call_tool_request",
                        "tool": name,
                        "arguments": arguments,
                    }
                )

                # --- SECURITY CHECK: pre-call allow-list + destination policy ---
                verdict, reason = check_tool_call(name, arguments, allowlist)
                # ^ check_tool_call returns TWO values at once (a
                #   "tuple"). This line unpacks them into two separate
                #   variables in one go.
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
                    # ^ "return" immediately exits this function with
                    #   this result -- none of the code below runs. This
                    #   is how a BLOCK stops the call before it ever
                    #   reaches the real server: we just never get there.

                # --- SECURITY CHECK: argument content scan ---
                arg_text = json.dumps(arguments, default=str)
                # ^ Turn the whole arguments dict into one JSON string
                #   so the same text scanner used for descriptions/
                #   output can also scan this. default=str means "if
                #   something in here isn't normally JSON-safe, just
                #   convert it to a string instead of crashing."
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
                    # ^ Same idea as the BLOCK above -- exit early,
                    #   never call the real downstream tool.

                result = await downstream.call_tool(name, arguments)
                # ^ We only reach this line if NOTHING above blocked the
                #   call. This is the actual real call to the real
                #   downstream tool, and we wait for its answer.

                # --- SECURITY CHECK: post-call output scan ---
                output_text = _extract_text(result.content)
                scan = scan_text(output_text)
                log_event(
                    {
                        "event": "call_tool_result_scan",
                        "tool": name,
                        "content_preview": output_text[:500],
                        # ^ [:500] is "slicing" -- take only the first
                        #   500 characters, so huge outputs don't bloat
                        #   the log file.
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
                    # ^ Same "copy with one field replaced" trick as the
                    #   description redaction earlier, but on the RESULT
                    #   object this time -- swapping the real (poisoned)
                    #   output for the warning message.

                log_event(
                    {
                        "event": "call_tool_result",
                        "tool": name,
                        "is_error": result.isError,
                        "content_preview": str(result.content)[:200],
                    }
                )
                return result
                # ^ This is what finally goes back to the client --
                #   either the real answer (if everything was clean) or
                #   the redacted warning (if the output scan caught
                #   something).

            async with stdio_server() as (in_stream, out_stream):
                # ^ Open OUR side of the stdio channel -- the one the
                #   real AI client will connect to.
                await app.run(
                    in_stream, out_stream, app.create_initialization_options()
                )
                # ^ Start the actual server loop: sit here and respond
                #   to whatever the client sends, using the two
                #   functions we registered above (handle_list_tools and
                #   handle_call_tool) whenever the matching request
                #   comes in. This line runs until the client disconnects.


if __name__ == "__main__":
    # ^ A very common Python idiom. __name__ is a special variable that
    #   equals "__main__" ONLY when this file is run directly (e.g.
    #   `python gateway.py`), and equals something else if this file
    #   is imported by another file instead. So this line means:
    #   "only actually start the server if someone ran this file
    #   directly -- don't start it just because another file imported
    #   something from it."
    anyio.run(main)
    # ^ "async def" functions can't just be called normally -- something
    #   has to actually run the async event loop that lets them pause
    #   and resume. anyio.run(main) is that: "start the async engine,
    #   and run main() inside it."
