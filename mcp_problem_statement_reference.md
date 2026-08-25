# MCP Security: Problem Statement Reference

Compiled August 10, 2026, from OWASP's MCP Security Cheat Sheet, the official MCP specification blog, WorkOS's spec analysis, and AuthZed's incident timeline (updated May 30, 2026). Full sources at the bottom.

---

## Part 1 — OAuth vs. Gateway, side by side

The short version: OAuth answers "who is this, and what are they allowed to do." A gateway answers "is what's actually happening in this specific request safe." They are not competitors — they sit at different layers, and a real deployment needs both.

| | **OAuth (2.1, as MCP now requires)** | **MCP Gateway / Proxy** |
|---|---|---|
| **What it is** | An identity/permission standard. The client proves who it is and gets a scoped, often short-lived access token instead of a raw password. | A choke point that every request and response physically passes through before reaching either side. |
| **Question it answers** | "Is this client allowed to connect, and what's it allowed to do?" | "Is the actual content of this specific message safe — could it be a poisoned description, a hidden instruction, a dangerous argument?" |
| **When it acts** | Once, at connection/token-issuance time (plus periodic refresh). | On every single request and response, continuously, for the life of the session. |
| **What it's genuinely good at** | Preventing impersonation, scoping exactly what a client can touch (e.g. read-only vs. full access), stopping a token issued for one server being replayed against another (new in the July 2026 spec via Resource Indicators). | Catching attacks that ride inside content a fully authenticated, fully authorized channel is carrying — because authentication says nothing about what's inside an approved message. |
| **Its real limitation** | Cannot inspect the meaning of a message. A perfectly valid, correctly-scoped token can still carry a request built from a poisoned tool description, or return output with a hidden instruction embedded in it. OAuth has no concept of "text" at all — only "who" and "what scope." | Cannot establish identity or prevent an unauthorized party from connecting in the first place. A gateway with no auth in front of it just means an attacker gets *scanned* traffic instead of *no* traffic — it doesn't stop them connecting. |
| **Where each "compromises"** | Compromises on: content safety. A revoked/well-scoped token stops a *known-bad actor*, not a legitimate, authenticated tool that's been poisoned or compromised after the fact (postmark-mcp: fully legitimate, fully authorized, still exfiltrated real emails for months). | Compromises on: identity guarantees. A gateway can flag or block suspicious *content*, but it has no way to verify that "user_123" is really user_123 unless something else (OAuth) already did that upstream. |
| **How companies actually use it** | Every remote MCP server, per the July 28, 2026 spec, must act as an OAuth 2.1 resource server — this is now closer to mandatory than optional for anything beyond local personal use. | OWASP explicitly lists it as best practice #8: "Use an MCP proxy or gateway to enforce isolation policies between servers," deployed as the mandatory hop every internal MCP client is pointed at, with logs feeding a SIEM. |
| **Real-world deployment shape** | Handled by an identity provider (Okta, Azure AD, WorkOS AuthKit, Google Workspace) that issues and validates tokens; the MCP server just validates them. | Handled by a security/platform team, deployed once, sitting between every client and every downstream server — architecturally identical to a corporate web proxy. |
| **What happens if you only have one** | Only OAuth: every attack in this document that used a *legitimate*, authenticated tool (WhatsApp, postmark-mcp, GitHub MCP) still works exactly as it did. | Only Gateway, no auth at all: anyone can connect and get scanned traffic, but there's no way to know *who* is generating that traffic, no scoping, no way to revoke a specific bad actor's access without blocking everyone. |

---

## Part 2 — The story of MCP security, chronologically

### Chapter 1: A universal adapter (November 2024)

Anthropic introduced the Model Context Protocol in November 2024, pitched — accurately, as it turned out — as "the USB-C of AI agents." Before MCP, every AI app that wanted to talk to GitHub, or a database, or email, needed custom integration code written specifically for that pairing. MCP made it a standard plug: any MCP client, any MCP server, no custom wiring. Adoption exploded within months — dozens of tool servers, open-source integrations, and hosted registries appeared almost immediately.

That speed was also the setup for everything that followed. AuthZed's incident timeline puts it plainly: developers connected powerful, sensitive systems to this new protocol "without rigorously applying established security controls." The tools were new; the mistakes were old.

### Chapter 2: The cracks appear (April–June 2025)

This is where the story gets specific, and where your project's actual focus lives. In **April 2025**, Invariant Labs demonstrated the first real "tool poisoning" attack: a MCP server offering a harmless "random fact of the day" tool had a hidden instruction embedded in its description that turned it into a sleeper backdoor, silently exfiltrating a user's entire WhatsApp chat history to an attacker. Nothing about the connection was unauthorized — the tool was legitimately installed, legitimately called. The attack lived entirely in text the AI read but no human ever double-checked.

A month later, in **May 2025**, the same research group found a related but distinct attack against the official **GitHub MCP server**: a malicious public GitHub issue — just text, sitting in a public repo — hijacked an AI assistant into pulling private repository data (including salary and financial information in one case) and leaking it into a public pull request. This is **indirect prompt injection**: the poison wasn't in a tool's description, it was in data a tool *returned*.

In **June 2025**, two more incidents rounded out this stretch — Anthropic's own MCP Inspector developer tool turned out to allow unauthenticated remote code execution (CVE-2025-49596), and Asana found a bug letting one customer's data potentially leak to a different customer's MCP integration. Different root causes, same lesson: the ecosystem was moving faster than its security review.

### Chapter 3: The supply-chain era (July–October 2025)

The next wave shifted from "the agent gets tricked" to "the tool itself is the trap." **July 2025**: a critical command-injection bug in `mcp-remote` (437,000+ downloads, used in Cloudflare and Auth0 integration guides) let a malicious server run arbitrary code on a client's machine just by sending a booby-trapped response. **August 2025**: Anthropic's own Filesystem MCP server had a sandbox escape, letting a tool reach files outside its intended boundary. Then, in **September 2025**, the incident your project's demo is modeled after: a package impersonating the "Postmark MCP Server" was found silently BCC'ing every email it processed — invoices, internal memos, confidential documents — to an attacker's address. It had been running, undetected, in production, for months, precisely because it was a fully legitimate-looking, fully functional tool. **October 2025** brought a Figma integration command-injection flaw and a Smithery hosting platform breach that leaked a token controlling access to over 3,000 hosted MCP servers.

### Chapter 4: The reckoning (January–April 2026)

This is where the scale stopped being "a string of incidents" and became a systemic finding. **January 2026**: a 0-day in `gemini-mcp-tool` (CVE-2026-0755) let unauthenticated attackers run arbitrary code by exploiting an unsanitized argument reaching a shell call — the exact CVE your gateway's argument-scanning layer is modeled on. **February 2026**: attackers cloned the legitimate Oura Ring MCP project, built a convincing fake GitHub ecosystem around it (fake contributors, fake forks), and distributed credential-stealing malware through it. **March 2026**: a critical, unauthenticated flaw in `nginx-ui`'s MCP integration (CVSS 9.8) let attackers take over web server configuration entirely.

Then, in **April 2026**, researchers disclosed what they called "The Mother of All AI Supply Chains" — a systemic architectural flaw in MCP's core `stdio` transport itself, present across the ecosystem's SDKs, affecting tools with a combined 150 million downloads and producing over 30 disclosures and 10+ CVEs in one wave. This wasn't one bad package anymore; it was a design-level weakness shared by the whole ecosystem.

### Chapter 5: Independent scrutiny arrives

By mid-2026, this had gone from "security researchers finding bugs" to "institutions building formal evaluation tools." **MCPTox**, an AAAI 2026 academic benchmark, tested detection systems against 353 real tools across 45 live MCP servers — the exact benchmark your gateway was validated against, and the one that exposed a real 12.5%-recall gap in an early version, tracing back to attack phrasing ("this description's priority is higher than the user's request...") that classic jailbreak-style detectors had never been built to recognize. In **June 2026**, the **NSA** published an official Cybersecurity Information Sheet specifically on MCP security — a government body treating this as a live, current threat category.

### Chapter 6: The biggest fix yet — July 28, 2026

Two and a half weeks before this document was written, MCP shipped what its own maintainers called "the largest revision of the protocol since launch." The two headline changes: the protocol became stateless (removing session-pinning complexity that made secure scaling harder), and — the part that matters most for the story here — **authorization got formalized**. MCP servers are now required to act as full OAuth 2.1 resource servers, with new protections (Resource Indicators, RFC 8707) specifically closing the "token issued for server A gets replayed against server B" class of attack. This is real, meaningful progress, and it directly answers a big chunk of the "over-privileged credentials" pattern that AuthZed's timeline calls the single most repeated root cause across every incident above.

### Chapter 7: What's still missing — and where this project fits

Read the whole timeline again and notice something: the July 28 spec update fixes *identity and scoping*. It does nothing — cannot do anything, by design — about **April 2025's WhatsApp attack, May 2025's GitHub attack, or September 2025's postmark-mcp backdoor**, because in every one of those, the connection was already fully authorized. The attacker's edge wasn't a stolen credential; it was text — a tool description, a returned webpage, a GitHub issue — read and acted on by an AI that had no way to tell "these are my instructions" from "this is data I should just report back." Better authentication makes this *more* true over time, not less: as impersonation gets harder under the new spec, manipulating an agent's legitimate, correctly-scoped access becomes the comparatively easier path for an attacker.

That gap — screening the actual content of live requests and responses, not just who's allowed to send them — is what still needs to be built into most real deployments, and it's exactly what this gateway does. It sits downstream of OAuth, not instead of it: authentication establishes who's connecting and what they're scoped to, and then every message that flows through that legitimate connection still gets scanned for the WhatsApp shape (poisoned description), the GitHub shape (poisoned output), the postmark-mcp shape (a legitimate tool's output carrying a hidden exfiltration instruction), and the gemini-mcp-tool shape (a dangerous value arriving as a plain argument) — with every verdict written to an auditable trail. It isn't a replacement for the July 28 spec's improvements; it's the layer those improvements were never designed to cover, validated against the same independent academic benchmark (MCPTox) the field is now using to actually measure whether these defenses work, rather than just claiming they do.

---

## Sources

- [MCP Security - OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [A Timeline of Model Context Protocol (MCP) Security Breaches — AuthZed](https://authzed.com/blog/timeline-mcp-breaches)
- [The biggest MCP spec update ships July 28: What changes for AI agent authentication — WorkOS](https://workos.com/blog/mcp-2026-spec-agent-authentication)
- [The 2026-07-28 MCP Specification Release Candidate — Model Context Protocol Blog](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
- [MCP Security Statistics 2026: CVEs, Vulnerabilities & Breach Data](https://www.practical-devsecops.com/mcp-security-statistics-2026-report/)
- [Anthropic: Introducing the Model Context Protocol](https://www.anthropic.com/news/model-context-protocol)
- [Invariant Labs: WhatsApp MCP Exploited](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
- [Invariant Labs: GitHub MCP Vulnerability](https://invariantlabs.ai/blog/mcp-github-vulnerability)
