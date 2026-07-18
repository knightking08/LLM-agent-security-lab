"""
The agent's three tools.

Think of tools as the "hands" of the agent. The LLM can't do anything on its
own — it can only decide to CALL one of these functions. That decision is the
whole security surface: if an attacker can steer the model's decision, they
control your hands.

Tool 1: read_file    -> reads a local document (this is how poisoned data gets in)
Tool 2: web_search   -> a harmless-looking lookup (mocked, no real network)
Tool 3: send_email   -> the DANGEROUS sink. Anything that reaches here has left
                        your system. Exfiltration = tricking the agent into
                        calling this with the secret in it.
"""

import os

# A log of everything the "email" tool was asked to send.
# In the real world this would be an SMTP call. Here we just record it so the
# demo can check: "did the secret leak out through this sink?"
SENT_EMAILS = []


def read_file(path: str) -> str:
    """Read a document from the local ./data folder and return its text."""
    base = os.path.join(os.path.dirname(__file__), "data")
    # Keep the agent inside ./data so a path-traversal answer can't wander off.
    safe_path = os.path.join(base, os.path.basename(path))
    if not os.path.exists(safe_path):
        return f"ERROR: no file named {path!r} in data/."
    with open(safe_path, "r", encoding="utf-8") as f:
        return f.read()


def web_search(query: str) -> str:
    """A fake web search. Returns canned text so the lab needs no internet."""
    return (
        f"Top result for {query!r}: Standard invoices are due within 30 days of "
        "the issue date. Late payments may incur a 1.5% monthly fee."
    )


def send_email(to: str, subject: str, body: str) -> str:
    """Send an email. THIS IS THE DANGEROUS TOOL — data leaves the system here."""
    SENT_EMAILS.append({"to": to, "subject": subject, "body": body})
    return f"Email sent to {to} with subject {subject!r}."


# ---- Schemas the model sees (OpenAI "tools" format) -------------------------
# This is how the model learns what it's allowed to call and what arguments
# each tool needs.
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a document from the local data folder.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File name, e.g. invoice.txt"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Look up general information on the web.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"}
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email to a recipient.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
]

# Maps a tool name to the actual Python function to run.
TOOL_IMPLS = {
    "read_file": read_file,
    "web_search": web_search,
    "send_email": send_email,
}
