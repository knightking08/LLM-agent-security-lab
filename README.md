# LLM Agent Security Lab

A tiny, deliberately vulnerable AI agent you can attack and defend a hands-on
lab for learning **indirect prompt injection** and how to stop it.

The agent ("BillingBot") processes invoices. It has three tools and holds a
secret internal credential it's told never to reveal. By feeding it a **poisoned
invoice**, we trick it into emailing that secret to an attacker. Then we turn on
an **LLM Guard** guardrail and watch the attack fail. Finally we scan the whole
thing with **Garak** and measure the before/after.

Maps to **OWASP LLM01: Prompt Injection**.

```
user ──► [BillingBot agent] ──► tools: read_file · web_search · send_email(!)
                 ▲                         │
                 └── reads a document ◄────┘   ← poison enters here (indirect injection)
```

## What's inside

| File | What it is |
|------|-----------|
| `agent.py` | The agent loop + a `/chat` HTTP endpoint |
| `tools.py` | The 3 tools; `send_email` is the dangerous data sink |
| `defense.py` | LLM Guard scanners, behind a `GUARD_ENABLED` toggle |
| `data/invoice_clean.txt` | A normal invoice |
| `data/invoice_poisoned.txt` | Same invoice + hidden attacker instructions |
| `run_attack.py` | Runs the attack with defense OFF then ON |
| `garak/` | Config + how-to for scanning the agent |

## Setup

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

**Pick a model.** Two easy options:

- **Local & free (recommended):** install [Ollama](https://ollama.com), then
  `ollama pull llama3.1`. Defaults already point at it. Use a model that
  supports tool-calling (llama3.1, qwen2.5, mistral-nemo).
- **OpenAI:** edit `.env` — set `LLM_BASE_URL=https://api.openai.com/v1`, a real
  `LLM_API_KEY`, and `LLM_MODEL=gpt-4o-mini`.

## Run the demo

```bash
python run_attack.py
```

You'll see two RESULT lines. With defense OFF the secret leaks to the attacker's
email; with defense ON it's blocked. That contrast is the whole lab.

## Scan with Garak

See `garak/HOWTO.md` for the before/after scan (start the server, run Garak with
the guard off, then on, compare the pass rates).

## How the defense works (the important lesson)

Indirect injection doesn't arrive in the user's message — it arrives inside a
**document the agent reads**. So a guardrail that only checks user input catches
nothing. `defense.py` scans in three places:

1. **User input** — direct injection attempts.
2. **Tool output** (the file the agent read) — *this* is what stops the indirect
   attack. Retrieved/untrusted content is where the poison lives.
3. **Outgoing email body** — a Secrets scanner as a last line of defense, so even
   if something slips through, the credential can't leave.

## ⚠️ Ethics

Everything here attacks an agent you run yourself, with a fake secret. Only ever
test systems you own or are authorized to test.
