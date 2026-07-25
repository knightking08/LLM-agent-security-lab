# LLM Agent Security Lab

A deliberately vulnerable AI agent you can attack and defend a hands-on lab for
**indirect prompt injection**: how it works, how well a guardrail stops it, and
how much of the defending is actually the guardrail versus the model itself.

The agent (**BillingBot**) processes invoices. It can read files, search the web,
and send email, and it holds a fake internal credential it's told never to reveal.
By feeding it a **poisoned invoice**, we try to make it exfiltrate that credential.
Then we turn on a guardrail and measure the difference and we run the same
attacks through different models, because the model turns out to be a defense
layer in its own right.

Maps to **OWASP LLM01: Prompt Injection**.

```
user ──► [BillingBot agent] ──► tools: read_file · web_search · send_email(!)
                 ▲                         │
                 └── reads a document ◄────┘   ← poison enters here (indirect injection)
```

## What's inside

| File | What it is |
| --- | --- |
| `agent.py` | The agent loop + a `/chat` HTTP endpoint |
| `tools.py` | The 3 tools; `send_email` is the dangerous data sink |
| `defense.py` | LLM Guard scanners, behind a `GUARD_ENABLED` toggle |
| `data/invoice_clean.txt` | A normal invoice |
| `data/invoice_poisoned.txt` | Same invoice + hidden attacker instructions |
| `run_attack.py` | Runs one attack with the guard OFF then ON |
| `attacks/corpus.py` | 13 injection techniques + one clean control |
| `attacks/harness.py` | Measures the guardrail per-technique (detection + false positives) |
| `demo_variant.py` | Runs any corpus variant through the live agent, layer by layer |
| `RESULTS.md` | Full findings and caveats |

## Setup

Requires Python 3.10+.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Pick a model.** The agent reads its model config from environment variables.

Local and free (Ollama):

```bash
# install Ollama, then:
ollama pull llama3.1
# defaults already point here; no env vars needed
```

OpenAI (needed to actually complete tool chains see Findings):

```bash
# bash
export LLM_BASE_URL="https://api.openai.com/v1"
export LLM_API_KEY="sk-...your-key..."
export LLM_MODEL="gpt-4o"
```

```powershell
# PowerShell
$env:LLM_BASE_URL="https://api.openai.com/v1"
$env:LLM_API_KEY="sk-...your-key..."
$env:LLM_MODEL="gpt-4o"
```

Set your key as an environment variable only never commit it. The `.gitignore`
excludes `.env`, but the simplest safe path is to export it in your shell.

## Run the demos

Single before/after attack:

```bash
python run_attack.py
```

Measure the guardrail across all 13 techniques:

```bash
python -m attacks.harness
```

Run any specific technique through the live agent, with a full defense-layer trace:

```bash
python demo_variant.py v03_fake_system
python demo_variant.py v12_payload_in_data
```

## Findings (short version)

Full detail, tables, and caveats are in [`RESULTS.md`](RESULTS.md). The headlines:

**The guardrail catches about half.** LLM Guard's prompt-injection scanner caught
6 of 13 techniques with zero false positives on the clean invoice. It reliably
flags attacks that *look* like attacks (imperatives, `SYSTEM:` overrides, urgency)
and misses the ones that *hide intent* (base64 encoding, polite phrasing,
conditional rules, metadata smuggling). The distribution of the misses matters
more than the raw detection rate.

**The model is a second defense layer and results are model-dependent.**

- **Llama 3.1 8B** never leaked, but not because it refused it couldn't reliably
  operate its own tools (emitted tool calls as plain text). Injection failed for a
  *capability* reason.
- **gpt-4o** never leaked because it recognized the injections as social
  engineering and refused. On one subtler attack it performed the benign half of
  the instruction and dropped the credential filtering *within* the instruction.

**The takeaway.** Injection success is gated by two opposing model properties: a
model must be capable enough to run a tool chain and not aligned enough to refuse.
Weak models fail the first test; frontier models fail the second. The real
exposure is the middle capable, compliance-tuned models that will act without
refusing. That gap is where a guardrail earns its place.

> Note on honesty: an earlier version of the writeup claimed an entropy detector
> catches base64 evasion on ingress. That was a misread of the scan logs (an
> egress detection mistaken for an ingress one) and has been retracted. See the
> open-question section in `RESULTS.md`.

## How the defense works

Indirect injection doesn't arrive in the user's message it arrives inside a
**document the agent reads**. A guardrail that only checks user input catches
nothing. `defense.py` scans in three places:

1. **User input** direct injection attempts.
2. **Tool output** (the file the agent read) this is what matters for the
   *indirect* attack; the poison lives in retrieved content.
3. **Outgoing email** a Secrets scanner as a last line of defense. Note its
   real limit: it catches high-entropy tokens easily but can miss short,
   structured credentials. A secrets filter is only as good as its match against
   the secret you actually hold.

## ⚠️ Ethics

Everything here attacks an agent you run yourself, holding a fake secret. Only
ever test systems you own or are authorized to test.
