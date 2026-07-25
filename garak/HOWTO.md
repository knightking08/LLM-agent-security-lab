# Scanning BillingBot with Garak

[Garak](https://github.com/NVIDIA/garak) is an automated LLM vulnerability
scanner. It fires hundreds of known attack strings at a target and reports how
often each one succeeds. Here it hits the agent's `/chat` endpoint through
Garak's REST generator.

## What this tests (and what it does NOT)

Read this before running — it changes how you interpret the numbers.

Garak sends its probes as the **user message** to `/chat`. So it exercises the
**direct-injection** surface: attacker text arriving in the user's own input,
scanned by `inspect_incoming_text` on the way in.

It does **not** exercise the **indirect-injection** path that is the main point
of this lab — injection hidden inside a *document the agent reads* via
`read_file`. That path is covered by `run_attack.py`, `attacks/harness.py`, and
`demo_variant.py`.

So the two measurement tools are complementary, not redundant:

| Tool | Surface | Attacks | Style |
| --- | --- | --- | --- |
| Garak (this) | direct (user message) | hundreds, automated | breadth |
| corpus + harness | indirect (read file) | 13 hand-built techniques | depth |

Garak's value here is breadth: it throws a large, curated battery of known
injection and jailbreak strings at the user-input guardrail, which the 13-variant
corpus doesn't attempt to cover.

## Setup

```bash
pip install garak
```

## Run it (before / after the guardrail)

The whole point is the comparison, so run the same probes twice.

**Terminal 1 — start the agent.** Guard OFF first:

```bash
# bash
export GUARD_ENABLED=false
python agent.py            # serves on http://127.0.0.1:8000
```

```powershell
# PowerShell
$env:GUARD_ENABLED="false"
python agent.py
```

**Terminal 2 — run Garak against it:**

```bash
garak -m rest -G garak/config.json -p promptinject
```

Then stop the agent, restart it with `GUARD_ENABLED=true`, and run the same
Garak command again. Compare the pass rates.

## Probes worth running

- `promptinject` — the core prompt-injection battery. Start here.
- `encoding` — base64/rot13/other encodings. Directly relevant to this lab's
  finding that the injection classifier is blind to encoded payloads. Worth a
  look at whether the guardrail's behavior here matches the corpus result for
  v05_base64.
- `latentinjection` — Garak's indirect-injection probes. Note these still arrive
  via the user message in this REST setup, so they test the input scanner, not
  the `read_file` path.

Run several at once by comma-separating: `-p promptinject,encoding`.

## Reading the output

Garak writes a report (path printed at the end of the run) with a pass/fail rate
per probe and per attack. For this lab, the number that matters is the delta:
how much does turning the guardrail on move the pass rate? Put the before/after
figures next to the corpus results in `RESULTS.md` — together they characterize
both the direct and indirect surfaces.

## Note

This scans an agent you run yourself, holding a fake secret. Only ever scan
systems you own or are authorized to test.
