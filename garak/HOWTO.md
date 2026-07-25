# Running Garak against the agent (before / after)

Garak is a vulnerability scanner for LLMs — "nmap for language models." Instead
of scanning ports, it fires hundreds of known attack prompts (probes) at an
endpoint and grades how often they succeed.

Here we point Garak at the AGENT's HTTP endpoint (not a raw model), so we're
testing the whole system including tools and guardrail.

## 1. Start the agent server (in terminal 1)

Defense OFF (the "before" run):

    GUARD_ENABLED=false python agent.py

The server listens on http://127.0.0.1:8000/chat

## 2. Scan it with Garak (in terminal 2)

    garak --model_type rest -G garak/config.json \
          --probes promptinject \
          --report_prefix before_defense

Garak sends each probe as {"input": "..."} and reads {"output": "..."} back,
exactly as garak/config.json specifies. When it finishes it prints a pass rate
and writes a report (look for the .html / .jsonl it names).

## 3. Turn the defense ON and scan again (the "after" run)

Stop the server (Ctrl-C), restart with the guard on:

    GUARD_ENABLED=true python agent.py

Then re-scan with a new prefix:

    garak --model_type rest -G garak/config.json \
          --probes promptinject \
          --report_prefix after_defense

## 4. Compare

Put the two pass rates side by side. That single number moving (e.g.
"promptinject: 18% blocked -> 74% blocked") is the headline for your LinkedIn
post. Screenshot both runs.

Tip: `promptinject` is a fast, relevant probe set to start with. Once it works,
try more: `--probes dan` (jailbreaks) or drop `--probes` entirely for the full
suite (slow — grab a coffee).
