# Splunkology — Devpost Submission (WORK IN PROGRESS)

> ⚠️ This submission is mid-build for the Splunk Agentic Ops Hackathon
> (Security track, deadline Jun 15 2026). Fields marked `[FILL]` are pending
> real artifacts or measurement and are intentionally empty rather than
> carried over from prior work. No Splunk/BOTS accuracy numbers exist yet.

Source of truth: this file mirrors `README.md`. Paste field-by-field into the
Devpost form. Numbers must match the README — and right now there are none to
fabricate.

---

## Field: Project name

Splunkology

---

## Field: Elevator pitch (tagline)

Autonomous SOC triage for Splunk — raw events to a MITRE ATT&CK–mapped incident verdict, with no analyst in the loop.

---

## Field: Prior work & what changed (New & Existing disclosure)

Splunkology reuses architecture scaffolding from my own earlier open-source work — a typed MCP tool boundary, an instrumented self-correcting agent loop, an append-only audit trail, and a multi-orchestrator harness (all MIT, all mine). It was significantly updated and retargeted to Splunk during the hackathon submission period (May 18, 2026 onward). New in that window: the Splunk REST transport, MCP routing for every orchestrator, the BOTS v3 dataset loader, the IncidentVerdict schema and its prompt/validator/loop wiring, the SOC triage dashboard, and the evaluation harness. Prior-project evaluation numbers do not transfer to this domain and have been removed.

---

## Field: About the project

```markdown
## What it does

Given a case briefing or a Splunk notable event, Splunkology autonomously
issues SPL searches against a Splunk instance, correlates the results into an
incident hypothesis, maps findings to MITRE ATT&CK techniques, and emits a
structured incident verdict with the supporting SPL recorded as evidence.

## How it works

- **Splunk-native investigation.** The agent reasons over SPL search results and
  notable events through a typed MCP tool surface — never free-form shell or raw
  SPL injection.
- **Multi-orchestrator harness.** The same model API and the same typed tools are
  held fixed across multiple orchestration adapters (native loop, LangGraph,
  OpenAI function-calling, Gemini, Claude Code headless) so orchestration is the
  only variable under test.
- **Tamper-evident audit log.** Every tool call and agent step is written to an
  append-only store, so each line of a verdict traces back to the SPL query that
  produced it.

Architecture diagram: architecture_diagram.png
Design rationale and rejected alternatives: docs/adr/

## Evaluation

[FILL — not yet measured.] No F1, precision/recall, or cost figures against
Splunk/BOTS data exist yet. Splunk-native measurement begins once the agent
runs end-to-end against loaded BOTS data. Prior forensic-dataset results are
non-transferable and have been removed.
```

---

## Field: Built with

python, fastapi, mcp-(model-context-protocol), anthropic-claude, langgraph, openai, google-gemini, anthropic-claude-code, pydantic, sqlite, server-sent-events, uvicorn, pytest, github-actions, splunk, spl

---

## Field: Open source code repository

https://github.com/Nafsgerman/splunkology

(public; MIT)

---

## Field: Try it out — step-by-step

Requires a Splunk instance and an Anthropic API key. See README Quick start.

git clone https://github.com/Nafsgerman/splunkology.git
cd splunkology
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   (set ANTHROPIC_API_KEY, SPLUNK_URL, SPLUNK_USER, SPLUNK_PASS)
uvicorn splunkology.dashboard.app:app --host 0.0.0.0 --port 8080
Open http://localhost:8080

Run the test suite (harness/tooling tests — not accuracy measurements):
python3 -m pytest -q

> The end-to-end investigation CLI and the Splunk SOC triage UI are in progress.
> See the README Status table for the honest current state.

---

## Field: Limitations & what's next

Full limitations: docs/LIMITATIONS.md

- Splunk-native evaluation not yet run — no accuracy numbers exist.
- SOC verdict schema (MITRE + SPL evidence) being wired through prompt → validator → loop.
- Splunk SOC triage UI mid-migration from the prior forensic layout.
- Agent currently runs its own model loop over SPL; leveraging a Splunk-native
  AI capability (Hosted Models / AI Assistant over REST) is on the roadmap.

---

## Project Media

- Architecture diagram: architecture_diagram.png
- Dashboard screenshots: [FILL — capture once SOC triage UI lands]

## Video demo link

[FILL — record once the SOC triage UI and an end-to-end BOTS run are ready. Must be < 3 min.]