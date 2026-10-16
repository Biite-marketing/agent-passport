---
name: agent-passport
description: "Give every AI agent and subagent a passport before it goes live, register subagents automatically, and keep a tamper-evident audit trail and organogram: who exists, what each agent does, on which model, with which data and permissions, who it reports to, whether it can still be invoked, and which agent changed which file, ran which command or touched which external system (linked read-only to graphify when present). Use whenever an agent, subagent, bot, orchestrator or AI workflow is created, spawned, deployed, changed (model, tools, data, permissions), killed or reviewed; when someone asks which agents exist, for an agent organogram, who to hand work to, who did what, which agent changed a file or caused an incident; for audit evidence (ISO 42001, ISO 27001, NEN 7510, EU AI Act); or when agent-passports/ exists. Works with any LLM."
---

# Agent Passport

Every agent gets a passport. No passport, no production.

When an agent misbehaves, the questions are always the same: what does it do, on which model, with which data, since when, with which permissions, and who answers for it? A passport answers those before anyone has to ask. The same registry tells agents who they can talk to, and lets the main agent (the **chief**) report who did what.

## The three rules

1. **No passport, no production.** An agent may not do real work until it has a passport. That includes subagents a chat spawns for a single task. In Claude Code, hooks register them automatically.
2. **Every material change updates the passport.** A change to the model, task, data, permissions, access or reporting line is recorded and sealed in the changelog.
3. **Quarterly review.** Every persistent agent is reviewed by a human at least every 90 days, like access rights.

Stopped agents are never deleted. They get status `killed` (stopped on purpose) or `ended` (a temporary agent that finished its job), so the trail stays for audits and incidents.

## What lives in the project

Everything is written to one folder in the project root, which humans and agents can both read:

```
agent-passports/
├── passports/AGT-0001.json   one passport per agent or subagent run (source of truth, never deleted)
├── activity.jsonl            hash-chained audit log: spawns, endings, status changes, every file change
│                             (with file hash), command and external MCP action, each tied to an agent
├── registry.html             the organogram: click an agent for its passport and a ready-to-paste message
├── REGISTRY.md               the same in text: findings, directory, who did what, every passport
├── registry.json             machine-readable directory for agents: who exists, who may call whom
├── passport.py               the tool (Python, no dependencies), copied in so any LLM, hook or CI can run it
└── README.md
```

## Roles in the organogram

- **Humans** are at the top. Every agent has an accountable human `owner`.
- **The chief** is the main session that talks to the user and spawns subagents. It gets one persistent passport per project (`role: chief`), which is created automatically on the first spawn if it doesn't exist yet.
- **Persistent agents** are defined once (for example in `.claude/agents/x.md`) and have a full, human-reviewed passport.
- **Subagent runs** are temporary (`kind: ephemeral`). Each spawn gets its own passport that reports to the chief. When the run is a custom agent with a persistent passport, it is linked through `instance_of` and inherits that passport's model, data and permissions.

## The tool

Before `init`, call `<skill-dir>/scripts/passport.py`. After `init`, use `agent-passports/passport.py`. Run everything from the project root.

| Command | Use |
|---|---|
| `init` | create `agent-passports/` |
| `install-hooks [--local]` | Claude Code: register every subagent automatically (writes `.claude/settings.json`) |
| `scan` | agent definitions in the project without a passport |
| `new --name N --kind K --platform P [--definition-ref path] [--owner H] [--reports-to R] [--role chief]` | skeleton for a persistent agent (starts in development) |
| `spawn --name N --task T [--parent ID] [--model M] [--tools ...] [--data ...] [--personal-data]` | one-step registration of a temporary agent on platforms without hooks |
| `end ID --result "..." [--killed]` | close a temporary agent and record what it delivered |
| `seal ID --change "..." --by WHO` | after every material edit: fingerprint, date, changelog |
| `status ID STATUS --reason "..." --by WHO` | lifecycle; `production` is refused while the passport is incomplete |
| `review ID --by NAME [--notes]` | record the quarterly review |
| `report [--since today\|YYYY-MM-DD] [--session ID]` | **who did what**: every subagent run with task, model, tools, time, tokens and result |
| `trace <file\|folder\|graphify cluster>` | **audit**: who changed it, when, with which tool, file hash after the change, related files in the graphify graph, and the passports of the agents involved |
| `verify` | prove the audit log was not edited, removed or reordered (hash chain) |
| `directory` | which agents can be invoked now, and how |
| `validate [--strict]` | check all rules; exit 1 on errors |
| `build` | regenerate registry.html, REGISTRY.md, registry.json |

The script calculates a fingerprint over `model`, `task`, `data_dependencies`, `permissions`, `access` and `reports_to`. If those fields change without `seal`, validation fails. That enforces rule 2 without relying on anyone's memory.

## Workflows

### Set up a project (do this the first time)

1. `python <skill-dir>/scripts/passport.py init`
2. **Turn on automatic registration.** In Claude Code, run `python agent-passports/passport.py install-hooks`. From then on every spawned subagent gets a passport, is closed when it finishes, and shows up in the organogram and the activity report, even when the model forgets this skill. Tell the user that this adds hooks to `.claude/settings.json` and that they take effect in new sessions. Use `--local` if they don't want to commit it for the team. For other platforms, see `references/enforcement.md`.
3. `scan` for existing agent definitions (Claude Code, Copilot, Cursor, Codex, Gemini folders). Ask the user about agents the scan can't see, such as n8n or Make flows, hosted assistants and agents in other repos.
4. Give each persistent agent a full passport (see below). Read its definition file and don't guess what you can read.
5. Add the snippet from `references/enforcement.md` to the project's agent instruction file (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursor/rules`, ...). That reaches LLMs that never load this skill.
6. `validate`, `build`, then tell the user where the organogram is: `agent-passports/registry.html`, which opens in any browser.

### Create a full passport for a persistent agent

1. `new` with what you already know. Pass `--definition-ref` for agents defined in a file, so scans and subagent runs link to it.
2. Replace every `TODO` in `passports/AGT-XXXX.json`. `references/passport-schema.md` explains each field and has examples; read it the first time.
3. `seal ID --change "initial passport" --by <who>`, then `status ID test|production --reason ...`.

Fill in facts, not hopes. If something is genuinely unknown (for example the hosting region of a vendor model), write `unknown` and tell the user. An honest `unknown` helps in an incident, while a guessed `EU` is a liability. Be precise about permissions: list the actual tools, skills, MCP servers, paths, network access and secret names. "Has access to everything" is exactly what a passport should reveal, so write it plainly when it's true.

### Subagents in a chat or multi-agent run

**With hooks installed (Claude Code):** you don't need to do anything to register the subagent. The hook creates the passport at spawn, takes the task from your `description`, takes tools and model from the agent definition, records the actual model, tokens and result when the subagent finishes, and closes it at the end of the session. Help it along: give every spawn a clear `description` (it becomes the task in the passport), and prefer named agent types with their own passport over general-purpose ones when the work touches sensitive data.

Afterwards you can still enrich an auto-registered passport, for example by adding the data it actually read to `data_dependencies`. Then `seal` it.

**Without hooks (any other platform or LLM):** register before spawning, close afterwards.
1. `spawn --name <role> --task "<what it will do>" --parent <your AGT-id> --model <model> --tools <tools...> --data <sources...> [--personal-data]` prints the new AGT-id.
2. Pass that AGT-id into the subagent's instructions so it can identify itself and look up peers.
3. `end <ID> --result "<what it delivered>"` when it finishes (`--killed` if you stopped it because it went wrong).

### "Who did what?"

When the user asks what agents did, which subagent touched what, or for a status report, run `report --since today` (or `--since <date>`, or `--session <id>`). Answer from it: which agent, which task, on which model, with which tools, how long, and what it delivered. Point to `registry.html` → "Who did what" for the visual version. Don't reconstruct this from memory; the log is the source of truth.

### Audits and incidents: "what went wrong, where, and which agent did it?"

With hooks installed, every file change (with the file's SHA-256 after the change), every shell command and every external action through an MCP server (CRM, mail, databases) is written to `activity.jsonl` and tied to the passport of the agent that did it. Changes made by the chief carry the chief's ID; changes made inside a subagent carry that subagent's ID. Secrets in commands are redacted before they are written.

To investigate:
1. `trace <file, folder or graphify cluster name>`: who touched it, when, with which tool, and in which session.
2. Open the passports of the agents involved: model, permissions, data, who they reported to, and their result (`runtime.result_summary`, plus the transcript path).
3. `report --session <id>` for the full context of that session.
4. `verify` to show the trail is intact. Each entry carries the hash of the previous one, so editing, deleting or reordering any line breaks the chain.

Treat `activity.jsonl` and `passports/` as evidence: never edit or delete them, and commit them to version control so history is preserved off-machine. `references/audit.md` has an incident playbook and how the trail maps to ISO/IEC 42001, ISO/IEC 27001, NEN 7510 and the EU AI Act.

### Graphify (read-only)

If the project has `graphify-out/graph.json`, the registry links to it: every changed file shows its graphify cluster ("community"), the graph nodes in that file, and the files connected to it in the graph. This shows the blast radius of a change, for example: "AGT-0007 changed `src/auth.py` in cluster *Session handling*; connected files are `api.py` and `middleware.py`."

This link is strictly read-only. The skill opens `graph.json` for reading and never writes, moves, rebuilds or updates anything in `graphify-out/`, and you shouldn't either as part of this skill. If the graph looks out of date (files marked "not in graph"), tell the user they can rebuild it with graphify themselves.

### Changing an agent

Edit the passport JSON (and the agent itself), then `seal ID --change "<what changed and why>" --by <who>`. Typical triggers: new model or model version, different hosting region, new or removed tools/skills/MCP servers, new data source, broader file or network access, new reporting line, changed escalation to humans. Write the change so someone reading it during an incident will understand it.

### Pausing, killing, ending

`status ID suspended|killed|ended --reason "..." --by WHO`. Never delete a passport file. If other agents still `talks_to` it, validation warns, so update them.

### Quarterly review

`validate` lists overdue reviews. For each agent, check that the passport still matches reality (definition file, actual permissions, model in use, data sources), fix and `seal` any differences, then `review ID --by <human reviewer>`. The reviewer is a human. An agent can prepare the review, but it should not sign off on itself. Auto-registered passports (the chief, subagent runs) show a warning until a human has completed and reviewed the chief.

### Working in a multi-agent setup: who can I talk to?

Before handing work to another agent, read `agent-passports/registry.json` (`directory`) or run `directory`. Only call agents that are `invocable`, whose `who_can_invoke` includes you or your role, and whose task and interface fit the request. If you need an agent that isn't there, don't improvise a hidden one: either let the hook register it by spawning normally, or create a passport first. Mention your AGT-id when you hand off work so the trail connects.

## Always finish with

`validate` and then `build`. Report errors and warnings to the user in plain words: which agent, which rule, and what to do about it. Never "fix" a validation error by weakening the passport (for example by deleting a data source to make a warning go away). Fix the agent, or tell the user.

## Reference files

- `references/passport-schema.md`: every field explained, with a full persistent example and a subagent-run example. Read it when filling in a passport.
- `references/audit.md`: incident investigation playbook, what is and isn't recorded, retention, and the mapping to ISO/IEC 42001, ISO/IEC 27001, NEN 7510 and the EU AI Act. Read it when preparing for an audit or investigating an incident.
- `references/enforcement.md`: auto-registration hooks (Claude Code and how to do the same elsewhere), the instruction-file snippet for any LLM, git/CI gates, and organisation-wide installation.
