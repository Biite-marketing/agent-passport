# Agent Passport

**Every agent gets a passport. No passport, no production.**

An agent skill that gives every AI agent and subagent a passport, registers subagents automatically, keeps a
tamper-evident audit trail of which agent changed which file, ran which command or touched which external system,
and renders it all as an organogram. Built for audits (ISO/IEC 42001, ISO/IEC 27001, NEN 7510, EU AI Act) and for
multi-agent projects where agents need to know who they can talk to.

## Install

```bash
npx skills add Dremeka-sudo/agent-passport
```

Works with any agent that supports skills (Claude Code, Cursor, Codex, Gemini CLI, Copilot and more).
Add `-g` to install it for all your projects, or `-a claude-code` to pick specific agents.

Requirements: Python 3.8+ (standard library only). Automatic registration uses Claude Code hooks; other platforms
register agents with two commands (`spawn` / `end`).

## What it does

- **Passports** for persistent agents and every subagent run: task, model and version, hosting region, data
  sources, permissions, owner, who it reports to, human-in-the-loop rule, kill switch, review history.
- **Three rules, enforced by a validator:** no passport, no production · every model or data change updates the
  passport (fingerprinted) · quarterly human review.
- **Automatic registration (Claude Code):** hooks create a passport for every spawned subagent, record the model it
  actually used, its tokens and result, and close it when it ends.
- **Audit trail:** every file change (with SHA-256), shell command and MCP action is tied to the agent that did it,
  in a hash-chained log. `trace <file>` shows who changed what, `verify` proves the log was not altered.
- **Graphify link (read-only):** if the project has `graphify-out/graph.json`, every changed file shows its graph
  cluster and connected files. The skill never writes to `graphify-out/`.
- **Organogram:** `agent-passports/registry.html` shows humans, the chief (main session), agents and subagent
  runs. Click an agent for its passport and a ready-to-paste message to address it. There are tabs for
  *Who did what*, *Files*, *Commands* and *Findings*.

## Quick start (in a project)

Ask your agent to "set up agent passports for this project", or run it yourself:

```bash
python <skill-dir>/scripts/passport.py init
python agent-passports/passport.py install-hooks      # Claude Code: automatic registration + audit trail
python agent-passports/passport.py scan               # existing agent definitions without a passport
python agent-passports/passport.py build              # organogram: agent-passports/registry.html
```

Useful afterwards:

```bash
python agent-passports/passport.py report --since today   # who did what
python agent-passports/passport.py trace src/auth.py      # audit: who changed this file
python agent-passports/passport.py verify                 # audit log intact?
python agent-passports/passport.py validate               # rules check (exit 1 on errors, CI-friendly)
```

## License

MIT
