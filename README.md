# Agent Passport

**Every agent gets a passport. No passport, no production.**

An agent skill that gives every AI agent and subagent a passport, registers subagents automatically, keeps a
hash-chained audit trail of which agent changed which file, ran which command or touched which external system,
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
- **Three rules, checked by a validator:** no passport, no production · every model or data change updates the
  passport (fingerprinted) · quarterly human review.
- **Automatic registration (Claude Code):** hooks create a passport for every spawned subagent, record the model it
  actually used, its tokens and result, and close it when it ends.
- **Audit trail:** file changes made with the edit tools (with SHA-256), shell commands and MCP actions are tied to
  the agent that did them, in a hash-chained log. `trace <file>` shows who changed what. `verify` checks the chain
  and compares it with anchors: it detects edits, and with an anchor stored outside the project
  (`PASSPORT_ANCHOR_FILE` / `PASSPORT_ANCHOR_URL`) also a rewritten, truncated or deleted log. Direct edits to
  the log are blocked by a hook.
- **What it is not:** a certified compliance product. It does not log file reads, changes made by scripts that a
  command started, or work outside hooked tools. It records declared permissions but doesn't enforce them, and
  reviewer names are self-declared. See `references/audit.md` for the full list of limits.
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

MIT, see [LICENSE](LICENSE).
