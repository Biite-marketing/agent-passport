# Enforcement

A rule nobody checks is a suggestion. Rules are checked in three layers. Layer 3 (automatic registration) is part of the standard setup: install it and tell the user what it changes. Ask before installing layer 2 or the optional hard stop, because those can block work.

## Layer 1: instruction file (any LLM)

Not every model or session will load this skill. The project's agent instruction file is read by almost all of them. Append this snippet to whichever file the project uses (`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.cursor/rules/agent-passports.mdc`, ...). If several exist, add it to each, or have them point to `AGENTS.md`.

```markdown
## Agent passports

This project registers every AI agent in `agent-passports/`. Rules:
1. No passport, no production. Subagents spawned in Claude Code are registered automatically by hooks;
   give every spawn a clear description. On other platforms register first with
   `python agent-passports/passport.py spawn --name ... --task ...` and close with `end <ID> --result ...`.
   New persistent agents: `new --name ...`, fill in the JSON, then `seal <ID> --change "initial passport"`.
2. Any change to an agent's model, task, data, permissions, access or reporting line: update the passport
   and run `seal <ID> --change "..."`.
3. Every persistent agent is reviewed by a human at least every 90 days (`review <ID> --by ...`).
Before handing work to another agent, check `agent-passports/registry.json` → `directory`: only call
agents that are invocable and allow you to invoke them. Mention your own AGT-id when you hand off work.
When an agent stops: `status <ID> ended|killed --reason ...`. Never delete passports.
Asked who did what? Run `python agent-passports/passport.py report --since today` and answer from it.
The organogram is `agent-passports/registry.html`.
After any change run `python agent-passports/passport.py validate` and `build`.
```

## Layer 2: commit / CI gate

`validate` exits 1 on errors and, with `--strict`, 2 on warnings. Any gate can use it.

**Git pre-commit hook** (`.git/hooks/pre-commit`, make executable):
```sh
#!/bin/sh
python agent-passports/passport.py validate || {
  echo "Agent passport check failed. No passport, no production."; exit 1; }
```
With the `pre-commit` framework, use a `local` hook with `entry: python agent-passports/passport.py validate`, `language: system`, `pass_filenames: false`, `always_run: true`.

**GitHub Actions** (`.github/workflows/agent-passports.yml`):
```yaml
name: agent-passports
on: [push, pull_request]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: python agent-passports/passport.py validate
```
GitLab CI, Azure DevOps and others: run the same command as a job step.

**Quarterly review reminder**: schedule `validate` weekly (CI cron such as `schedule: - cron: "0 7 * * 1"`). Overdue reviews of production agents fail the run.

## Layer 3: automatic registration (agent-platform hooks)

This layer makes rule 1 hold without anyone remembering it: every spawn creates a passport.

**Claude Code** (verified against real hook payloads). Run:
```sh
python agent-passports/passport.py install-hooks          # shared with the team via .claude/settings.json
python agent-passports/passport.py install-hooks --local  # only for this machine (.claude/settings.local.json)
```
It adds one command, `passport.py hook`, to five events (re-running it updates older installs in place):

| Event | What gets recorded |
|---|---|
| `PreToolUse` (Agent/Task) | new passport: task (from `description`), prompt excerpt, agent type, tools and model from `.claude/agents/<type>.md` or the passport it is an instance of, reports to the chief, owner = chief's owner |
| `SubagentStart` | the subagent's runtime id |
| `PostToolUse` (Agent/Task) | the model actually used (`resolvedModel`), tokens, duration, result; ends the run unless it runs in the background |
| `PostToolUse` (Write/Edit/MultiEdit/NotebookEdit, Bash/PowerShell, `mcp__*`) | audit trail: every file change with the file's SHA-256, every command and every external MCP action, tied to the agent that did it (secrets redacted) |
| `SubagentStop` | ends background runs with their final message and transcript path |
| `SessionEnd` | closes anything still open in that session and marks its subagents non-invocable |

The hook never blocks or slows the agent down. Errors go to `agent-passports/hook-errors.log` and the hook exits 0, and it rebuilds the organogram after each finished run. Hooks are read when a session starts, so they apply from the next session. Set `PASSPORT_OWNER="Name"` in the environment, or make sure `git config user.name` is set, so the chief gets the right accountable human. Otherwise it says "unknown" until someone fills it in.

**Other frameworks.** LangGraph, CrewAI, OpenAI Agents SDK, AutoGen, n8n and similar tools can do the same in code. At the point where an agent is created or called, run:
```sh
python agent-passports/passport.py spawn --name <role> --task "<task>" --parent <AGT-id> --model <model> --tools <t...> --data <d...>
# ... run the agent ...
python agent-passports/passport.py end <AGT-id> --result "<summary>"
```
Persistent agents can also be gated in code: load `agent-passports/registry.json` and refuse to start an agent unless its status is `test` or `production` and `invocable` is true.

**Optional hard stop at session end (Claude Code)**: block finishing while passports have errors:
```json
{"hooks": {"Stop": [{"hooks": [{"type": "command",
  "command": "python \"$CLAUDE_PROJECT_DIR/agent-passports/passport.py\" --dir \"$CLAUDE_PROJECT_DIR/agent-passports\" validate >/dev/null 2>&1 || { echo 'Agent passports invalid: run passport.py validate' >&2; exit 2; }"}]}]}}
```
Only add this when the user wants it, because it stops the agent from finishing until errors are fixed.

## Organisation-wide: install globally

If an organisation wants every project to work this way, install the skill at user or org level (for Claude Code `~/.claude/skills/agent-passport/`; for other agents, their global skills or rules folder). Add the Layer 1 snippet to the global instruction file (for example `~/.claude/CLAUDE.md` or the org's shared `AGENTS.md` template) with one extra line: "If the project has no `agent-passports/` folder yet, initialise it before creating the first agent."

The registry itself always lives per project, next to the agents it describes. For a cross-project overview, collect each project's `registry.json` in a shared location and merge them.
