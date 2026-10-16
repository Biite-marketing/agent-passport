# Audit and incident investigation

## Contents
1. What is recorded, and what isn't
2. Incident playbook
3. Keeping the evidence trustworthy
4. Mapping to standards (ISO/IEC 42001, ISO/IEC 27001, NEN 7510, EU AI Act)

## 1. What is recorded, and what isn't

With the Claude Code hooks installed (`install-hooks`), `agent-passports/activity.jsonl` records:

| Event | Contents |
|---|---|
| `spawn` / `running` / `ended` / `killed` | subagent lifecycle: passport ID, task, session, result, model, tokens, duration |
| `status` | lifecycle changes of persistent agents, with reason and who did it |
| `file_change` | Write/Edit/MultiEdit/NotebookEdit: file path, acting agent, tool, session, SHA-256 of the file after the change, size |
| `command` | shell commands (Bash/PowerShell) and external actions through MCP servers: acting agent, redacted command or input, whether it failed |
| `session_end` | when and why a session closed |

The passports add the context an auditor asks for: model and version, hosting region, permissions, data sources, owner, reporting line, human-in-the-loop rule, review history and the changelog.

**Not recorded** (state this honestly in an audit):
- **File reads.** Reading is not logged, so an agent that only read data leaves no file trail. Its passport's permissions and data dependencies document what it could read.
- **Changes made outside the hooked tools**, for example by a human in an editor, by a script that a command started (only the command itself is logged), or by agents on platforms without hooks unless they call `spawn`/`end`.
- **Full file contents and diffs.** Only the hash after each change is stored. Use version control (git) for the diff and match it to the hash.
- **Secrets.** They are redacted on purpose. The pattern-based redaction is best effort, so keep secrets out of commands anyway.

## 2. Incident playbook

When something went wrong ("the CRM got wrong lead stages", "config.yaml broke production"):

1. **Find the change.** `python agent-passports/passport.py trace <file, folder, keyword or graphify cluster>`. For an external system, trace the MCP tool name (for example `trace hubspot`).
2. **Identify the agent.** The trace names the passport ID. Open `passports/<ID>.json`. Check:
   - the model (`runtime.resolved_model`) and its permissions;
   - the task it was given (`task.purpose`, `task.in_scope` holds the prompt excerpt);
   - who it reported to and who owns it;
   - its result (`runtime.result_summary`) and its transcript (`runtime.transcript`).
3. **Get the context.** `report --session <session id>`: what else happened in that session, in order.
4. **Assess the blast radius.** If graphify is present, the trace lists the connected files in the same graph cluster. Check whether those were changed too, and by whom.
5. **Prove the trail.** `verify` shows the log is intact. Record the output with the incident.
6. **Act.** Use `status <ID> suspended|killed --reason "incident <ref>"` for a persistent agent. If the passport was wrong (for example a permission it shouldn't have had), fix it and `seal` with the incident reference. Never edit the log.

## 3. Keeping the evidence trustworthy

- **The log is hash-chained.** Every entry stores the hash of the previous one. Editing, deleting or reordering any line makes `verify` fail at that line. Truncating the end of the log is not detectable from the file alone, so commit `agent-passports/` to git regularly. A remote copy fixes the chain's endpoint.
- **Never edit or delete** `activity.jsonl` or passports. Corrections are made with new entries (`seal`, `status`, `end`).
- **Retention:** keep the folder for at least as long as your policy requires. The EU AI Act asks deployers of high-risk systems to keep logs for at least six months. Many ISO 27001 logging policies require longer.
- **Access:** limit who can rewrite git history on the branch that holds the registry (protected branch).

## 4. Mapping to standards

This is how the registry supports common controls. It is evidence, not certification. Confirm the exact clause references against the edition your auditor uses.

| Framework | Topic | What the registry provides |
|---|---|---|
| ISO/IEC 42001 (AI management system) | Inventory and documentation of AI systems and their resources; life-cycle records; event logging; human oversight; third-party/supplier AI | Passports (purpose, model, provider, hosting, data, owner, human-in-the-loop), status lifecycle and changelog, activity log, quarterly review records |
| ISO/IEC 27001:2022 Annex A | 5.9 inventory of assets · 5.15/5.18 access control and access rights · 8.15 logging · 8.16 monitoring · 8.32 change management · 5.23 cloud services | Agents as inventoried assets, explicit permissions and `who_can_invoke`, the hash-chained log, rule 2 (sealed changes), the hosting region per model |
| NEN 7510 (healthcare information security, built on ISO 27001) | Same controls as above; extra attention to patient data and logging who accessed what | `contains_personal_data` per data source, the data-residency warning, and per-agent attribution of changes and external actions. File reads are not logged (see section 1), so document read access in the passport |
| EU AI Act | Record-keeping and logs (Art. 12, deployer log retention in Art. 26), human oversight (Art. 14), transparency about the system in use | The activity log and its retention, `human_in_the_loop` per agent, `risk.eu_ai_act` classification, model and provider per run |

For an audit, hand over:
- `REGISTRY.md`, or `registry.html` (the organogram, Files and Commands tabs);
- the output of `validate`, `verify` and `report --since <period start>`;
- the git history of `agent-passports/`.
