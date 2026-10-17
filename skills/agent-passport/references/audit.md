# Audit and incident investigation

This skill is a governance aid, not certified or designated tooling: it is not endorsed by ISO, NEN or any certification body. When you talk to users or auditors, present the registry as supporting evidence that helps with audits, never as proof of compliance.

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
| `status` / `seal` / `review` | lifecycle changes, sealed passport changes and reviews, with the real time and whether they were recorded from inside an agent session |
| `file_change` | Write/Edit/MultiEdit/NotebookEdit: file path, acting agent, tool, session, SHA-256 of the file after the change, size |
| `command` | shell commands (Bash/PowerShell) and external actions through MCP servers: acting agent, redacted command or input, whether it failed |
| `session_end` | when and why a session closed (an anchor is written at the same moment) |
| `blocked` | an attempt to edit the audit log directly, which was refused |
| `hook_error` | a gap: the hook failed and the trail may be incomplete around this time |

The passports add the context an auditor asks for: model and version, hosting region, permissions, data sources, owner, reporting line, human-in-the-loop rule, review history and the changelog.

**Not recorded** (state this honestly in an audit):
- **File reads.** Reading is not logged, so an agent that only read data leaves no file trail. Its passport's permissions and data dependencies document what it could read.
- **Changes made outside the hooked tools**, for example by a human in an editor, by a script that a command started (only the command itself is logged), or by agents on platforms without hooks unless they call `spawn`/`end`.
- **Full file contents and diffs.** Only the hash after each change is stored. Use version control (git) for the diff and match it to the hash.
- **Secrets.** They are redacted on purpose. The pattern-based redaction is best effort, so keep secrets out of commands anyway.
- **Enforcement of permissions.** Passports record the permissions you declare. Whether the agent actually stays within them is up to the agent platform's own permission settings.
- **Who approved.** Reviewer and `--by` names are self-declared. Reviews recorded from inside an agent session are flagged, but real approval with identity (a signed commit, a PR approval) has to come from your process.
- **Completeness under failure.** Hooks fail open, so a crashed hook never stops work. Each failure is written to the trail as `hook_error` and flagged by `validate`.

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
5. **Check the trail.** Run `verify`, ideally with your external anchors (`--anchors <file>` or `--head COUNT:HASH`). Record the output with the incident.
6. **Act.** Use `status <ID> suspended|killed --reason "incident <ref>"` for a persistent agent. If the passport was wrong (for example a permission it shouldn't have had), fix it and `seal` with the incident reference. Never edit the log.

## 3. Keeping the evidence trustworthy

- **The log is hash-chained, and that alone is not enough.** Every entry stores the hash of the previous one, so a careless edit, deletion or reordering makes `verify` fail. The chain uses no secret key, though. Anyone who can write to the folder can rewrite the whole log and recompute every hash, and that includes an agent running as your user.
- **Anchors make it hold up.** At every session end, and whenever you run `anchor`, the log's head (entry count and last hash) is written to `anchors.jsonl`. If `PASSPORT_ANCHOR_FILE` or `PASSPORT_ANCHOR_URL` is set, it is also sent out of reach. `verify` compares the log with every anchor it can find, so a rewritten, truncated or deleted log is detected against an external anchor. Without one, `verify` says so.
- **Direct edits are blocked.** A PreToolUse hook refuses Write/Edit on `activity.jsonl` and `anchors.jsonl`, and refuses shell commands that would modify them. A determined actor with shell access can still find other ways, which is why the external anchor matters.
- **Never edit or delete** `activity.jsonl` or passports. Corrections are made with new entries (`seal`, `status`, `end`).
- **Retention:** keep the folder for at least as long as your policy requires. The EU AI Act asks deployers of high-risk systems to keep logs for at least six months. Many ISO 27001 logging policies require longer.
- **Access:** limit who can rewrite git history on the branch that holds the registry (protected branch).

## 4. Mapping to standards

This is how the registry can support common controls. It is supporting evidence next to your documented process, not a control by itself and not certification. Confirm clause references against the edition your auditor uses.

| Framework | Topic | What the registry provides |
|---|---|---|
| ISO/IEC 42001 (AI management system) | Inventory and documentation of AI systems and their resources; life-cycle records; event logging; human oversight; third-party/supplier AI | Passports (purpose, model, provider, hosting, data, owner, human-in-the-loop), status lifecycle and changelog, activity log, quarterly review records |
| ISO/IEC 27001:2022 Annex A | 5.9 inventory of assets · 5.18 access rights (review records) · 8.15 logging (partially) · 8.32 change management (partially) | Agents as inventoried assets, declared permissions and `who_can_invoke` (documented, not enforced), the review history, the hash-chained log (stronger with external anchors), and rule 2 (sealed changes). It is input for, not a substitute for, 8.16 monitoring, 5.15 access control or 5.23 cloud-service management |
| NEN 7510 (healthcare information security, built on ISO 27001) | Same controls as above; logging who accessed patient data (see also NEN 7513) | `contains_personal_data` per data source, the data-residency warning, and per-agent attribution of changes and external actions. **It does not meet the healthcare access-logging requirement**: reads are not logged. Use it next to the access logging of the systems that hold the patient data |
| EU AI Act | Mainly relevant if an agent is part of a high-risk system: record-keeping (Art. 12, which is the provider's duty), deployer log retention (Art. 26), human oversight (Art. 14) | An inventory with `risk.eu_ai_act` classification, `human_in_the_loop` per agent, model and provider per run. For most coding and back-office agents this is good practice, not a legal logging obligation |

For an audit, hand over:
- `REGISTRY.md`, or `registry.html` (the organogram, Files and Commands tabs);
- the output of `validate`, `verify` and `report --since <period start>`;
- the git history of `agent-passports/`.
