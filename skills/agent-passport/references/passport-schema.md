# Passport schema

A passport is one JSON file: `agent-passports/passports/AGT-XXXX.json`. Field names are fixed so scripts and other agents can rely on them.

## Contents
1. Field reference
2. Status lifecycle
3. Example: persistent production agent
4. Example: ephemeral subagent spawned in a chat

## 1. Field reference

| Field | Required | What to write |
|---|---|---|
| `agent_id` | always | `AGT-0001` etc. Assigned by `new`; never reuse an ID, even after an agent is killed. |
| `name` | always | Short, stable role name (`invoice-checker`). |
| `kind` | always | `persistent` (lives on), `ephemeral` (spawned for a task, then ends), `workflow` (automation like n8n/Make/Zapier with an LLM step), `external` (vendor agent you use but don't build). |
| `platform` | always | Where it runs: `claude-code`, `claude-api`, `openai-assistants`, `langgraph`, `n8n`, `copilot-studio`, ... |
| `definition_ref` | if a file defines it | Path from project root to the definition (`.claude/agents/x.md`). Lets `scan` link file and passport. |
| `status` | always | See lifecycle below. |
| `invocable` | always | Can it be called right now? False for killed/ended unless it can be resumed. |
| `how_to_invoke` | production | Concrete: "Agent tool, subagent_type=invoice-checker", "POST /agents/invoice", "message session local_ab12". |
| `created_at` / `updated_at` | always | ISO dates. `seal` and `status` maintain `updated_at`. |
| `created_by` | recommended | Human, AGT-id or session that created it. For spawned subagents: the parent. |
| `owner` | always | The accountable **human**. Never an agent. |
| `reports_to` | production | AGT-id of the orchestrator, or a human. Where its output and escalations go. |
| `talks_to` | optional | AGT-ids it may hand work to or call. These become graph edges. |
| `model.provider` / `name` / `version` | production | Exact model ID or snapshot (`claude-sonnet-5-5`, `gpt-4.1-2025-04-14`). "latest" is not a version. |
| `model.hosting_region` | production | `EU (Frankfurt)`, `US`, `on-prem`, `unknown`. |
| `model.eu_hosted` | recommended | `true` / `false` / `null` if unknown. Drives the data-residency warning. |
| `task.purpose` | always | One or two sentences: what it does. |
| `task.in_scope` / `out_of_scope` | recommended | Lists. Out-of-scope is what stops scope creep. |
| `task.human_in_the_loop` | production | When it escalates to a human and how: thresholds, uncertainty, irreversible actions. "Never" is a valid but notable answer. |
| `interface.input` / `output` | production | What you give it and what comes back. Other agents read this to decide whether to call it. |
| `data_dependencies` | production | List of `{source, type, access, contains_personal_data}`. `type`: database, api, files, mailbox, web, vector-store... `access`: read / write / read-write. Use `[]` if it truly uses none. |
| `permissions.tools` | production | Every tool / MCP server / function it can call. |
| `permissions.skills` | optional | Skills or plugins loaded. |
| `permissions.file_access` | optional | Paths it may read or write: globs or folders (`invoices/`, `docs/*.md`), optionally with a note in brackets. `validate` compares this and `data_dependencies` with the sensitive paths the agent actually read, and warns about reads it doesn't cover. |
| `permissions.network` | optional | Domains or "none" / "unrestricted". |
| `permissions.secrets` | optional | Names of credentials it uses (never the values). |
| `permissions.can_spawn_agents` | always | `true` means every agent it spawns needs its own passport. |
| `access.who_can_invoke` | production | Humans, roles or AGT-ids allowed to call it. |
| `access.who_can_modify` | recommended | Who may change its prompt, tools or model. |
| `risk.level` | recommended | low / medium / high. |
| `risk.eu_ai_act` | recommended | minimal / limited / high / prohibited / unknown. |
| `risk.kill_switch` | production | How to stop it immediately, and who may. |
| `review.*` | production (persistent) | Set by `review`. Ephemeral agents are exempt. |
| `role` | optional | `chief` for the main session that talks to the user and spawns subagents (one per project). |
| `instance_of` | subagent runs | AGT-id of the persistent passport this run is an instance of. The run inherits its model, data and permissions. |
| `auto_registered` | set by hooks | `true` when a hook created the passport. Gaps then show as warnings, not errors, until a human completes them. |
| `runtime` | subagent runs | Set by hooks or `spawn`/`end`: `session_id`, `agent_id` (to resume it), `agent_type`, `started_at`, `ended_at`, `resolved_model`, `tokens`, `duration_ms`, `result_summary`, `transcript`. Not part of the fingerprint. |
| `fingerprint` | — | Set by `seal`. Don't edit by hand. |
| `changelog` | — | Appended by `seal`, `status`, `review`. |

## 2. Status lifecycle

```
development → test → production ⇄ suspended
                          ↓
                 killed (stopped on purpose)      ended (ephemeral, job done)
```

- Moving to `production` is refused while required fields are missing (rule 1).
- `killed` / `ended` set `invocable` to false unless `--still-invocable` is passed.
- Passports are never deleted.

## 3. Example: persistent production agent

```json
{
  "passport_version": 1,
  "agent_id": "AGT-0003",
  "name": "invoice-checker",
  "kind": "persistent",
  "platform": "claude-code",
  "definition_ref": ".claude/agents/invoice-checker.md",
  "status": "production",
  "invocable": true,
  "how_to_invoke": "Agent tool with subagent_type=invoice-checker; pass the invoice PDF path",
  "created_at": "2026-07-01",
  "updated_at": "2026-09-12",
  "created_by": "Sanne de Vries",
  "owner": "Sanne de Vries (Finance)",
  "reports_to": "AGT-0001",
  "talks_to": ["AGT-0004"],
  "model": {"provider": "Anthropic", "name": "claude-sonnet-5-5", "version": "claude-sonnet-5-5",
            "hosting_region": "EU (AWS Bedrock eu-central-1)", "eu_hosted": true},
  "task": {
    "purpose": "Checks incoming supplier invoices against purchase orders and flags mismatches.",
    "in_scope": ["match invoice lines to PO lines", "flag price or quantity differences"],
    "out_of_scope": ["approving payments", "contacting suppliers"],
    "human_in_the_loop": "Any mismatch above EUR 500 or any unknown supplier goes to the finance team queue; it never approves on its own."
  },
  "interface": {"input": "path to invoice PDF + PO number", "output": "JSON: match | mismatch with line-level reasons"},
  "data_dependencies": [
    {"source": "ERP purchase orders", "type": "api", "access": "read", "contains_personal_data": false},
    {"source": "invoices/ folder", "type": "files", "access": "read", "contains_personal_data": true}
  ],
  "permissions": {"tools": ["Read", "Grep", "erp-mcp:get_purchase_order"], "skills": ["pdf"],
                  "file_access": ["invoices/ (read)"], "network": ["erp.internal"], "secrets": ["ERP_READONLY_TOKEN"],
                  "can_spawn_agents": false},
  "access": {"who_can_invoke": ["AGT-0001", "finance team"], "who_can_modify": ["Sanne de Vries"]},
  "risk": {"level": "medium", "eu_ai_act": "minimal", "kill_switch": "Remove .claude/agents/invoice-checker.md or set status suspended; finance lead or IT"},
  "review": {"last_reviewed": "2026-09-12", "reviewed_by": "Sanne de Vries", "next_review_due": "2026-12-11"},
  "fingerprint": "set-by-seal",
  "changelog": [
    {"date": "2026-07-01", "change": "initial passport", "by": "Sanne de Vries"},
    {"date": "2026-09-12", "change": "model sonnet-4-6 -> sonnet-5-5; moved to Bedrock EU", "by": "Sanne de Vries"}
  ]
}
```

## 4. Example: ephemeral subagent spawned in a chat

With hooks installed this is created automatically and gets a `runtime` block. The example below is filled in by hand, as you would on a platform without hooks.

```json
{
  "passport_version": 1,
  "agent_id": "AGT-0017",
  "name": "competitor-research-worker",
  "kind": "ephemeral",
  "platform": "claude-code",
  "definition_ref": null,
  "status": "ended",
  "invocable": true,
  "how_to_invoke": "SendMessage to subagent 'competitor-research-worker' in session local_9f2a (until the session is archived)",
  "created_at": "2026-10-16",
  "updated_at": "2026-10-16",
  "created_by": "AGT-0001 (orchestrator, session local_9f2a)",
  "owner": "Daan (requested the research)",
  "reports_to": "AGT-0001",
  "talks_to": [],
  "model": {"provider": "Anthropic", "name": "claude-haiku-5-5", "version": "claude-haiku-5-5",
            "hosting_region": "unknown", "eu_hosted": null},
  "task": {
    "purpose": "One-off: collect public pricing pages of five named competitors and summarise them.",
    "in_scope": ["public websites"], "out_of_scope": ["logging in anywhere", "contacting anyone"],
    "human_in_the_loop": "Returns findings to the orchestrator; the human reviews before anything is published."
  },
  "interface": {"input": "list of competitor URLs", "output": "markdown table of plans and prices"},
  "data_dependencies": [{"source": "public web", "type": "web", "access": "read", "contains_personal_data": false}],
  "permissions": {"tools": ["WebSearch", "WebFetch"], "skills": [], "file_access": ["none"],
                  "network": ["public internet"], "secrets": [], "can_spawn_agents": false},
  "access": {"who_can_invoke": ["AGT-0001"], "who_can_modify": ["AGT-0001"]},
  "risk": {"level": "low", "eu_ai_act": "minimal", "kill_switch": "Stop the parent session"},
  "review": {"last_reviewed": null, "reviewed_by": null, "next_review_due": null},
  "fingerprint": "set-by-seal",
  "changelog": [
    {"date": "2026-10-16", "change": "initial passport", "by": "AGT-0001"},
    {"date": "2026-10-16", "change": "status production -> ended: delivered pricing table for 5 competitors", "by": "AGT-0001"}
  ]
}
```
