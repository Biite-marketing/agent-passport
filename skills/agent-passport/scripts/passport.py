#!/usr/bin/env python3
"""Agent Passport CLI. Python 3.8+, standard library only, so any LLM, git hook or CI job can run it.

Every agent gets a passport. No passport, no production.

Commands
  init                         create agent-passports/ in the project (copies this script into it)
  install-hooks                register every Claude Code subagent automatically (writes .claude/settings.json)
  hook                         entry point for agent-platform hooks; reads the event JSON on stdin
  new --name NAME [...]        create a passport skeleton, prints the new agent id and path
  spawn --name N --task T ...  register a temporary agent in one go (for platforms without hooks)
  end ID --result TEXT         close a temporary agent and record what it delivered
  seal ID --change TEXT        record a change: refresh fingerprint + updated_at, append changelog
  status ID STATUS --reason T  move through the lifecycle (production is gated by validation)
  review ID --by NAME          record the quarterly review
  scan                         list agent definitions in the project that have no passport
  validate [--strict]          check the rules; exit code 1 on errors (2 on warnings with --strict)
  report [--since D] [--session S]   who did what: the chief's activity report
  trace QUERY                  audit: who changed this file / folder / graphify cluster, when, with which hash
  verify                       prove the audit log was not altered (hash chain)
  build                        write registry.json, REGISTRY.md and registry.html (the organogram)
  directory [--json]           who can be invoked right now, and how

Global option --dir points at the agent-passports folder (default: ./agent-passports).
Set PASSPORT_TODAY=YYYY-MM-DD to fake today's date (useful for tests).
"""
import argparse
import datetime as dt
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

STATUSES = ["development", "test", "production", "suspended", "killed", "ended"]
TERMINAL = {"killed", "ended"}
KINDS = ["persistent", "ephemeral", "workflow", "external"]
REVIEW_DAYS = 90
ID_RE = re.compile(r"^AGT-\d{4,}$")
HOOK_BY = "auto-register hook"
SPAWN_TOOLS = {"Agent", "Task"}
FILE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
COMMAND_TOOLS = {"Bash", "PowerShell"}
TRACKED_TOOLS = SPAWN_TOOLS | FILE_TOOLS | COMMAND_TOOLS
SECRET_RE = re.compile(r"(?i)(bearer\s+\S+|(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[=:]\s*\S+|sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9]{20,})")

# Rule 2: a change in any of these fields is material and must be sealed with a changelog entry.
FINGERPRINT_FIELDS = ["model", "task", "data_dependencies", "permissions", "access", "reports_to"]

REQUIRED_ALWAYS = ["agent_id", "name", "kind", "platform", "status", "created_at", "updated_at",
                   "owner", "task.purpose"]
REQUIRED_PRODUCTION = ["model.provider", "model.name", "model.version", "model.hosting_region",
                       "task.human_in_the_loop", "data_dependencies", "permissions.tools",
                       "access.who_can_invoke", "reports_to", "interface.input", "interface.output",
                       "risk.kill_switch"]
REQUIRED_REVIEW = ["review.last_reviewed", "review.reviewed_by"]

# Where agents are commonly defined. Anything found here is invocable and therefore needs a passport.
DEFINITION_GLOBS = [
    ".claude/agents/**/*.md",
    ".github/agents/**/*.md",
    ".github/chatmodes/**/*.md",
    ".cursor/agents/**/*.md",
    ".codex/agents/**/*",
    ".gemini/agents/**/*",
    "agents/**/agent.json",
    "agents/**/agent.yaml",
    "agents/**/agent.yml",
]

# Built-in Claude Code subagent types and what they can touch.
BUILTIN_TOOLS = {
    "general-purpose": "all tools available to the parent session",
    "Explore": "read-only search and read tools (no edits)",
    "Plan": "read-only tools (no edits)",
    "claude-code-guide": "Glob, Grep, Read, WebFetch, WebSearch",
    "statusline-setup": "Read, Edit",
}

TEMPLATE = {
    "passport_version": 1,
    "agent_id": "",
    "name": "",
    "kind": "persistent",
    "platform": "TODO e.g. claude-code, openai-assistants, n8n, langgraph, copilot-studio",
    "definition_ref": None,
    "status": "development",
    "invocable": True,
    "how_to_invoke": "TODO how another agent or human calls this agent",
    "created_at": "",
    "updated_at": "",
    "created_by": "TODO human, AGT-id or session that created it",
    "owner": "TODO the accountable human (a person, never an agent)",
    "reports_to": "TODO AGT-id of the orchestrator or a human",
    "talks_to": [],
    "model": {
        "provider": "TODO",
        "name": "TODO",
        "version": "TODO exact model id or snapshot",
        "hosting_region": "TODO e.g. EU (Frankfurt), US, on-prem",
        "eu_hosted": None,
    },
    "task": {
        "purpose": "TODO one or two sentences: what it does",
        "in_scope": [],
        "out_of_scope": [],
        "human_in_the_loop": "TODO when and how it hands over to a human",
    },
    "interface": {"input": "TODO", "output": "TODO"},
    "data_dependencies": "TODO list of {source, type, access, contains_personal_data}",
    "permissions": {
        "tools": "TODO",
        "skills": [],
        "file_access": [],
        "network": [],
        "secrets": [],
        "can_spawn_agents": False,
    },
    "access": {"who_can_invoke": "TODO", "who_can_modify": []},
    "risk": {"level": "TODO low|medium|high", "eu_ai_act": "unknown",
             "kill_switch": "TODO how to stop it, and who may"},
    "review": {"last_reviewed": None, "reviewed_by": None, "next_review_due": None},
    "fingerprint": None,
    "changelog": [],
}


# ---------------------------------------------------------------- helpers

def today():
    forced = os.environ.get("PASSPORT_TODAY")
    return dt.date.fromisoformat(forced) if forced else dt.date.today()


def now_iso():
    return dt.datetime.now().isoformat(timespec="seconds")


def get(d, dotted):
    cur = d
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def is_missing(value):
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == "" or "TODO" in value
    return False


def parse_date(value):
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except (TypeError, ValueError):
        return None


def clip(text, n):
    text = " ".join(str(text or "").split())
    return text if len(text) <= n else text[:n - 1] + "…"


def fingerprint(p):
    material = {k: p.get(k) for k in FINGERPRINT_FIELDS}
    raw = json.dumps(material, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def root_dir(args):
    return Path(args.dir).resolve()


def project_root(root):
    return root.parent


def passport_path(root, agent_id):
    return root / "passports" / f"{agent_id}.json"


def load(root, agent_id):
    path = passport_path(root, agent_id)
    if not path.exists():
        sys.exit(f"No passport {agent_id} in {root / 'passports'}")
    return json.loads(path.read_text(encoding="utf-8"))


def save(root, p):
    p = {k: v for k, v in p.items() if not k.startswith("_")}
    path = passport_path(root, p["agent_id"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(p, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_all(root):
    agents, findings = {}, []
    for path in sorted((root / "passports").glob("*.json")):
        try:
            p = json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError) as e:
            findings.append(finding("ERROR", path.stem, "format", f"unreadable passport: {e}"))
            continue
        aid = p.get("agent_id") or path.stem
        if aid in agents:
            findings.append(finding("ERROR", aid, "identity", f"duplicate agent_id in {path.name}"))
        if aid != path.stem:
            findings.append(finding("ERROR", aid, "identity",
                                    f"file name {path.name} does not match agent_id {aid}"))
        p["_path"] = str(path)
        agents[aid] = p
    return agents, findings


def norm_ref(ref):
    ref = str(ref or "").replace("\\", "/")
    return ref[2:] if ref.startswith("./") else ref


def finding(level, agent_id, rule, message):
    return {"level": level, "agent_id": agent_id, "rule": rule, "message": message}


def log(p, change, by):
    p.setdefault("changelog", []).append({"date": today().isoformat(), "change": change, "by": by})


def seal_passport(p, change, by):
    p["updated_at"] = today().isoformat()
    p["fingerprint"] = fingerprint(p)
    log(p, change, by)


def next_id(root):
    nums = [int(m.group(1)) for f in (root / "passports").glob("AGT-*.json")
            if (m := re.match(r"AGT-(\d+)", f.stem))]
    return f"AGT-{(max(nums) + 1) if nums else 1:04d}"


def create_passport(root, p):
    """Write a new passport under a fresh ID. Safe when several hooks fire at once."""
    (root / "passports").mkdir(parents=True, exist_ok=True)
    for _ in range(50):
        p["agent_id"] = next_id(root)
        path = passport_path(root, p["agent_id"])
        try:
            with open(path, "x", encoding="utf-8") as fh:
                fh.write(json.dumps(p, indent=2, ensure_ascii=False) + "\n")
            return p
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate an agent id")


def entry_hash(entry):
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _last_line(path):
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        fh.seek(max(0, size - 65536))
        lines = fh.read().decode("utf-8", errors="replace").splitlines()
    return lines[-1] if lines else None


def _acquire_lock(root):
    lock = root / ".activity.lock"
    for _ in range(250):
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
            return lock
        except FileExistsError:
            try:
                if time.time() - lock.stat().st_mtime > 10:  # stale lock from a crashed hook
                    lock.unlink()
            except OSError:
                pass
            time.sleep(0.02)
    return None


def activity(root, event, **fields):
    """Append-only audit log. Every entry carries the hash of the previous one, so any later edit,
    deletion or reordering breaks the chain and shows up in `passport.py verify`."""
    root.mkdir(parents=True, exist_ok=True)
    path = root / "activity.jsonl"
    lock = _acquire_lock(root)
    try:
        prev = "GENESIS"
        if path.exists():
            last = _last_line(path)
            if last:
                try:
                    prev = json.loads(last).get("hash") or hashlib.sha256(last.encode("utf-8")).hexdigest()
                except ValueError:
                    prev = hashlib.sha256(last.encode("utf-8")).hexdigest()
        entry = {"ts": now_iso(), "event": event, **fields, "prev": prev}
        entry["hash"] = entry_hash(entry)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    finally:
        if lock:
            try:
                lock.unlink()
            except OSError:
                pass


def read_activity(root):
    path = root / "activity.jsonl"
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def redact(text):
    return SECRET_RE.sub("[REDACTED]", str(text or ""))


def rel_to_project(root, file_path):
    if not file_path:
        return None
    proj = project_root(root).resolve()
    try:
        return Path(file_path).resolve().relative_to(proj).as_posix()
    except (ValueError, OSError):
        return Path(file_path).as_posix()


def file_digest(root, rel):
    path = project_root(root) / rel if not Path(rel).is_absolute() else Path(rel)
    try:
        if path.is_file() and path.stat().st_size <= 50 * 1024 * 1024:
            return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size
    except OSError:
        pass
    return None, None


def git_user():
    try:
        out = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def read_frontmatter(path):
    meta = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return meta
    if not lines or lines[0].strip() != "---":
        return meta
    for line in lines[1:]:
        if line.strip() == "---":
            break
        m = re.match(r"^([A-Za-z_][\w-]*):\s*(.*)$", line)
        if m:
            meta[m.group(1)] = m.group(2).strip().strip('"\'')
    return meta


def find_definition(proj, agent_type):
    """Locate .claude/agents/<type>.md (by file name or by its frontmatter name)."""
    agents_dir = proj / ".claude" / "agents"
    if not agents_dir.exists():
        return None, {}
    for f in agents_dir.rglob("*.md"):
        meta = read_frontmatter(f)
        if f.stem == agent_type or meta.get("name") == agent_type:
            return f, meta
    return None, {}


# ---------------------------------------------------------------- rules

def scan_definitions(root, agents):
    proj = project_root(root)
    registered = {norm_ref(p.get("definition_ref")) for p in agents.values()}
    unregistered = []
    for pattern in DEFINITION_GLOBS:
        for f in proj.glob(pattern):
            if f.is_file() and root not in f.parents:
                rel = f.relative_to(proj).as_posix()
                if rel not in registered:
                    unregistered.append(rel)
    return sorted(set(unregistered))


def validate(root):
    agents, findings = load_all(root)
    now = today()
    for aid, p in agents.items():
        status, kind = p.get("status"), p.get("kind")
        auto = bool(p.get("auto_registered"))
        # Auto-registered passports are created by a hook, not a person. Gaps are reported as
        # warnings so they never block work, but they stay visible until a human completes them.
        gap = "WARNING" if auto else "ERROR"
        if not ID_RE.match(aid):
            findings.append(finding("ERROR", aid, "identity", "agent_id must look like AGT-0001"))
        if status not in STATUSES:
            findings.append(finding("ERROR", aid, "lifecycle", f"unknown status '{status}' (use {', '.join(STATUSES)})"))
        if kind not in KINDS:
            findings.append(finding("ERROR", aid, "identity", f"unknown kind '{kind}' (use {', '.join(KINDS)})"))
        for field in REQUIRED_ALWAYS:
            if is_missing(get(p, field)):
                findings.append(finding(gap, aid, "completeness", f"missing {field}"))

        # Rule 1: no passport, no production.
        if status == "production":
            required = REQUIRED_PRODUCTION + ([] if kind == "ephemeral" else REQUIRED_REVIEW)
            missing = [f for f in required if is_missing(get(p, f))]
            if missing:
                msg = "in production with an incomplete passport: " + ", ".join(missing)
                if auto:
                    msg = "auto-registered; a human must complete: " + ", ".join(missing)
                findings.append(finding(gap, aid, "rule-1-no-passport-no-production", msg))

        # Rule 2: every material change updates the passport.
        if p.get("fingerprint") is None:
            findings.append(finding("ERROR", aid, "rule-2-change-means-update",
                                    "never sealed; run: passport.py seal " + aid + " --change \"initial passport\""))
        elif p.get("fingerprint") != fingerprint(p):
            findings.append(finding("ERROR", aid, "rule-2-change-means-update",
                                    "model/task/data/permissions/access/reports_to changed without a sealed "
                                    "changelog entry; run: passport.py seal " + aid + " --change \"...\""))

        # Rule 3: quarterly review (persistent agents that are not retired).
        if kind != "ephemeral" and status not in TERMINAL:
            last = parse_date(get(p, "review.last_reviewed"))
            if last is None:
                if status != "production":  # production case already reported under rule 1
                    findings.append(finding("WARNING", aid, "rule-3-quarterly-review", "never reviewed"))
            else:
                age = (now - last).days
                if age > REVIEW_DAYS:
                    level = "ERROR" if status == "production" else "WARNING"
                    findings.append(finding(level, aid, "rule-3-quarterly-review",
                                            f"last review {age} days ago (limit {REVIEW_DAYS})"))
                elif age > REVIEW_DAYS - 14:
                    findings.append(finding("INFO", aid, "rule-3-quarterly-review",
                                            f"review due within {REVIEW_DAYS - age} days"))

        # Lifecycle consistency.
        if status in TERMINAL and p.get("invocable") and not get(p, "runtime.agent_id"):
            findings.append(finding("ERROR", aid, "lifecycle", f"status {status} but invocable is true"))

        # Relationships must point at known agents.
        targets = [("reports_to", p.get("reports_to"))] + [("talks_to", t) for t in (p.get("talks_to") or [])]
        for rel, target in targets:
            if isinstance(target, str) and ID_RE.match(target):
                if target not in agents:
                    findings.append(finding("ERROR", aid, "relationships", f"{rel} {target} has no passport"))
                elif agents[target].get("status") in TERMINAL and status not in TERMINAL:
                    findings.append(finding("WARNING", aid, "relationships",
                                            f"{rel} {target}, which is {agents[target].get('status')}"))

        owner = p.get("owner")
        if isinstance(owner, str) and ID_RE.match(owner):
            findings.append(finding("ERROR", aid, "accountability", "owner must be a human, not an agent"))

        if p.get("permissions", {}).get("can_spawn_agents") and status == "production" and not auto:
            findings.append(finding("INFO", aid, "permissions",
                                    "can spawn agents: every agent it spawns needs its own passport"))

        deps = p.get("data_dependencies")
        personal = isinstance(deps, list) and any(isinstance(d, dict) and d.get("contains_personal_data") for d in deps)
        if personal and get(p, "model.eu_hosted") is False and status not in TERMINAL:
            findings.append(finding("WARNING", aid, "data-residency",
                                    "processes personal data on a model hosted outside the EU"))

    for rel in scan_definitions(root, agents):
        findings.append(finding("ERROR", "-", "rule-1-no-passport-no-production",
                                f"agent definition {rel} has no passport (set definition_ref to link it)"))
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda f: (order[f["level"]], f["agent_id"]))
    return agents, findings


# ---------------------------------------------------------------- automatic registration (hooks)

def find_chief(agents):
    for aid, p in sorted(agents.items()):
        if p.get("role") == "chief" and p.get("status") not in TERMINAL:
            return p
    return None


def ensure_chief(root, platform="claude-code"):
    """The main session that talks to the user and spawns subagents. Created once per project."""
    agents, _ = load_all(root)
    chief = find_chief(agents)
    if chief:
        return chief
    owner = os.environ.get("PASSPORT_OWNER") or git_user() or "unknown (set the accountable human)"
    p = json.loads(json.dumps(TEMPLATE))
    p.update({
        "name": "chief",
        "role": "chief",
        "kind": "persistent",
        "platform": platform,
        "status": "production",
        "invocable": True,
        "auto_registered": True,
        "how_to_invoke": "Open the agent tool (e.g. Claude Code) in this project and talk to it",
        "created_at": today().isoformat(),
        "updated_at": today().isoformat(),
        "created_by": HOOK_BY,
        "owner": owner,
        "reports_to": owner,
    })
    p["model"] = {"provider": "Anthropic" if platform == "claude-code" else "unknown",
                  "name": "session model (varies per session, see activity log)",
                  "version": "varies per session", "hosting_region": "unknown", "eu_hosted": None}
    p["task"] = {"purpose": "Main agent session in this project: works with the user, spawns and coordinates "
                            "subagents, and reports who did what.",
                 "in_scope": [], "out_of_scope": [],
                 "human_in_the_loop": "Works directly with the user; the user approves risky actions."}
    p["interface"] = {"input": "requests from the user", "output": "answers, changes and reports to the user"}
    p["data_dependencies"] = "the project folder and whatever the user connects (not declared)"
    p["permissions"]["tools"] = "all tools allowed by the project's agent settings"
    p["permissions"]["can_spawn_agents"] = True
    p["access"]["who_can_invoke"] = [owner, "anyone with access to this project"]
    p["risk"]["kill_switch"] = "End the session; remove the hooks to stop auto-registration"
    seal_passport(p, "auto-registered as chief (main session) on first subagent spawn", HOOK_BY)
    return create_passport(root, p)


def find_by_runtime(agents, **match):
    hits = [p for p in agents.values()
            if all(get(p, f"runtime.{k}") == v for k, v in match.items() if v is not None)]
    hits.sort(key=lambda p: get(p, "runtime.started_at") or "", reverse=True)
    return hits[0] if hits else None


def on_spawn(root, payload):
    ti = payload.get("tool_input") or {}
    sid = payload.get("session_id")
    chief = ensure_chief(root)
    agents, _ = load_all(root)
    agent_type = ti.get("subagent_type") or "general-purpose"
    proj = project_root(root)
    def_file, meta = find_definition(proj, agent_type)
    def_ref = def_file.relative_to(proj).as_posix() if def_file else None
    parent = None  # the persistent passport of a custom agent definition, if any
    for p in agents.values():
        if p.get("kind") != "ephemeral" and (
                (def_ref and norm_ref(p.get("definition_ref")) == def_ref) or p.get("name") == agent_type):
            parent = p
            break

    p = json.loads(json.dumps(TEMPLATE))
    description = ti.get("description") or agent_type
    p.update({
        "name": ti.get("name") or agent_type,
        "kind": "ephemeral",
        "platform": chief.get("platform") or "claude-code",
        "definition_ref": def_ref,
        "status": "production",
        "invocable": True,
        "auto_registered": True,
        "instance_of": parent["agent_id"] if parent else None,
        "how_to_invoke": "Running; its result returns to the chief",
        "created_at": today().isoformat(),
        "updated_at": today().isoformat(),
        "created_by": f"{chief['agent_id']} (session {str(sid)[:8]})",
        "owner": chief.get("owner"),
        "reports_to": chief["agent_id"],
    })
    if parent:
        for field in ["model", "data_dependencies", "permissions", "risk"]:
            p[field] = json.loads(json.dumps(parent.get(field)))
        p["owner"] = parent.get("owner") or p["owner"]
    else:
        tools = meta.get("tools") or BUILTIN_TOOLS.get(agent_type) or "unknown (custom agent type)"
        p["model"] = {"provider": get(chief, "model.provider") or "unknown",
                      "name": ti.get("model") or meta.get("model") or "inherits the chief's model",
                      "version": "resolved at run time (see runtime.resolved_model)",
                      "hosting_region": get(chief, "model.hosting_region") or "unknown",
                      "eu_hosted": get(chief, "model.eu_hosted")}
        p["data_dependencies"] = "not declared at spawn; see task and transcript"
        p["permissions"]["tools"] = [t.strip() for t in tools.split(",")] if "," in tools else tools
        p["risk"]["level"] = "unknown"
        p["risk"]["kill_switch"] = "Stop the agent or end the chief's session"
    p["task"] = {"purpose": description,
                 "in_scope": [clip(ti.get("prompt"), 400)] if ti.get("prompt") else [],
                 "out_of_scope": [],
                 "human_in_the_loop": f"Returns its result to the chief ({chief['agent_id']}); "
                                      "the chief and the user decide what happens with it."}
    p["interface"] = {"input": "prompt from the chief", "output": "result returned to the chief"}
    p["access"] = {"who_can_invoke": [chief["agent_id"]], "who_can_modify": [chief["agent_id"]]}
    p["runtime"] = {"session_id": sid, "tool_use_id": payload.get("tool_use_id"), "agent_id": None,
                    "agent_type": agent_type, "background": bool(ti.get("run_in_background")),
                    "started_at": now_iso(), "ended_at": None, "resolved_model": None,
                    "tokens": None, "duration_ms": None, "result_summary": None, "transcript": None}
    seal_passport(p, "auto-registered at spawn" + (f" as instance of {parent['agent_id']}" if parent else ""), HOOK_BY)
    p = create_passport(root, p)
    activity(root, "spawn", agent_id=p["agent_id"], name=p["name"], task=description,
             session_id=sid, by=chief["agent_id"])


def finish(root, p, result, status="ended", reason=None):
    if p.get("status") in TERMINAL:
        if result and not get(p, "runtime.result_summary"):
            p["runtime"]["result_summary"] = clip(result, 600)
            save(root, p)
        return
    rt = p.setdefault("runtime", {})
    rt["ended_at"] = now_iso()
    if not rt.get("duration_ms") and rt.get("started_at"):
        started = dt.datetime.fromisoformat(rt["started_at"])
        rt["duration_ms"] = int((dt.datetime.fromisoformat(rt["ended_at"]) - started).total_seconds() * 1000)
    if result:
        rt["result_summary"] = clip(result, 600)
    p["status"] = status
    agent_id, sid = rt.get("agent_id"), rt.get("session_id")
    if agent_id and status == "ended":
        p["invocable"] = True
        p["how_to_invoke"] = f"Resume agent {agent_id} (e.g. SendMessage) in session {str(sid)[:8]}, only while that session is open"
    else:
        p["invocable"] = False
        p["how_to_invoke"] = "No longer invocable"
    p["updated_at"] = today().isoformat()
    log(p, f"status production -> {status}: " + clip(reason or result or "finished", 160), HOOK_BY)
    save(root, p)
    activity(root, status, agent_id=p["agent_id"], name=p.get("name"), task=get(p, "task.purpose"),
             session_id=sid, result=clip(result, 300), tokens=rt.get("tokens"),
             duration_ms=rt.get("duration_ms"), model=rt.get("resolved_model"))


def on_spawn_done(root, payload):
    agents, _ = load_all(root)
    p = find_by_runtime(agents, tool_use_id=payload.get("tool_use_id"))
    if not p:
        return
    resp = payload.get("tool_response")
    rt = p.setdefault("runtime", {})
    text = None
    if isinstance(resp, dict):
        rt["agent_id"] = resp.get("agentId") or rt.get("agent_id")
        if resp.get("status") == "completed":  # a background launch returns at once; its numbers come later
            rt["tokens"] = resp.get("totalTokens")
            rt["duration_ms"] = resp.get("totalDurationMs") or payload.get("duration_ms")
        model = resp.get("resolvedModel")
        if model and rt.get("resolved_model") != model:
            rt["resolved_model"] = model
            if not p.get("instance_of"):
                p["model"]["name"] = model
                p["model"]["version"] = model
                seal_passport(p, f"model resolved at run time: {model}", HOOK_BY)
        parts = resp.get("content") or []
        text = " ".join(c.get("text", "") for c in parts if isinstance(c, dict)) if isinstance(parts, list) else str(parts)
        done = resp.get("status") == "completed"
    else:
        text = str(resp or "")
        done = not rt.get("background")
    save(root, p)
    if done:
        finish(root, p, text)
    else:
        activity(root, "running", agent_id=p["agent_id"], name=p.get("name"), session_id=rt.get("session_id"),
                 note="started in the background")


def on_subagent_start(root, payload):
    agents, _ = load_all(root)
    waiting = {aid: p for aid, p in agents.items() if not get(p, "runtime.agent_id")}
    p = find_by_runtime(waiting, session_id=payload.get("session_id"), agent_type=payload.get("agent_type"))
    if p and p.get("status") == "production":
        p["runtime"]["agent_id"] = payload.get("agent_id")
        save(root, p)


def on_subagent_stop(root, payload):
    agents, _ = load_all(root)
    p = find_by_runtime(agents, agent_id=payload.get("agent_id"))
    if not p:
        return
    rt = p["runtime"]
    rt["transcript"] = payload.get("agent_transcript_path")
    if not rt.get("resolved_model"):
        model, tokens = transcript_model(rt["transcript"])
        if model:
            rt["resolved_model"] = model
            rt["tokens"] = rt.get("tokens") or tokens
            if not p.get("instance_of"):
                p["model"]["name"] = p["model"]["version"] = model
                seal_passport(p, f"model resolved at run time: {model}", HOOK_BY)
    save(root, p)
    finish(root, p, payload.get("last_assistant_message"))


def transcript_model(path):
    """Read (never write) a subagent transcript to find the model that actually answered."""
    model, tokens = None, 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if '"model"' not in line:
                    continue
                try:
                    msg = (json.loads(line).get("message") or {})
                except ValueError:
                    continue
                if msg.get("model"):
                    model = msg["model"]
                    usage = msg.get("usage") or {}
                    tokens += sum(int(usage.get(k) or 0) for k in ("input_tokens", "output_tokens"))
    except (OSError, TypeError):
        pass
    return model, (tokens or None)


def on_session_end(root, payload):
    sid = payload.get("session_id")
    agents, _ = load_all(root)
    for p in agents.values():
        if get(p, "runtime.session_id") != sid or p.get("kind") != "ephemeral":
            continue
        if p.get("status") == "production":
            finish(root, p, None, reason="session ended before the agent reported back")
        elif p.get("invocable"):
            p["invocable"] = False
            p["how_to_invoke"] = "No longer invocable (session ended)"
            save(root, p)
    activity(root, "session_end", session_id=sid, reason=payload.get("reason"))


def resolve_actor(root, payload):
    """Tool calls made inside a subagent carry its agent_id; calls without one come from the chief."""
    agents, _ = load_all(root)
    sub = payload.get("agent_id")
    if sub:
        p = find_by_runtime(agents, agent_id=sub)
        return (p["agent_id"] if p else None), sub
    chief = find_chief(agents) or ensure_chief(root)
    return chief["agent_id"], None


def on_tool_use(root, payload):
    tool = payload.get("tool_name")
    ti = payload.get("tool_input") or {}
    actor, sub = resolve_actor(root, payload)
    base = {"actor": actor, "subagent_id": sub, "session_id": payload.get("session_id"), "tool": tool}
    if tool in FILE_TOOLS:
        rel = rel_to_project(root, ti.get("file_path") or ti.get("notebook_path"))
        if not rel or rel.startswith(root.name + "/"):
            return  # the registry's own files are not part of the trail
        digest, size = file_digest(root, rel)
        activity(root, "file_change", **base, file=rel, sha256=digest, bytes=size)
    elif tool.startswith("mcp__"):
        # Actions in external systems (CRM, mail, databases) through MCP servers.
        resp = payload.get("tool_response")
        failed = isinstance(resp, dict) and bool(resp.get("isError") or resp.get("is_error"))
        activity(root, "command", **base, command=clip(redact(tool + " " + json.dumps(ti, ensure_ascii=False)), 300),
                 description="external action via MCP", failed=failed)
    else:
        resp = payload.get("tool_response")
        failed = None
        if isinstance(resp, dict):
            code = resp.get("returnCode", resp.get("exit_code"))
            failed = bool(resp.get("interrupted")) or (code not in (None, 0))
        activity(root, "command", **base, command=clip(redact(ti.get("command")), 300),
                 description=clip(ti.get("description"), 120) or None, failed=failed)


def cmd_hook(args):
    """Never blocks or fails the agent: problems go to hook-errors.log."""
    root = root_dir(args)
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")  # hook payloads are UTF-8
        payload = json.loads(raw) if raw.strip() else {}
        event = payload.get("hook_event_name")
        if not root.exists():
            (root / "passports").mkdir(parents=True, exist_ok=True)
        if event == "PreToolUse" and payload.get("tool_name") in SPAWN_TOOLS:
            on_spawn(root, payload)
        elif event == "PostToolUse" and payload.get("tool_name") in SPAWN_TOOLS:
            on_spawn_done(root, payload)
        elif event == "PostToolUse" and (payload.get("tool_name") in FILE_TOOLS | COMMAND_TOOLS
                                         or str(payload.get("tool_name")).startswith("mcp__")):
            on_tool_use(root, payload)
            return
        elif event == "SubagentStart":
            on_subagent_start(root, payload)
        elif event == "SubagentStop":
            on_subagent_stop(root, payload)
        elif event == "SessionEnd":
            on_session_end(root, payload)
        else:
            return
        if event in {"PostToolUse", "SubagentStop", "SessionEnd"}:
            write_outputs(root)
    except Exception as e:  # noqa: BLE001 - a registry problem must never break the user's work
        try:
            with open(root / "hook-errors.log", "a", encoding="utf-8") as fh:
                fh.write(f"{now_iso()} {type(e).__name__}: {e}\n")
        except OSError:
            pass
    sys.exit(0)


def cmd_install_hooks(args):
    root = root_dir(args)
    proj = project_root(root)
    settings_path = proj / ".claude" / ("settings.local.json" if args.local else "settings.json")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
    python = args.python or ("python" if os.name == "nt" else "python3")
    rel = root.relative_to(proj).as_posix()
    command = f'{python} "$CLAUDE_PROJECT_DIR/{rel}/passport.py" --dir "$CLAUDE_PROJECT_DIR/{rel}" hook'
    wanted = {"PreToolUse": "Agent|Task",
              "PostToolUse": "|".join(sorted(TRACKED_TOOLS)) + "|mcp__.*",
              "SubagentStart": None, "SubagentStop": None, "SessionEnd": None}
    hooks = settings.setdefault("hooks", {})
    for event, matcher in wanted.items():
        # Replace an older passport hook instead of adding a second one.
        entries = [e for e in hooks.get(event, [])
                   if not any("passport.py" in h.get("command", "") for h in e.get("hooks", []))]
        hooks[event] = entries
        entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
        if matcher:
            entry = {"matcher": matcher, **entry}
        entries.append(entry)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    print(f"Auto-registration hooks written to {settings_path.relative_to(proj).as_posix()}")
    print("Every subagent spawned in this project now gets a passport automatically, and every file change")
    print("and command is attributed to the agent that made it (agent-passports/activity.jsonl).")


# ---------------------------------------------------------------- manual commands

def cmd_init(args):
    root = root_dir(args)
    (root / "passports").mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve()
    if here.parent != root:
        shutil.copy2(here, root / "passport.py")
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8")
    print(f"Initialised {root}")
    print(f"Run from the project root: python {root.name}/passport.py validate")


def cmd_new(args):
    root = root_dir(args)
    p = json.loads(json.dumps(TEMPLATE))
    p["name"] = args.name
    p["kind"] = args.kind
    p["status"] = args.status
    if args.platform:
        p["platform"] = args.platform
    if args.definition_ref:
        p["definition_ref"] = args.definition_ref.replace("\\", "/")
    if args.created_by:
        p["created_by"] = args.created_by
    if args.owner:
        p["owner"] = args.owner
    if args.reports_to:
        p["reports_to"] = args.reports_to
    if args.role:
        p["role"] = args.role
    p["created_at"] = p["updated_at"] = today().isoformat()
    p = create_passport(root, p)
    print(p["agent_id"])
    print(passport_path(root, p["agent_id"]))


def cmd_spawn(args):
    """One-step registration of a temporary agent, for platforms without spawn hooks."""
    root = root_dir(args)
    agents, _ = load_all(root)
    parent = agents.get(args.parent) if args.parent else find_chief(agents)
    if parent is None:
        parent = ensure_chief(root, platform=args.platform or "unknown")
    p = json.loads(json.dumps(TEMPLATE))
    p.update({"name": args.name, "kind": "ephemeral", "platform": args.platform or parent.get("platform"),
              "status": "production", "invocable": True, "how_to_invoke": "Running; its result returns to " + parent["agent_id"],
              "created_at": today().isoformat(), "updated_at": today().isoformat(),
              "created_by": args.by or parent["agent_id"], "owner": args.owner or parent.get("owner"),
              "reports_to": parent["agent_id"]})
    p["model"] = {"provider": args.provider or get(parent, "model.provider") or "unknown",
                  "name": args.model or "unknown", "version": args.model or "unknown",
                  "hosting_region": args.region or get(parent, "model.hosting_region") or "unknown",
                  "eu_hosted": None}
    p["task"] = {"purpose": args.task, "in_scope": [], "out_of_scope": [],
                 "human_in_the_loop": f"Returns its result to {parent['agent_id']}"}
    p["interface"] = {"input": f"instructions from {parent['agent_id']}", "output": f"result returned to {parent['agent_id']}"}
    p["data_dependencies"] = [{"source": d, "type": "unspecified", "access": "read",
                               "contains_personal_data": bool(args.personal_data)} for d in (args.data or [])]
    p["permissions"]["tools"] = args.tools or "unknown"
    p["access"] = {"who_can_invoke": [parent["agent_id"]], "who_can_modify": [parent["agent_id"]]}
    p["risk"]["kill_switch"] = "Stop the agent or its parent " + parent["agent_id"]
    p["runtime"] = {"session_id": args.session, "started_at": now_iso(), "agent_type": args.name}
    seal_passport(p, "registered at spawn", args.by or parent["agent_id"])
    p = create_passport(root, p)
    activity(root, "spawn", agent_id=p["agent_id"], name=p["name"], task=args.task,
             session_id=args.session, by=parent["agent_id"])
    print(p["agent_id"])


def cmd_end(args):
    root = root_dir(args)
    p = load(root, args.agent_id)
    finish(root, p, args.result, status="killed" if args.killed else "ended")
    print(f"{args.agent_id} {p['status']}")


def cmd_seal(args):
    root = root_dir(args)
    p = load(root, args.agent_id)
    seal_passport(p, args.change, args.by)
    save(root, p)
    print(f"{args.agent_id} sealed ({p['fingerprint']})")


def cmd_status(args):
    root = root_dir(args)
    if args.status not in STATUSES:
        sys.exit(f"Unknown status. Use one of: {', '.join(STATUSES)}")
    p = load(root, args.agent_id)
    old = p.get("status")
    p["status"] = args.status
    if args.status in TERMINAL:
        p["invocable"] = bool(args.still_invocable)
    if args.status == "production":
        findings = validate_single(root, dict(p))
        errors = [f for f in findings if f["level"] == "ERROR"]
        if errors:
            print(f"Refused: {args.agent_id} cannot go to production. No passport, no production.")
            for f in errors:
                print(f"  [{f['rule']}] {f['message']}")
            sys.exit(1)
    p["updated_at"] = today().isoformat()
    log(p, f"status {old} -> {args.status}: {args.reason}", args.by)
    save(root, p)
    activity(root, "status", agent_id=args.agent_id, name=p.get("name"), change=f"{old} -> {args.status}",
             reason=args.reason, by=args.by)
    print(f"{args.agent_id}: {old} -> {args.status}")


def validate_single(root, candidate):
    """Validate as if candidate were saved, without writing it."""
    aid = candidate["agent_id"]
    original = passport_path(root, aid).read_text(encoding="utf-8")
    try:
        save(root, candidate)
        _, findings = validate(root)
    finally:
        passport_path(root, aid).write_text(original, encoding="utf-8")
    return [f for f in findings if f["agent_id"] == aid]


def cmd_review(args):
    root = root_dir(args)
    p = load(root, args.agent_id)
    d = today()
    p.setdefault("review", {})
    p["review"]["last_reviewed"] = d.isoformat()
    p["review"]["reviewed_by"] = args.by
    p["review"]["next_review_due"] = (d + dt.timedelta(days=REVIEW_DAYS)).isoformat()
    log(p, "quarterly review" + (f": {args.notes}" if args.notes else ""), args.by)
    save(root, p)
    print(f"{args.agent_id} reviewed, next review due {p['review']['next_review_due']}")


def cmd_scan(args):
    root = root_dir(args)
    agents, _ = load_all(root)
    missing = scan_definitions(root, agents)
    if not missing:
        print("Every agent definition found has a passport.")
        return
    print("Agent definitions without a passport:")
    for rel in missing:
        print(f"  {rel}")


def print_findings(findings):
    if not findings:
        print("All passports valid.")
        return
    for f in findings:
        print(f"{f['level']:<7} {f['agent_id']:<9} [{f['rule']}] {f['message']}")


def cmd_validate(args):
    root = root_dir(args)
    agents, findings = validate(root)
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(f"{len(agents)} passports checked.")
        print_findings(findings)
    if any(f["level"] == "ERROR" for f in findings):
        sys.exit(1)
    if args.strict and any(f["level"] == "WARNING" for f in findings):
        sys.exit(2)


def directory_entries(agents):
    rows = []
    for aid, p in sorted(agents.items()):
        rows.append({
            "agent_id": aid,
            "name": p.get("name"),
            "kind": p.get("kind"),
            "status": p.get("status"),
            "invocable": bool(p.get("invocable")) and p.get("status") not in {"suspended", "killed"}
                         and (p.get("status") != "ended" or bool(get(p, "runtime.agent_id"))),
            "how_to_invoke": p.get("how_to_invoke"),
            "purpose": get(p, "task.purpose"),
            "input": get(p, "interface.input"),
            "output": get(p, "interface.output"),
            "who_can_invoke": get(p, "access.who_can_invoke"),
            "reports_to": p.get("reports_to"),
            "talks_to": p.get("talks_to") or [],
        })
    return rows


def cmd_directory(args):
    root = root_dir(args)
    agents, _ = load_all(root)
    rows = directory_entries(agents)
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    live = [r for r in rows if r["invocable"]]
    if not live:
        print("No agents can be invoked right now.")
    for r in live:
        allowed = r["who_can_invoke"]
        print(f"{r['agent_id']}  {r['name']}  ({r['status']})")
        print(f"    does:    {r['purpose']}")
        print(f"    invoke:  {r['how_to_invoke']}")
        print(f"    allowed: {', '.join(allowed) if isinstance(allowed, list) else allowed}")
    gone = [r for r in rows if not r["invocable"]]
    if gone:
        print("\nNot invocable: " + ", ".join(f"{r['agent_id']} ({r['status']})" for r in gone))


# ---------------------------------------------------------------- report: who did what

def report_rows(root, since=None, session=None):
    agents, _ = load_all(root)
    touched = {}
    for t in file_ledger_entries(root, agents):
        touched.setdefault(t["actor"], []).append(t["file"])
    rows = []
    for aid, p in sorted(agents.items()):
        if p.get("kind") != "ephemeral":
            continue
        rt = p.get("runtime") or {}
        started = rt.get("started_at") or p.get("created_at") or ""
        if since and started[:10] < since:
            continue
        if session and not str(rt.get("session_id") or "").startswith(session):
            continue
        rows.append({
            "started": started, "agent_id": aid, "name": p.get("name"), "task": get(p, "task.purpose"),
            "status": p.get("status"), "reports_to": p.get("reports_to"),
            "model": rt.get("resolved_model") or get(p, "model.name"),
            "tools": get(p, "permissions.tools"), "duration_s": round(rt["duration_ms"] / 1000) if rt.get("duration_ms") else None,
            "tokens": rt.get("tokens"), "result": rt.get("result_summary"), "session": str(rt.get("session_id") or "")[:8],
            "files": sorted(set(touched.get(aid, []))),
        })
    rows.sort(key=lambda r: r["started"])
    changes = []
    for aid, p in sorted(agents.items()):
        if p.get("kind") == "ephemeral":
            continue
        for c in p.get("changelog") or []:
            if not since or (c.get("date") or "") >= since:
                changes.append({"date": c.get("date"), "agent_id": aid, "name": p.get("name"),
                                "change": c.get("change"), "by": c.get("by")})
    return rows, changes


def render_report(rows, changes, since=None):
    def fmt_tools(t):
        return ", ".join(t) if isinstance(t, list) else str(t or "-")
    out = ["# Agent activity report" + (f" since {since}" if since else ""), ""]
    if not rows:
        out.append("No subagent runs recorded in this period.")
    else:
        by_session = {}
        for r in rows:
            by_session.setdefault(r["session"] or "-", []).append(r)
        out.append(f"{len(rows)} subagent runs in {len(by_session)} session(s).")
        for sess, items in by_session.items():
            out += ["", f"## Session {sess} (started {items[0]['started'].replace('T', ' ')})", "",
                    "| Started | Agent | Task | Model | Tools | Time | Tokens | Status | Files changed | Result |",
                    "|---|---|---|---|---|---|---|---|---|---|"]
            for r in items:
                files = r.get("files") or []
                shown = ", ".join(files[:5]) + (f" (+{len(files) - 5})" if len(files) > 5 else "")
                out.append(f"| {r['started'][11:16]} | {r['agent_id']} {md_value(r['name'])} | {md_value(r['task'])} | "
                           f"{md_value(r['model'])} | {md_value(fmt_tools(r['tools']))} | "
                           f"{(str(r['duration_s']) + 's') if r['duration_s'] is not None else '-'} | {r['tokens'] or '-'} | "
                           f"{r['status']} | {md_value(shown)} | {md_value(clip(r['result'], 160))} |")
    if changes:
        out += ["", "## Changes to persistent agents", "", "| Date | Agent | Change | By |", "|---|---|---|---|"]
        out += [f"| {c['date']} | {c['agent_id']} {md_value(c['name'])} | {md_value(c['change'])} | {md_value(c['by'])} |"
                for c in changes]
    return "\n".join(out) + "\n"


def cmd_report(args):
    root = root_dir(args)
    since = args.since
    if since == "today":
        since = today().isoformat()
    rows, changes = report_rows(root, since, args.session)
    if args.json:
        print(json.dumps({"runs": rows, "changes": changes}, indent=2, ensure_ascii=False))
    else:
        print(render_report(rows, changes, since))


# ---------------------------------------------------------------- audit trail: files, graphify, trace, verify

def file_ledger_entries(root, agents=None):
    """Every recorded file change and command, with the actor resolved to a passport."""
    if agents is None:
        agents, _ = load_all(root)
    by_sub = {get(p, "runtime.agent_id"): aid for aid, p in agents.items() if get(p, "runtime.agent_id")}
    out = []
    for e in read_activity(root):
        if e.get("event") not in ("file_change", "command"):
            continue
        actor = e.get("actor") or by_sub.get(e.get("subagent_id")) or f"unresolved:{e.get('subagent_id')}"
        out.append({"ts": e.get("ts"), "event": e["event"], "actor": actor,
                    "actor_name": (agents.get(actor) or {}).get("name"), "tool": e.get("tool"),
                    "file": e.get("file"), "sha256": e.get("sha256"), "command": e.get("command"),
                    "failed": e.get("failed"), "session": str(e.get("session_id") or "")[:8]})
    return out


def graphify_index(root):
    """Read graphify-out/graph.json if the project has one. Strictly read-only: this function opens
    the file for reading and never writes, moves or rebuilds anything in graphify-out/."""
    path = project_root(root) / "graphify-out" / "graph.json"
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            g = json.load(fh)
    except (OSError, ValueError):
        return None
    files, node_file = {}, {}
    for n in g.get("nodes") or []:
        src = norm_ref(n.get("source_file"))
        if not src or not n.get("id"):
            continue
        node_file[n["id"]] = src
        entry = files.setdefault(src, {"nodes": [], "communities": {}})
        entry["nodes"].append(n.get("label") or n["id"])
        if n.get("community") is not None:
            entry["communities"][str(n["community"])] = n.get("community_name") or f"community {n['community']}"
    related = {}
    for link in g.get("links") or g.get("edges") or []:
        a, b = node_file.get(link.get("source")), node_file.get(link.get("target"))
        if a and b and a != b:
            related.setdefault(a, set()).add(b)
            related.setdefault(b, set()).add(a)
    built = dt.datetime.fromtimestamp(path.stat().st_mtime).isoformat(timespec="seconds")
    return {"path": "graphify-out/graph.json", "built_at": built, "files": files,
            "related": {k: sorted(v) for k, v in related.items()}}


def file_view(root, agents, gi=None):
    """Per file: who changed it, when, with which hash, and where it sits in the graphify graph."""
    files = {}
    for t in file_ledger_entries(root, agents):
        if t["event"] != "file_change":
            continue
        f = files.setdefault(t["file"], {"file": t["file"], "touches": []})
        f["touches"].append({k: t[k] for k in ("ts", "actor", "actor_name", "tool", "sha256", "session")})
    for f in files.values():
        g = (gi or {}).get("files", {}).get(f["file"]) if gi else None
        f["graphify"] = {"communities": sorted(set(g["communities"].values())), "nodes": g["nodes"][:12],
                         "related_files": (gi["related"].get(f["file"]) or [])[:15]} if g else None
        if gi and not g:
            f["graphify"] = {"note": "not in the graphify graph (new file, or graph built before this change)"}
    return dict(sorted(files.items()))


def cmd_trace(args):
    """Audit question: what happened to this file / folder / graphify cluster, and which agent did it?"""
    root = root_dir(args)
    agents, _ = load_all(root)
    gi = graphify_index(root)
    q = args.query.replace("\\", "/").lower()
    ledger = [t for t in file_ledger_entries(root, agents) if not args.since or (t["ts"] or "") >= args.since]
    # Match on path, or on a graphify community / node name that covers the file.
    def matches(path):
        if not path:
            return False
        if q in path.lower():
            return True
        g = (gi or {}).get("files", {}).get(path) if gi else None
        return bool(g) and (any(q in c.lower() for c in g["communities"].values())
                            or any(q in str(n).lower() for n in g["nodes"]))
    hits = [t for t in ledger if t["event"] == "file_change" and matches(t["file"])]
    cmds = [t for t in ledger if t["event"] == "command" and q in (t["command"] or "").lower()]
    if args.json:
        print(json.dumps({"query": args.query, "file_changes": hits, "commands": cmds}, indent=2, ensure_ascii=False))
        return
    print(f"# Trace: {args.query}\n")
    if gi:
        print(f"Graphify graph: {gi['path']} (built {gi['built_at']}, read-only)\n")
    if not hits and not cmds:
        print("No recorded file changes or commands match.")
        return
    files = {}
    for t in hits:
        files.setdefault(t["file"], []).append(t)
    for path, touches in files.items():
        print(f"## {path}")
        g = (gi or {}).get("files", {}).get(path) if gi else None
        if g:
            print(f"Graphify: cluster {', '.join(sorted(set(g['communities'].values()))) or '-'}; "
                  f"nodes {', '.join(map(str, g['nodes'][:6]))}")
            rel = gi["related"].get(path) or []
            if rel:
                print(f"Connected files in the graph: {', '.join(rel[:8])}{' ...' if len(rel) > 8 else ''}")
        print("\n| When | Agent | Tool | Session | File hash after change |\n|---|---|---|---|---|")
        for t in touches:
            print(f"| {t['ts'].replace('T', ' ')} | {t['actor']} {t['actor_name'] or ''} | {t['tool']} | "
                  f"{t['session']} | {(t['sha256'] or '-')[:16]} |")
        print()
    if cmds:
        print("## Matching commands\n\n| When | Agent | Command | Failed |\n|---|---|---|---|")
        for t in cmds:
            print(f"| {t['ts'].replace('T', ' ')} | {t['actor']} {t['actor_name'] or ''} | "
                  f"{md_value(t['command'])} | {md_value(t['failed'])} |")
    actors = sorted({t["actor"] for t in hits + cmds if t["actor"] in agents})
    if actors:
        print("\n## Agents involved\n")
        for aid in actors:
            p = agents[aid]
            print(f"- {aid} {p.get('name')} ({p.get('kind')}, {p.get('status')}): model "
                  f"{get(p, 'runtime.resolved_model') or get(p, 'model.name')}, tools {md_value(get(p, 'permissions.tools'))}, "
                  f"reports to {p.get('reports_to')}, owner {p.get('owner')}")


def cmd_verify(args):
    """Check the hash chain of activity.jsonl: proves no entry was edited, removed or reordered."""
    root = root_dir(args)
    path = root / "activity.jsonl"
    if not path.exists():
        print("No activity log yet.")
        return
    prev, n, unchained = "GENESIS", 0, 0
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            e = json.loads(line)
        except ValueError:
            print(f"BROKEN at line {i}: not valid JSON")
            sys.exit(1)
        if "hash" not in e:
            unchained += 1
            prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
            continue
        if e.get("prev") != prev or entry_hash(e) != e["hash"]:
            print(f"BROKEN at line {i} ({e.get('ts')} {e.get('event')}): the log was changed after it was written.")
            sys.exit(1)
        prev, n = e["hash"], n + 1
    print(f"Audit log intact: {n} chained entries" + (f", {unchained} older unchained entries" if unchained else "") + ".")


# ---------------------------------------------------------------- build outputs

def write_outputs(root):
    agents, findings = validate(root)
    counts = {s: sum(1 for p in agents.values() if p.get("status") == s) for s in STATUSES}
    runs, changes = report_rows(root)
    gi = graphify_index(root)
    files = file_view(root, agents, gi)
    commands = [t for t in file_ledger_entries(root, agents) if t["event"] == "command"][-300:]
    registry = {
        "generated_at": now_iso(),
        "rules": ["No passport, no production.",
                  "Every model or data change updates the passport.",
                  f"Every passport is reviewed at least every {REVIEW_DAYS} days."],
        "summary": {"agents": len(agents), "by_status": counts,
                    "errors": sum(f["level"] == "ERROR" for f in findings),
                    "warnings": sum(f["level"] == "WARNING" for f in findings)},
        "directory": directory_entries(agents),
        "edges": build_edges(agents),
        "findings": findings,
        "activity": runs[-200:],
        "files": files,
        "commands": commands,
        "graphify": {"path": gi["path"], "built_at": gi["built_at"], "files_in_graph": len(gi["files"])} if gi else None,
        "passports": {aid: {k: v for k, v in p.items() if not k.startswith("_")} for aid, p in agents.items()},
    }
    (root / "registry.json").write_text(json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (root / "REGISTRY.md").write_text(render_markdown(registry, runs, changes), encoding="utf-8")
    (root / "registry.html").write_text(render_html(registry), encoding="utf-8")
    return registry


def build_edges(agents):
    edges = []
    for aid, p in sorted(agents.items()):
        if isinstance(p.get("reports_to"), str) and not is_missing(p.get("reports_to")):
            edges.append({"source": aid, "target": p["reports_to"], "relation": "reports_to"})
        for t in p.get("talks_to") or []:
            edges.append({"source": aid, "target": t, "relation": "talks_to"})
        if p.get("instance_of"):
            edges.append({"source": aid, "target": p["instance_of"], "relation": "instance_of"})
        deps = p.get("data_dependencies")
        if isinstance(deps, list):
            for d in deps:
                name = d.get("source") if isinstance(d, dict) else str(d)
                edges.append({"source": aid, "target": f"data:{name}", "relation": "depends_on",
                              "access": d.get("access") if isinstance(d, dict) else None})
    return edges


def cmd_build(args):
    root = root_dir(args)
    reg = write_outputs(root)
    print(f"Wrote registry.json, REGISTRY.md, registry.html to {root}")
    print(f"{reg['summary']['agents']} agents, {reg['summary']['errors']} errors, "
          f"{reg['summary']['warnings']} warnings")


def md_value(v):
    if v is None or v == "" or v == []:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, list):
        return ", ".join(md_value(x) for x in v)
    if isinstance(v, dict):
        return "; ".join(f"{k}: {md_value(x)}" for k, x in v.items())
    return str(v).replace("|", "\\|").replace("\n", " ")


def render_markdown(reg, runs, changes):
    s = reg["summary"]
    out = ["# Agent Registry", "",
           f"Generated {reg['generated_at']}. {s['agents']} agents, "
           f"{s['errors']} errors, {s['warnings']} warnings. Open `registry.html` for the organogram.", "",
           "**Rules:** " + " ".join(f"({i}) {r}" for i, r in enumerate(reg["rules"], 1)), "",
           "## Status", "",
           "| " + " | ".join(STATUSES) + " |", "|" + "---|" * len(STATUSES),
           "| " + " | ".join(str(s["by_status"][x]) for x in STATUSES) + " |", ""]
    out += ["## Findings", ""]
    if reg["findings"]:
        out += ["| Level | Agent | Rule | Message |", "|---|---|---|---|"]
        out += [f"| {f['level']} | {f['agent_id']} | {f['rule']} | {md_value(f['message'])} |" for f in reg["findings"]]
    else:
        out.append("No findings. All passports valid.")
    out += ["", "## Directory: who can I talk to?", "",
            "| Agent | Name | Status | Invocable | Does | How to invoke | Who may invoke |",
            "|---|---|---|---|---|---|---|"]
    for r in reg["directory"]:
        if r["kind"] == "ephemeral" and not r["invocable"]:
            continue
        out.append(f"| {r['agent_id']} | {md_value(r['name'])} | {r['status']} | {md_value(r['invocable'])} | "
                   f"{md_value(r['purpose'])} | {md_value(r['how_to_invoke'])} | {md_value(r['who_can_invoke'])} |")
    out += ["", render_report(runs[-50:], changes[-50:]).replace("# Agent activity report", "## Activity: who did what", 1)]
    if reg.get("files"):
        g = reg.get("graphify")
        out += ["## Files changed by agents", "",
                (f"Linked read-only to `{g['path']}` (built {g['built_at']})." if g else "No graphify graph found."), "",
                "| File | Graphify cluster | Changes | Last change | Last by |", "|---|---|---|---|---|"]
        for f in reg["files"].values():
            last = f["touches"][-1]
            gg = f.get("graphify") or {}
            cl = ", ".join(gg.get("communities") or []) or ("not in graph" if gg.get("note") else "-")
            out.append(f"| {md_value(f['file'])} | {md_value(cl)} | {len(f['touches'])} | {last['ts']} | "
                       f"{last['actor']} {md_value(last.get('actor_name'))} |")
        out.append("")
    out += ["## Passports", ""]
    for aid, p in sorted(reg["passports"].items()):
        out += [f"### {aid} · {p.get('name')}", "", "| Field | Value |", "|---|---|"]
        rows = [
            ("Status", f"{p.get('status')} (invocable: {md_value(p.get('invocable'))})"),
            ("Kind / platform", f"{p.get('kind')} / {p.get('platform')}" + (" · auto-registered" if p.get("auto_registered") else "")),
            ("Created / updated", f"{p.get('created_at')} / {p.get('updated_at')}"),
            ("Created by", p.get("created_by")),
            ("Owner (human)", p.get("owner")),
            ("Reports to", p.get("reports_to")),
            ("Talks to", p.get("talks_to")),
            ("Instance of", p.get("instance_of")),
            ("Model", p.get("model")),
            ("Task", get(p, "task.purpose")),
            ("Human in the loop", get(p, "task.human_in_the_loop")),
            ("Interface", p.get("interface")),
            ("How to invoke", p.get("how_to_invoke")),
            ("Data dependencies", p.get("data_dependencies")),
            ("Permissions", p.get("permissions")),
            ("Access", p.get("access")),
            ("Risk / kill switch", p.get("risk")),
            ("Review", p.get("review")),
            ("Definition", p.get("definition_ref")),
            ("Run", {k: v for k, v in (p.get("runtime") or {}).items() if k in
                     ("session_id", "agent_id", "started_at", "ended_at", "resolved_model", "tokens", "result_summary")} or None),
        ]
        out += [f"| {k} | {md_value(v)} |" for k, v in rows if v not in (None, "", [])]
        log_rows = p.get("changelog") or []
        if log_rows:
            out += ["", "Changelog:", ""]
            out += [f"- {c.get('date')} · {c.get('by')} · {c.get('change')}" for c in log_rows[-10:]]
        out.append("")
    return "\n".join(out) + "\n"


def render_html(reg):
    data = json.dumps({"summary": reg["summary"], "findings": reg["findings"], "activity": reg["activity"],
                       "files": reg["files"], "commands": reg["commands"], "graphify": reg["graphify"],
                       "passports": reg["passports"], "generated_at": reg["generated_at"]}, ensure_ascii=False)
    data = data.replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__DATA__", data).replace("__TITLE__", html.escape("Agent Organogram"))


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f5f1;--panel:#fff;--ink:#1d1d1b;--muted:#6d6c66;--line:#d6d4cc;--accent:#2f6fde;
--development:#6f8fd8;--test:#d39a2c;--production:#2b9466;--suspended:#c9663b;--killed:#8f8e88;--ended:#aaa9a3;--human:#7c55c0}
@media (prefers-color-scheme:dark){:root{--bg:#131312;--panel:#1d1d1b;--ink:#ecebe5;--muted:#9d9c95;--line:#36352f;--accent:#7aa5f0}}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,sans-serif}
header{padding:14px 16px 0;border-bottom:1px solid var(--line);background:var(--panel)}
h1{font-size:18px;margin:0 0 2px}.muted{color:var(--muted)}.err{color:#cf3f35;font-weight:600}
nav{display:flex;gap:4px;margin-top:10px}nav button{border:0;background:none;color:var(--muted);padding:8px 12px;font:inherit;cursor:pointer;border-bottom:2px solid transparent}
nav button.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:600}
main{display:grid;grid-template-columns:1fr 380px;min-height:calc(100vh - 92px)}
@media (max-width:860px){main{grid-template-columns:1fr}}
section{padding:20px 16px;overflow:auto}section[hidden]{display:none}
aside{border-left:1px solid var(--line);background:var(--panel);padding:16px;overflow:auto;max-height:calc(100vh - 92px);position:sticky;top:0}
@media (max-width:860px){aside{border-left:0;border-top:1px solid var(--line);max-height:none;position:static}}
/* organogram */
.tree{display:flex;justify-content:center;min-width:max-content;padding-bottom:24px}
.tree ul{display:flex;justify-content:center;padding:22px 0 0;margin:0;position:relative}
.tree li{list-style:none;position:relative;padding:22px 8px 0;display:flex;flex-direction:column;align-items:center}
.tree>ul{padding-top:0}.tree>ul>li{padding-top:0}
.tree li::before,.tree li::after{content:"";position:absolute;top:0;width:50%;height:22px;border-top:1.5px solid var(--line)}
.tree li::before{right:50%}.tree li::after{left:50%;border-left:1.5px solid var(--line)}
.tree li:only-child::before,.tree li:only-child::after{border-top:0}
.tree li:first-child::before,.tree li:last-child::after{border-top:0}
.tree li:last-child::before{border-right:1.5px solid var(--line)}
.tree>ul>li::before,.tree>ul>li::after{display:none}
.tree ul ul::before{content:"";position:absolute;top:0;left:50%;height:22px;border-left:1.5px solid var(--line)}
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--line));border-radius:8px;padding:8px 12px;min-width:150px;max-width:220px;text-align:left;cursor:pointer;font:inherit;color:inherit}
.card:hover,.card.sel{border-color:var(--accent);box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 25%,transparent)}
.card b{display:block;font-size:13px}.card small{display:block;color:var(--muted);font-size:11.5px;line-height:1.35}
.card.human{border-left-color:var(--human);cursor:default;background:color-mix(in srgb,var(--human) 8%,var(--panel))}
.card.off{opacity:.6}.pill{display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:9px;background:color-mix(in srgb,var(--c) 18%,transparent);color:var(--ink);margin-top:3px}
.group{border:1px dashed var(--line);border-radius:8px;padding:6px 8px;background:color-mix(in srgb,var(--panel) 60%,transparent);max-width:240px}
.group summary{cursor:pointer;font-size:12.5px;color:var(--muted)}.group .card{margin-top:6px;min-width:0;max-width:none}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:16px;font-size:12px;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:12px}
tr.click{cursor:pointer}tr.click:hover{background:color-mix(in srgb,var(--accent) 7%,transparent)}
aside h2{font-size:16px;margin:0 0 4px}aside dl{margin:10px 0 0}aside dt{color:var(--muted);font-size:11.5px;margin-top:9px;text-transform:uppercase;letter-spacing:.03em}aside dd{margin:2px 0 0;word-break:break-word}aside a{color:var(--accent)}
.talk{margin:12px 0 4px;padding:10px;border:1px solid var(--line);border-radius:8px}
.talk textarea{width:100%;min-height:70px;font:12.5px ui-monospace,monospace;background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:6px}
.btn{background:var(--accent);color:#fff;border:0;border-radius:6px;padding:7px 12px;font:inherit;font-weight:600;cursor:pointer;margin-top:6px}.btn[disabled]{opacity:.45;cursor:not-allowed}
.f{font-size:12.5px;margin:4px 0}.lvl-ERROR{color:#cf3f35;font-weight:600}.lvl-WARNING{color:#b9801b;font-weight:600}
</style></head><body>
<header><h1>Agent Organogram</h1><div class="muted" id="sum"></div>
<nav><button class="on" data-tab="org">Organogram</button><button data-tab="act">Who did what</button><button data-tab="files">Files</button><button data-tab="cmd">Commands</button><button data-tab="fin">Findings</button></nav></header>
<main>
<section id="org"><div class="legend" id="legend"></div><div class="tree" id="tree"></div></section>
<section id="act" hidden></section>
<section id="files" hidden></section>
<section id="cmd" hidden></section>
<section id="fin" hidden></section>
<aside id="side"><h2>Select an agent</h2><p class="muted">Click any card to see its passport: what it does, which model, which data, which permissions, who it reports to. Agents that can still be reached get a ready-to-paste message.</p></aside>
</main>
<script>
const D=__DATA__, P=D.passports, ids=Object.keys(P).sort();
const esc=s=>String(s??'-').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=v=>{if(v==null||v===''||(Array.isArray(v)&&!v.length))return '-';if(Array.isArray(v))return v.map(fmt).join(', ');if(typeof v==='object')return Object.entries(v).filter(([k,x])=>x!=null&&x!=='').map(([k,x])=>k+': '+fmt(x)).join('; ');return String(v)};
const isAgt=s=>typeof s==='string'&&/^AGT-\d{4,}$/.test(s)&&P[s];
const invocable=p=>p.invocable&&!['suspended','killed'].includes(p.status)&&(p.status!=='ended'||(p.runtime&&p.runtime.agent_id));
document.getElementById('sum').innerHTML=`${D.summary.agents} agents · <span class="${D.summary.errors?'err':''}">${D.summary.errors} errors</span> · ${D.summary.warnings} warnings · generated ${esc(D.generated_at.replace('T',' '))}`;
document.getElementById('legend').innerHTML=['development','test','production','suspended','killed','ended','human'].map(s=>`<span><i style="background:var(--${s})"></i>${s}</span>`).join('');
document.querySelectorAll('nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('nav button').forEach(x=>x.classList.toggle('on',x===b));['org','act','files','cmd','fin'].forEach(t=>document.getElementById(t).hidden=t!==b.dataset.tab)});
// build hierarchy
const kids={},roots={};
for(const id of ids){const p=P[id],up=p.reports_to;if(isAgt(up)&&up!==id)(kids[up]=kids[up]||[]).push(id);else{const h=(typeof up==='string'&&up&&!/TODO/.test(up))?up:(p.owner||'unassigned');(roots[h]=roots[h]||[]).push(id)}}
function card(id){const p=P[id],off=!invocable(p);const rt=p.runtime||{};
return `<button class="card${off?' off':''}" style="--c:var(--${p.status})" data-id="${id}"><b>${esc(p.name)}</b><small>${id} · ${esc(p.kind)}${p.role==='chief'?' · chief':''}</small><small>${esc((p.task&&p.task.purpose||'').slice(0,70))}</small><span class="pill">${esc(p.status)}${rt.resolved_model?' · '+esc(rt.resolved_model):''}</span></button>`}
function node(id,depth){const ch=kids[id]||[];const persistent=ch.filter(c=>P[c].kind!=='ephemeral');const temp=ch.filter(c=>P[c].kind==='ephemeral');
const groups={};temp.forEach(c=>{const k=(P[c].runtime&&P[c].runtime.agent_type)||P[c].name;(groups[k]=groups[k]||[]).push(c)});
let inner=persistent.map(c=>node(c,depth+1)).join('');
inner+=Object.entries(groups).map(([k,list])=>{const live=list.filter(c=>P[c].status==='production').length;
return `<li><details class="group"${live?' open':''}><summary>${esc(k)} · ${list.length} run${list.length>1?'s':''}${live?` · <b>${live} running</b>`:''}</summary>${list.slice().reverse().map(card).join('')}</details></li>`}).join('');
return `<li>${card(id)}${inner?`<ul>${inner}</ul>`:''}</li>`}
document.getElementById('tree').innerHTML='<ul>'+Object.entries(roots).map(([h,list])=>`<li><div class="card human"><b>${esc(h)}</b><small>accountable human</small></div><ul>${list.map(id=>node(id,1)).join('')}</ul></li>`).join('')+'</ul>';
// activity
const A=D.activity.slice().reverse();
document.getElementById('act').innerHTML=A.length?`<p class="muted">Subagent runs, newest first. This is what the chief reports when asked "who did what".</p><table><tr><th>Started</th><th>Agent</th><th>Task</th><th>Model</th><th>Time</th><th>Status</th><th>Result</th></tr>${A.map(r=>`<tr class="click" data-id="${r.agent_id}"><td>${esc((r.started||'').replace('T',' ').slice(0,16))}</td><td>${esc(r.agent_id)}<br><span class="muted">${esc(r.name)}</span></td><td>${esc(r.task)}</td><td>${esc(r.model)}</td><td>${r.duration_s!=null?r.duration_s+'s':'-'}</td><td>${esc(r.status)}</td><td>${esc((r.result||'').slice(0,200))}</td></tr>`).join('')}</table>`:'<p class="muted">No subagent runs recorded yet. Once auto-registration hooks are installed, every spawned subagent appears here.</p>';
const F=Object.values(D.files||{}).sort((a,b)=>(b.touches.at(-1).ts||'').localeCompare(a.touches.at(-1).ts||''));
const gnote=D.graphify?`Linked read-only to ${esc(D.graphify.path)} (built ${esc(D.graphify.built_at.replace('T',' '))}, ${D.graphify.files_in_graph} files in graph).`:'No graphify-out/graph.json found in this project; files are listed without graph context.';
document.getElementById('files').innerHTML=`<p class="muted">Every file an agent changed, newest first. ${gnote} Click a row for the full trail.</p>`+(F.length?`<table><tr><th>File</th><th>Graphify cluster</th><th>Changes</th><th>Last change</th><th>Last by</th></tr>${F.map(f=>{const l=f.touches.at(-1),g=f.graphify||{};return `<tr class="click" data-file="${esc(f.file)}"><td>${esc(f.file)}</td><td>${esc(g.communities?g.communities.join(', '):(g.note?'not in graph':'-'))}</td><td>${f.touches.length}</td><td>${esc((l.ts||'').replace('T',' ').slice(0,16))}</td><td>${esc(l.actor)} ${esc(l.actor_name||'')}</td></tr>`}).join('')}</table>`:'<p class="muted">No file changes recorded yet.</p>');
const C=(D.commands||[]).slice().reverse();
document.getElementById('cmd').innerHTML=C.length?`<p class="muted">Shell commands run by agents (secrets redacted), newest first.</p><table><tr><th>When</th><th>Agent</th><th>Command</th><th>Failed</th></tr>${C.map(c=>`<tr class="click" data-id="${esc(c.actor)}"><td>${esc((c.ts||'').replace('T',' ').slice(0,16))}</td><td>${esc(c.actor)} ${esc(c.actor_name||'')}</td><td><code>${esc(c.command)}</code></td><td>${c.failed?'<span class="lvl-ERROR">yes</span>':(c.failed===false?'no':'-')}</td></tr>`).join('')}</table>`:'<p class="muted">No commands recorded yet.</p>';
function selectFile(path){const f=(D.files||{})[path];if(!f)return;const g=f.graphify||{};
document.getElementById('side').innerHTML=`<h2>${esc(path)}</h2><div class="muted">file trail</div><dl><dt>Graphify cluster</dt><dd>${esc(g.communities?g.communities.join(', '):(g.note||'-'))}</dd>${g.nodes?`<dt>Graph nodes in this file</dt><dd>${esc(g.nodes.join(', '))}</dd>`:''}${g.related_files&&g.related_files.length?`<dt>Connected files (graph)</dt><dd>${g.related_files.map(r=>(D.files||{})[r]?`<a href="#" data-file="${esc(r)}">${esc(r)}</a>`:esc(r)).join(', ')}</dd>`:''}<dt>Changes (newest first)</dt><dd><table>${f.touches.slice().reverse().map(t=>`<tr class="click" data-id="${esc(t.actor)}"><td>${esc((t.ts||'').replace('T',' ').slice(0,16))}</td><td>${esc(t.actor)} ${esc(t.actor_name||'')}<br><span class="muted">${esc(t.tool)} · sha ${esc((t.sha256||'-').slice(0,12))}</span></td></tr>`).join('')}</table></dd></dl><p class="muted" style="font-size:12px">CLI: python agent-passports/passport.py trace "${esc(path)}"</p>`}
document.getElementById('fin').innerHTML=D.findings.length?`<table><tr><th>Level</th><th>Agent</th><th>Rule</th><th>Message</th></tr>${D.findings.map(f=>`<tr class="click" data-id="${f.agent_id}"><td class="lvl-${f.level}">${f.level}</td><td>${esc(f.agent_id)}</td><td>${esc(f.rule)}</td><td>${esc(f.message)}</td></tr>`).join('')}</table>`:'<p>No findings. All passports valid.</p>';
// talk-to message
function talk(id){const p=P[id],rt=p.runtime||{};if(!invocable(p))return {ok:false,why:p.status==='ended'?'This run has ended and cannot be resumed.':'Status is '+p.status+'; it cannot be invoked.'};
if(p.role==='chief')return {ok:true,text:'(Talk to the chief directly in your agent session in this project.)\nReport who did what today: run python agent-passports/passport.py report --since today'};
if(p.kind==='ephemeral'&&rt.agent_id)return {ok:true,text:`Continue subagent ${rt.agent_id} (passport ${id}, "${p.task&&p.task.purpose}") with SendMessage: `};
if(p.platform==='claude-code')return {ok:true,text:`Use the ${p.name} subagent (passport ${id}) to: `};
return {ok:true,text:`${p.how_to_invoke||'See passport'}\nTask for ${p.name} (${id}): `}}
function select(id){const p=P[id];if(!p)return;document.querySelectorAll('.card.sel').forEach(c=>c.classList.remove('sel'));document.querySelectorAll(`.card[data-id="${id}"]`).forEach(c=>c.classList.add('sel'));
const t=talk(id),fs=D.findings.filter(f=>f.agent_id===id),rt=p.runtime||{};
const rows=[['Status',p.status+(invocable(p)?' · can be invoked':' · not invocable')],['Kind / platform',p.kind+' / '+p.platform+(p.auto_registered?' · auto-registered':'')],['Owner (human)',p.owner],['Reports to',p.reports_to],['Talks to',p.talks_to],['Instance of',p.instance_of],['Task',p.task&&p.task.purpose],['Human in the loop',p.task&&p.task.human_in_the_loop],['Model',p.model],['Data',p.data_dependencies],['Permissions',p.permissions],['Who may invoke',p.access&&p.access.who_can_invoke],['How to invoke',p.how_to_invoke],['Kill switch',p.risk&&p.risk.kill_switch],['Run',rt.started_at?{started:rt.started_at,ended:rt.ended_at,model:rt.resolved_model,tokens:rt.tokens,result:rt.result_summary}:null],['Created / updated',p.created_at+' / '+p.updated_at],['Review',p.review],['Last changes',(p.changelog||[]).slice(-4).map(c=>c.date+' '+c.change).join(' | ')],['Files changed',Object.values(D.files||{}).filter(f=>f.touches.some(t=>t.actor===id)).map(f=>f.file)]];
document.getElementById('side').innerHTML=`<h2>${esc(p.name)}</h2><div class="muted">${id}</div>${fs.map(f=>`<p class="f lvl-${f.level}">${f.level}: ${esc(f.message)}</p>`).join('')}
<div class="talk"><b>Talk to this agent</b>${t.ok?`<textarea id="msg">${esc(t.text)}</textarea><button class="btn" id="cp">Copy message</button> <span class="muted" id="cpok"></span><div class="muted" style="font-size:12px;margin-top:4px">Paste it in your agent session in this project and finish the sentence.</div>`:`<p class="muted">${esc(t.why)}</p>`}</div>
<dl>${rows.filter(([k,v])=>v!=null&&v!==''&&!(Array.isArray(v)&&!v.length)).map(([k,v])=>`<dt>${k}</dt><dd>${esc(fmt(v))}</dd>`).join('')}</dl>`;
const cp=document.getElementById('cp');if(cp)cp.onclick=async()=>{const ta=document.getElementById('msg');try{await navigator.clipboard.writeText(ta.value)}catch(e){ta.select();document.execCommand('copy')}document.getElementById('cpok').textContent='Copied'}}
document.addEventListener('click',e=>{const fe=e.target.closest('[data-file]');if(fe){e.preventDefault();selectFile(fe.dataset.file);return}const el=e.target.closest('[data-id]');if(el&&(!e.target.closest('aside')||el.tagName==='TR'))select(el.dataset.id)});
const chief=ids.find(i=>P[i].role==='chief');if(chief)select(chief);
</script></body></html>
"""

README = """# Agent passports

Every agent in this project has a passport in `passports/AGT-XXXX.json`. No passport, no production.
Open `registry.html` for the organogram, or `REGISTRY.md` for the same in text.

Rules
1. No passport, no production. `passport.py status ID production` refuses incomplete passports.
   Subagents spawned in Claude Code are registered automatically by hooks (see .claude/settings.json).
2. Every model, task, data, permission or reporting change updates the passport: edit the JSON, then
   `python agent-passports/passport.py seal ID --change "what changed and why"`.
3. Every passport is reviewed at least every 90 days: `passport.py review ID --by "Name"`.

Agents that are stopped are never deleted. They become `killed` (stopped on purpose) or `ended`
(a temporary agent that finished) so the trail stays.

Useful commands (run from the project root)
- `python agent-passports/passport.py report --since today`   who did what
- `python agent-passports/passport.py directory`              which agents can be invoked, and how
- `python agent-passports/passport.py validate`               check everything, exit 1 on errors
- `python agent-passports/passport.py build`                  regenerate registry.json, REGISTRY.md, registry.html
"""


def main():
    ap = argparse.ArgumentParser(description="Agent Passport CLI")
    ap.add_argument("--dir", default="agent-passports", help="path to the agent-passports folder")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    p = sub.add_parser("install-hooks")
    p.add_argument("--local", action="store_true", help="write .claude/settings.local.json instead (not shared)")
    p.add_argument("--python", help="interpreter command used by the hook (default: python on Windows, python3 elsewhere)")
    p.set_defaults(fn=cmd_install_hooks)

    sub.add_parser("hook").set_defaults(fn=cmd_hook)

    p = sub.add_parser("new")
    p.add_argument("--name", required=True)
    p.add_argument("--kind", default="persistent", choices=KINDS)
    # Production is only reachable through `status`, which validates first (rule 1).
    p.add_argument("--status", default="development", choices=["development", "test"])
    p.add_argument("--platform")
    p.add_argument("--definition-ref")
    p.add_argument("--created-by")
    p.add_argument("--owner")
    p.add_argument("--reports-to")
    p.add_argument("--role", choices=["chief"], help="mark the main orchestrating agent")
    p.set_defaults(fn=cmd_new)

    p = sub.add_parser("spawn")
    p.add_argument("--name", required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--parent", help="AGT-id of the spawning agent (default: the chief)")
    p.add_argument("--platform")
    p.add_argument("--provider")
    p.add_argument("--model")
    p.add_argument("--region")
    p.add_argument("--tools", nargs="*")
    p.add_argument("--data", nargs="*")
    p.add_argument("--personal-data", action="store_true")
    p.add_argument("--owner")
    p.add_argument("--session")
    p.add_argument("--by")
    p.set_defaults(fn=cmd_spawn)

    p = sub.add_parser("end")
    p.add_argument("agent_id")
    p.add_argument("--result", required=True)
    p.add_argument("--killed", action="store_true", help="stopped because it went wrong")
    p.set_defaults(fn=cmd_end)

    p = sub.add_parser("seal")
    p.add_argument("agent_id")
    p.add_argument("--change", required=True)
    p.add_argument("--by", default="unknown")
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("status")
    p.add_argument("agent_id")
    p.add_argument("status")
    p.add_argument("--reason", required=True)
    p.add_argument("--by", default="unknown")
    p.add_argument("--still-invocable", action="store_true",
                   help="for killed/ended agents that can still be resumed (e.g. an ended subagent session)")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("review")
    p.add_argument("agent_id")
    p.add_argument("--by", required=True)
    p.add_argument("--notes")
    p.set_defaults(fn=cmd_review)

    sub.add_parser("scan").set_defaults(fn=cmd_scan)

    p = sub.add_parser("validate")
    p.add_argument("--strict", action="store_true", help="exit 2 on warnings too")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_validate)

    p = sub.add_parser("report")
    p.add_argument("--since", help="YYYY-MM-DD or 'today'")
    p.add_argument("--session", help="session id (prefix is enough)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_report)

    sub.add_parser("build").set_defaults(fn=cmd_build)

    p = sub.add_parser("trace", help="who changed a file, folder or graphify cluster")
    p.add_argument("query", help="file path, folder, or graphify cluster/node name (substring)")
    p.add_argument("--since", help="YYYY-MM-DD")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_trace)

    sub.add_parser("verify", help="check the audit log's hash chain").set_defaults(fn=cmd_verify)

    p = sub.add_parser("directory")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_directory)

    args = ap.parse_args()
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    args.fn(args)


if __name__ == "__main__":
    main()
