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
import fnmatch
import hashlib
import html
import json
import os
import re
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
PRE_TOOLS = TRACKED_TOOLS                                   # tools the PreToolUse hook needs to see
READ_TOOLS = {"Read", "Grep", "Glob", "WebFetch", "WebSearch"}
MAX_SEARCH_FILES = 100                                       # matched files recorded per Grep call
SENSITIVE_FILE = "sensitive-paths.txt"
DEFAULT_SENSITIVE = [".env*", "*.pem", "*.key", "id_rsa*", "*secret*", "*credentials*"]
PROTECTED_FILES = {"activity.jsonl", "anchors.jsonl"}

# Secret redaction. Best effort: applied to commands and MCP inputs before anything is written.
SECRET_KEY = r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|" \
             r"client[_-]?secret|credentials?|authorization|auth[_-]?token|session[_-]?id|cookie|signature|sas[_-]?token)"
SECRET_KEY_RE = re.compile(r"(?i)^[\w.-]*" + SECRET_KEY + r"[\w.-]*$")
SECRET_PATTERNS = [
    # Authorization headers first, so the generic key rule below doesn't stop at the word "Bearer"
    (re.compile(r"(?i)((?:proxy-)?auth(?:orization)?\s*:\s*)(?:(?:bearer|basic|token|digest)\s+)?[^\s\"']+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[\w.~+/=-]+"), "Bearer [REDACTED]"),
    # "password": "x"  /  'api_key': 'x'  (JSON / dict style)
    (re.compile(r"(?i)([\"']?[\w.-]*" + SECRET_KEY + r"[\w.-]*[\"']?\s*:\s*)([\"'])(?:\\.|(?!\2).)*\2"), r"\1\2[REDACTED]\2"),
    # KEY=value, --password=value, password: value  (env, flags, yaml-ish)
    (re.compile(r"(?i)((?:--?)?[\w.-]*" + SECRET_KEY + r"[\w.-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)"), r"\1[REDACTED]"),
    # --password value / --token value
    (re.compile(r"(?i)(--?[\w-]*" + SECRET_KEY + r"[\w-]*\s+)(\"[^\"]*\"|'[^']*'|[^\s-]\S*)"), r"\1[REDACTED]"),
    # credentials inside URLs: scheme://user:pass@host
    (re.compile(r"([a-zA-Z][\w+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    # curl -u user:pass / --user user:pass
    (re.compile(r"((?:^|\s)(?:-u|--user)\s+)[^\s:]+:\S+"), r"\1[REDACTED]"),
    # mysql -pSecret (password glued to -p)
    (re.compile(r"(\bmysql\w*\b[^|;&\n]*?\s-p)(?!\s)\S+"), r"\1[REDACTED]"),
    # Well-known token formats
    (re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{12,}"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), "[REDACTED]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "[REDACTED]"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), "[REDACTED]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}"), "[REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"), "[REDACTED PRIVATE KEY]"),
]

# Rule 2: a change in any of these fields is material and must be sealed with a changelog entry.
# kind/role/owner/auto_registered are included so they cannot be flipped quietly to dodge the rules.
FINGERPRINT_FIELDS = ["model", "task", "data_dependencies", "permissions", "access", "reports_to",
                      "owner", "kind", "role", "auto_registered"]

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
    """Date used for *checking* (review age). PASSPORT_TODAY may fake it for tests; it never affects
    what gets written, so it cannot be used to backdate a review or a change."""
    forced = os.environ.get("PASSPORT_TODAY")
    return dt.date.fromisoformat(forced) if forced else dt.date.today()


def stamp():
    """Real date for everything that is written."""
    return dt.date.today().isoformat()


def now_iso():
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")  # with UTC offset


def in_agent_session():
    """True when this command runs inside an AI agent's shell (used to flag self-approval)."""
    return any(os.environ.get(k) for k in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_SANDBOX",
                                           "CURSOR_AGENT", "GEMINI_CLI", "PASSPORT_AGENT_SESSION"))


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
    p.setdefault("changelog", []).append({"date": stamp(), "change": change, "by": by})


def seal_passport(p, change, by):
    p["updated_at"] = stamp()
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


class FileLock:
    """Cross-process lock via an exclusive lock file. Hooks hold it for milliseconds, so a lock older
    than `stale` seconds belongs to a crashed process and is taken over."""

    def __init__(self, root, name, wait=20.0, stale=5.0):
        self.path, self.wait, self.stale, self.held = root / name, wait, stale, False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        deadline = time.time() + self.wait
        while time.time() < deadline:
            try:
                os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
                self.held = True
                return self
            except FileExistsError:
                try:
                    if time.time() - self.path.stat().st_mtime > self.stale:
                        self.path.unlink()
                        continue
                except OSError:
                    pass
                time.sleep(0.01)
        return self

    def __exit__(self, *exc):
        if self.held:
            try:
                self.path.unlink()
            except OSError:
                pass


def log_head(path):
    """(number of entries, hash of the last entry) of the activity log."""
    if not path.exists():
        return 0, "GENESIS"
    count, head = 0, "GENESIS"
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip():
                continue
            count += 1
            try:
                head = json.loads(line).get("hash") or hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()
            except ValueError:
                head = hashlib.sha256(line.rstrip("\n").encode("utf-8")).hexdigest()
    return count, head


def activity(root, event, **fields):
    """Append-only audit log. Every entry carries the hash of the previous one, so a later edit,
    deletion or reordering breaks the chain. That detects changes, but anyone with write access can
    recompute the whole chain; only anchors stored outside the agent's reach (see `anchor`) make
    rewriting or truncating the log detectable."""
    activity_batch(root, [(event, fields)])


def activity_batch(root, items):
    """Append several chained entries under one lock with a single write and fsync."""
    if not items:
        return
    root.mkdir(parents=True, exist_ok=True)
    path = root / "activity.jsonl"
    with FileLock(root, ".activity.lock") as lock:
        prev = "GENESIS"
        if path.exists():
            last = _last_line(path)
            if last:
                try:
                    prev = json.loads(last).get("hash") or hashlib.sha256(last.encode("utf-8")).hexdigest()
                except ValueError:
                    prev = hashlib.sha256(last.encode("utf-8")).hexdigest()
        out = []
        for event, fields in items:
            entry = {"ts": now_iso(), "event": event, **fields, "prev": prev}
            if not lock.held:
                entry["lock"] = "timeout"  # written without the lock: a later chain break here is a race, not tampering
            entry["hash"] = entry_hash(entry)
            prev = entry["hash"]
            out.append(json.dumps(entry, ensure_ascii=False) + "\n")
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        try:
            os.write(fd, "".join(out).encode("utf-8"))  # one write call, so lines are never interleaved
            os.fsync(fd)
        finally:
            os.close(fd)


def anchor(root, reason, by=None):
    """Record the current head of the log (count + hash) so truncation or a rewritten chain can be
    detected later. Local anchors live in anchors.jsonl; copies sent to PASSPORT_ANCHOR_FILE
    (e.g. a network share or synced folder the agent can't write to) or PASSPORT_ANCHOR_URL (a webhook,
    SIEM or log collector) are what make it hold up against someone who can rewrite this folder."""
    count, head = log_head(root / "activity.jsonl")
    rec = {"ts": now_iso(), "project": project_root(root).name, "entries": count, "head": head,
           "reason": reason, "by": by or ("agent session" if in_agent_session() else "human/CLI")}
    line = json.dumps(rec, ensure_ascii=False) + "\n"
    with open(root / "anchors.jsonl", "a", encoding="utf-8") as fh:
        fh.write(line)
    sent = []
    ext_file = os.environ.get("PASSPORT_ANCHOR_FILE")
    if ext_file:
        try:
            with open(ext_file, "a", encoding="utf-8") as fh:
                fh.write(line)
            sent.append("file")
        except OSError as e:
            sent.append(f"file failed: {e}")
    url = os.environ.get("PASSPORT_ANCHOR_URL")
    if url:
        try:
            import urllib.request
            req = urllib.request.Request(url, data=line.encode("utf-8"), method="POST",
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).close()
            sent.append("url")
        except Exception as e:  # noqa: BLE001 - anchoring must never break the agent
            sent.append(f"url failed: {type(e).__name__}")
    return rec, sent


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
    text = str(text or "")
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_obj(obj):
    """Redact structured input (MCP arguments) by key name first, then by value pattern."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if SECRET_KEY_RE.match(str(k)) and v not in (None, "", [], {}) else redact_obj(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, str):
        return redact(obj)
    return obj


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
        import subprocess  # loaded only when needed: keeps every hook call fast
        out = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, timeout=5)
        return out.stdout.strip() or None
    except Exception:  # git missing or not a repo: no name, no problem
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
        # Auto-registered passports are created by a hook, not a person. Their gaps are warnings so they
        # never block work. That leniency only exists for subagent runs and the chief: setting the flag
        # on any other passport is itself an error, so it can't be used to silence the rules.
        flagged = bool(p.get("auto_registered"))
        auto = flagged and (kind == "ephemeral" or p.get("role") == "chief")
        if flagged and not auto:
            findings.append(finding("ERROR", aid, "rule-1-no-passport-no-production",
                                    "auto_registered is only valid for subagent runs and the chief; "
                                    "this passport is checked as a normal one"))
        gap = "WARNING" if auto else "ERROR"
        if p.get("role") == "chief" and not flagged and p.get("kind") != "persistent":
            findings.append(finding("ERROR", aid, "identity", "the chief must be a persistent agent"))
        rec = get(p, "review.recorded_from")
        if rec == "agent session" and status not in TERMINAL:
            findings.append(finding("WARNING", aid, "rule-3-quarterly-review",
                                    "last review was recorded from inside an agent session; a human should "
                                    "record it from their own terminal"))
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

    chiefs = [aid for aid, p in agents.items() if p.get("role") == "chief" and p.get("status") not in TERMINAL]
    if len(chiefs) > 1:
        findings.append(finding("WARNING", "-", "identity",
                                f"more than one active chief ({', '.join(chiefs)}); set the extras to ended"))

    # Gaps in the trail itself.
    errors_log = root / "hook-errors.log"
    if errors_log.exists():
        n = sum(1 for line in errors_log.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
        if n:
            findings.append(finding("WARNING", "-", "audit-trail",
                                    f"{n} hook error(s) in hook-errors.log: the trail may be incomplete around those times"))
    for e in read_activity(root):
        if e.get("event") == "audit_log_edit":
            findings.append(finding("WARNING", e.get("actor") or str(e.get("subagent_id")), "audit-trail",
                                    f"{e.get('file')} was edited directly at {e.get('ts')}; run verify"))
    # Who read sensitive paths without the passport saying they may.
    flagged = {}
    for r in read_ledger(root, agents)[0]:
        if r["sens"]:
            flagged.setdefault((r["actor"], r["pattern"]), []).append(r["path"])
    for (actor, pat), paths in flagged.items():
        uncovered = sorted({x for x in paths if not declares_access(agents.get(actor), agents, x)})
        if uncovered:
            findings.append(finding("WARNING", actor, "data-access",
                                    f"read {len(uncovered)} sensitive path(s) matching '{pat}' (e.g. {uncovered[0]}) that its "
                                    "passport does not cover: add them to permissions.file_access or data_dependencies, "
                                    "or find out why they were read"))
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
    """The main session that talks to the user and spawns subagents. Created once per project.
    Parallel hooks can race here, so the check-and-create happens under a lock."""
    agents, _ = load_all(root)
    chief = find_chief(agents)
    if chief:
        return chief
    with FileLock(root, ".chief.lock"):
        agents, _ = load_all(root)
        chief = find_chief(agents)
        if chief:
            return chief
        return _create_chief(root, platform)


def _create_chief(root, platform):
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
        "created_at": stamp(),
        "updated_at": stamp(),
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
        "created_at": stamp(),
        "updated_at": stamp(),
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
    p["updated_at"] = stamp()
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
        real_id = resp.get("agentId")
        if real_id:
            # PostToolUse is matched by tool_use_id, so this mapping is authoritative. Undo any guess
            # SubagentStart made for another passport with the same runtime id.
            for other in agents.values():
                if other is not p and get(other, "runtime.agent_id") == real_id:
                    other["runtime"]["agent_id"] = None
                    save(root, other)
            rt["agent_id"] = real_id
        pending = take_pending_stop(root, rt.get("agent_id"))
        if pending:
            rt["transcript"] = pending.get("agent_transcript_path")
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
        pending = None
    save(root, p)
    if done:
        finish(root, p, text)
    elif pending:  # the background run already stopped before we knew which passport it belonged to
        finish(root, p, pending.get("last_assistant_message"))
    else:
        activity(root, "running", agent_id=p["agent_id"], name=p.get("name"), session_id=rt.get("session_id"),
                 note="started in the background")


def on_subagent_start(root, payload):
    """SubagentStart carries no tool_use_id, so it can only be matched by session + agent type.
    Only link when exactly one run is waiting; otherwise PostToolUse makes the authoritative link."""
    agents, _ = load_all(root)
    waiting = [p for p in agents.values()
               if p.get("status") == "production" and not get(p, "runtime.agent_id")
               and get(p, "runtime.session_id") == payload.get("session_id")
               and get(p, "runtime.agent_type") == payload.get("agent_type")]
    if len(waiting) == 1:
        waiting[0]["runtime"]["agent_id"] = payload.get("agent_id")
        save(root, waiting[0])


def stash_pending_stop(root, payload):
    d = root / ".pending"
    d.mkdir(exist_ok=True)
    keep = {k: payload.get(k) for k in ("agent_id", "agent_transcript_path", "last_assistant_message", "session_id")}
    (d / f"{re.sub(r'[^A-Za-z0-9_-]', '_', str(payload.get('agent_id')))}.json").write_text(
        json.dumps(keep, ensure_ascii=False), encoding="utf-8")


def take_pending_stop(root, agent_id):
    if not agent_id:
        return None
    f = root / ".pending" / f"{re.sub(r'[^A-Za-z0-9_-]', '_', str(agent_id))}.json"
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        f.unlink()
        return data
    except (OSError, ValueError):
        return None


def on_subagent_stop(root, payload):
    agents, _ = load_all(root)
    p = find_by_runtime(agents, agent_id=payload.get("agent_id"))
    if not p:
        # Not linked yet (parallel runs of the same type): keep it until PostToolUse links the run.
        stash_pending_stop(root, payload)
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


def cached_chief(root):
    """Id of the active chief from a one-line cache, checked against its passport. Avoids loading every
    passport on each hook call (this matters for read hooks, which fire very often)."""
    try:
        cid = (root / ".chief").read_text(encoding="utf-8").strip()
        p = json.loads(passport_path(root, cid).read_text(encoding="utf-8"))
        if p.get("role") == "chief" and p.get("status") not in TERMINAL:
            return cid
    except (OSError, ValueError):
        pass
    return None


def resolve_actor(root, payload):
    """Tool calls made inside a subagent carry its runtime agent_id. That raw id is what gets stored;
    it is resolved to a passport when the trail is read, after PostToolUse has made the authoritative
    link. Calls without an agent_id come from the chief."""
    sub = payload.get("agent_id")
    if sub:
        return None, sub
    cid = cached_chief(root)
    if cid:
        return cid, None
    agents, _ = load_all(root)
    chief = find_chief(agents) or ensure_chief(root)
    try:
        (root / ".chief").write_text(chief["agent_id"], encoding="utf-8")
    except OSError:
        pass
    return chief["agent_id"], None


def is_protected(root, rel):
    return bool(rel) and rel.startswith(root.name + "/") and rel.split("/")[-1] in PROTECTED_FILES


def on_pre_tool(root, payload):
    """Block direct edits to the audit log and anchors. Returns a deny decision or None.
    Only passport.py itself appends to them."""
    tool = payload.get("tool_name")
    ti = payload.get("tool_input") or {}
    if tool in FILE_TOOLS:
        rel = rel_to_project(root, ti.get("file_path") or ti.get("notebook_path"))
        if is_protected(root, rel):
            return f"{rel} is the append-only audit trail; only passport.py may write to it."
    elif tool in COMMAND_TOOLS:
        cmd = str(ti.get("command") or "")
        if any(name in cmd for name in PROTECTED_FILES) and "passport.py" not in cmd:
            # Reading is fine; anything that could write, move or delete is not.
            if re.search(r"(>|\brm\b|\bdel\b|\bmv\b|\bmove\b|\bcp\b|\bcopy\b|\bsed\b|\btruncate\b|Set-Content|Out-File|"
                         r"Remove-Item|Clear-Content|Add-Content|\btee\b|\bperl\b|\bpython\b|\bnode\b|\bgit\s+(checkout|restore|rm|reset))",
                         cmd, re.I):
                return ("This command could modify the append-only audit trail (activity.jsonl / anchors.jsonl). "
                        "Use passport.py commands instead.")
    return None


def on_tool_use(root, payload):
    tool = payload.get("tool_name")
    ti = payload.get("tool_input") or {}
    actor, sub = resolve_actor(root, payload)
    base = {"actor": actor, "subagent_id": sub, "session_id": payload.get("session_id"), "tool": tool}
    if tool in FILE_TOOLS:
        rel = rel_to_project(root, ti.get("file_path") or ti.get("notebook_path"))
        if not rel:
            return
        digest, size = file_digest(root, rel)
        # Edits to passports are logged like any other file; an edit to the trail itself is flagged.
        event = "audit_log_edit" if is_protected(root, rel) else "file_change"
        activity(root, event, **base, file=rel, sha256=digest, bytes=size)
    elif tool.startswith("mcp__"):
        # Actions in external systems (CRM, mail, databases) through MCP servers.
        resp = payload.get("tool_response")
        failed = isinstance(resp, dict) and bool(resp.get("isError") or resp.get("is_error"))
        activity(root, "command", **base, command=clip(tool + " " + json.dumps(redact_obj(ti), ensure_ascii=False), 300),
                 description="external action via MCP", failed=failed)
    else:
        resp = payload.get("tool_response")
        failed = None
        if isinstance(resp, dict):
            code = resp.get("returnCode", resp.get("exit_code"))
            failed = bool(resp.get("interrupted")) or (code not in (None, 0))
        activity(root, "command", **base, command=clip(redact(ti.get("command")), 300),
                 description=clip(ti.get("description"), 120) or None, failed=failed)


def sensitive_patterns(root):
    pats = list(DEFAULT_SENSITIVE)
    try:
        for line in (root / SENSITIVE_FILE).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                pats.append(line)
    except OSError:
        pass
    return pats


def match_sensitive(pats, rel):
    """The first sensitive pattern a project-relative path matches, else None."""
    if not rel:
        return None
    low = rel.lower()
    name = low.rsplit("/", 1)[-1]
    if name in {".env.example", ".env.sample", ".env.template", ".env.dist"}:
        return None  # templates hold no real secrets
    for pat in pats:
        p = pat.lower().replace("\\", "/")
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(low, p) or fnmatch.fnmatch(low, p.rstrip("/") + "/*"):
            return pat
    return None


def strip_url(url):
    """Drop the query string and fragment (they often carry tokens), then redact what is left."""
    return redact(re.sub(r"[?#].*$", "", str(url or "")))


def _state_path(root, sid):
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", str(sid or "nosession"))
    return root / ".state" / f"reads-{safe}.json"


def _load_state(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def read_items(root, payload):
    """(kind, text) pairs for one read-type tool call. No contents, no hashes: what was looked at, not what it said."""
    tool = payload.get("tool_name")
    ti = payload.get("tool_input") or {}
    resp = payload.get("tool_response")
    items = []
    if tool == "Read":
        items.append(("file", rel_to_project(root, ti.get("file_path") or ti.get("notebook_path"))))
    elif tool == "Grep":
        scope = rel_to_project(root, ti.get("path")) or "."
        items.append(("search", f"grep {clip(redact(ti.get('pattern')), 120)} in {scope}"))
        names = resp.get("filenames") if isinstance(resp, dict) else None
        for f in (names or [])[:MAX_SEARCH_FILES]:  # files whose content the agent saw in the result
            items.append(("file", rel_to_project(root, f)))
    elif tool == "Glob":
        scope = rel_to_project(root, ti.get("path")) or "."
        items.append(("search", f"glob {clip(redact(ti.get('pattern')), 120)} in {scope}"))
    elif tool == "WebFetch":
        items.append(("url", clip(strip_url(ti.get("url")), 200)))
    elif tool == "WebSearch":
        items.append(("query", clip(redact(ti.get("query")), 200)))
    prefix = root.name + "/"
    return [(k, t) for k, t in items if t and not (k == "file" and t.startswith(prefix))]


def on_read(root, payload):
    """Record what an agent looked at. Each (agent, item) is logged once per session with a counter kept in a
    small state file; reads of sensitive paths are always logged. A summary is written when the agent or
    session ends (see flush_reads)."""
    items = read_items(root, payload)
    if not items:
        return
    actor, sub = resolve_actor(root, payload)
    key_actor = sub or actor
    base = {"actor": actor, "subagent_id": sub, "session_id": payload.get("session_id"), "tool": payload.get("tool_name")}
    pats = sensitive_patterns(root)
    path = _state_path(root, payload.get("session_id"))
    path.parent.mkdir(parents=True, exist_ok=True)
    batch = []
    with FileLock(root, ".reads.lock"):
        state = _load_state(path)
        for kind, text in items:
            key = f"{key_actor}|{kind}|{text}"
            seen = key in state
            state[key] = state.get(key, 0) + 1
            pat = match_sensitive(pats, text) if kind == "file" else None
            if seen and not pat:
                continue
            fields = {**base, "kind": kind, "path": text}
            if pat:
                fields.update(sens=True, pattern=pat)
            batch.append(("read", fields))
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, path)
    activity_batch(root, batch)


def flush_reads(root, sid, only_actor=None):
    """Write one reads_summary per agent from the session's counters and drop what was summarised."""
    path = _state_path(root, sid)
    if not path.exists():
        return
    summaries = {}
    with FileLock(root, ".reads.lock"):
        state = _load_state(path)
        keep = {}
        for key, n in state.items():
            actor, kind, text = (key.split("|", 2) + ["", ""])[:3]
            if only_actor and actor != only_actor:
                keep[key] = n
                continue
            g = summaries.setdefault(actor, {"unique": 0, "total": 0, "repeats": {}})
            g["unique"] += 1
            g["total"] += n
            if n > 1 and len(g["repeats"]) < 50:
                g["repeats"][text] = n
        if keep:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(keep), encoding="utf-8")
            os.replace(tmp, path)
        else:
            try:
                path.unlink()
            except OSError:
                pass
    activity_batch(root, [("reads_summary", {"actor": a if ID_RE.match(a) else None,
                                              "subagent_id": None if ID_RE.match(a) else a,
                                              "session_id": sid, **g}) for a, g in summaries.items()])


def cmd_hook(args):
    """Never fails the agent because of a registry problem: errors go to hook-errors.log and are
    recorded in the trail as a gap. The only thing it ever blocks is a direct edit of the audit log."""
    root = root_dir(args)
    if args.global_hook and not global_hook_applies(root):
        sys.exit(0)
    try:
        raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")  # hook payloads are UTF-8
        payload = json.loads(raw) if raw.strip() else {}
        event = payload.get("hook_event_name")
        if not root.exists():
            # First agent activity in this project: start its register automatically.
            init_folder(root)
            activity(root, "registry_initialised", by=HOOK_BY,
                     note="created automatically on the first agent activity in this project")
        if event == "PreToolUse" and payload.get("tool_name") in FILE_TOOLS | COMMAND_TOOLS:
            reason = on_pre_tool(root, payload)
            if reason:
                actor, sub = resolve_actor(root, payload)
                activity(root, "blocked", actor=actor, subagent_id=sub, session_id=payload.get("session_id"),
                         tool=payload.get("tool_name"), reason=reason)
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                         "permissionDecision": "deny",
                                                         "permissionDecisionReason": reason}}))
            return
        if event == "PreToolUse" and payload.get("tool_name") in SPAWN_TOOLS:
            on_spawn(root, payload)
        elif event == "PostToolUse" and payload.get("tool_name") in SPAWN_TOOLS:
            on_spawn_done(root, payload)
        elif event == "PostToolUse" and payload.get("tool_name") in READ_TOOLS:
            on_read(root, payload)
            return
        elif event == "PostToolUse" and (payload.get("tool_name") in FILE_TOOLS | COMMAND_TOOLS
                                         or str(payload.get("tool_name")).startswith("mcp__")):
            on_tool_use(root, payload)
            return
        elif event == "SubagentStart":
            on_subagent_start(root, payload)
        elif event == "SubagentStop":
            flush_reads(root, payload.get("session_id"), payload.get("agent_id"))
            on_subagent_stop(root, payload)
        elif event == "SessionEnd":
            flush_reads(root, payload.get("session_id"))
            on_session_end(root, payload)
            anchor(root, "session end", by=HOOK_BY)
        else:
            return
        if event in {"PostToolUse", "SubagentStop", "SessionEnd"}:
            write_outputs(root, force=(event == "SessionEnd"))
    except Exception as e:  # noqa: BLE001 - a registry problem must never break the user's work
        try:
            with open(root / "hook-errors.log", "a", encoding="utf-8") as fh:
                fh.write(f"{now_iso()} {type(e).__name__}: {e}\n")
            activity(root, "hook_error", error=f"{type(e).__name__}: {clip(str(e), 200)}",
                     note="the trail may be incomplete around this time")
        except Exception:  # noqa: BLE001
            pass
    sys.exit(0)


def is_passport_command(cmd):
    return "passport.py" in cmd or "import passport;" in cmd


def hook_command(python, folder, dir_arg, extra=""):
    """Run the script as an imported module: Python then keeps the compiled version and skips about
    60 ms of compiling on every hook call. -S skips site-packages, the tool needs only the standard library."""
    # dont_write_bytecode=False: some environments set PYTHONDONTWRITEBYTECODE, which would defeat the cache
    code = "import sys;sys.dont_write_bytecode=False;sys.path.insert(0,r'" + folder + "');import passport;passport.main()"
    return f'{python} -S -c "{code}" --dir "{dir_arg}" hook{extra}'


GLOBAL_HOME = Path.home() / ".agent-passport"
OPT_OUT_FILE = ".no-agent-passports"


def has_project_hooks(proj):
    for name in ("settings.json", "settings.local.json"):
        f = proj / ".claude" / name
        try:
            text = f.read_text(encoding="utf-8")
            if is_passport_command(text) and "--global-hook" not in text:
                return True
        except OSError:
            pass
    return False


def global_hook_applies(root):
    """The user-level hook runs in every Claude Code session. It stays out of the way when it shouldn't act:
    the home folder itself, projects that opted out, and projects that have their own passport hooks
    (which would otherwise log everything twice)."""
    proj = project_root(root)
    if os.environ.get("PASSPORT_DISABLE"):
        return False
    try:
        if not proj.is_dir() or proj.resolve() == Path.home().resolve():
            return False
    except OSError:
        return False
    if (proj / OPT_OUT_FILE).exists():
        return False
    return not has_project_hooks(proj)


def write_hooks(settings_path, command):
    settings = json.loads(settings_path.read_text(encoding="utf-8")) if settings_path.exists() else {}
    wanted = {"PreToolUse": "|".join(sorted(PRE_TOOLS)),
              "PostToolUse": "|".join(sorted(TRACKED_TOOLS | READ_TOOLS)) + "|mcp__.*",
              "SubagentStart": None, "SubagentStop": None, "SessionEnd": None}
    hooks = settings.setdefault("hooks", {})
    for event, matcher in wanted.items():
        # Replace an older passport hook instead of adding a second one; other hooks are left alone.
        entries = [e for e in hooks.get(event, [])
                   if not any(is_passport_command(h.get("command", "")) for h in e.get("hooks", []))]
        hooks[event] = entries
        if command is None:
            if not entries:
                hooks.pop(event)
            continue
        entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
        if matcher:
            entry = {"matcher": matcher, **entry}
        entries.append(entry)
    if not hooks:
        settings.pop("hooks")
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")


def cmd_install_hooks(args):
    if args.global_:
        # User level: every project gets its own agent-passports/ on its first agent activity.
        GLOBAL_HOME.mkdir(parents=True, exist_ok=True)
        script = GLOBAL_HOME / "passport.py"
        import shutil
        shutil.copy2(Path(__file__).resolve(), script)
        python = args.python or Path(sys.executable).as_posix()  # this machine's interpreter: no PATH guessing
        command = hook_command(f'"{python}"', script.parent.as_posix(), "$CLAUDE_PROJECT_DIR/agent-passports",
                               " --global-hook")
        settings_path = Path.home() / ".claude" / "settings.json"
        write_hooks(settings_path, None if args.remove else command)
        if args.remove:
            print(f"Global agent-passport hooks removed from {settings_path}")
            return
        print(f"Global hooks written to {settings_path} (script: {script})")
        print("From the next Claude Code session on, every project gets agent-passports/ on its first agent")
        print(f"activity. Opt a project out with an empty '{OPT_OUT_FILE}' file in its root; set PASSPORT_DISABLE=1")
        print("to pause everywhere. Projects with their own passport hooks keep using those.")
        return
    root = root_dir(args)
    proj = project_root(root)
    settings_path = proj / ".claude" / ("settings.local.json" if args.local else "settings.json")
    python = args.python or ("python" if os.name == "nt" else "python3")
    rel = root.relative_to(proj).as_posix()
    command = hook_command(python, f"$CLAUDE_PROJECT_DIR/{rel}", f"$CLAUDE_PROJECT_DIR/{rel}")
    write_hooks(settings_path, None if args.remove else command)
    if args.remove:
        print(f"Agent-passport hooks removed from {settings_path.relative_to(proj).as_posix()}")
        return
    print(f"Auto-registration hooks written to {settings_path.relative_to(proj).as_posix()}")
    print("Every subagent spawned in this project now gets a passport automatically, and every file change")
    print("and command is attributed to the agent that made it (agent-passports/activity.jsonl).")


# ---------------------------------------------------------------- manual commands

def init_folder(root):
    (root / "passports").mkdir(parents=True, exist_ok=True)
    here = Path(__file__).resolve()
    if here.parent != root:
        import shutil
        shutil.copy2(here, root / "passport.py")
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8")
    ignore = root / ".gitignore"
    if not ignore.exists():
        ignore.write_text("__pycache__/\n.state/\n.pending/\n.chief\n.*.lock\n", encoding="utf-8")
    sens = root / SENSITIVE_FILE
    if not sens.exists():
        sens.write_text(SENSITIVE_TEMPLATE, encoding="utf-8")


def cmd_init(args):
    root = root_dir(args)
    init_folder(root)
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
    p["created_at"] = p["updated_at"] = stamp()
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
              "created_at": stamp(), "updated_at": stamp(),
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
    # Every seal also lands in the hash-chained log with the real time, so changes can't be backdated.
    activity(root, "seal", agent_id=args.agent_id, change=clip(args.change, 300), by=args.by,
             fingerprint=p["fingerprint"], recorded_from="agent session" if in_agent_session() else "human shell")
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
    p["updated_at"] = stamp()
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
    d = dt.date.today()  # always the real date: a review cannot be backdated
    agent = in_agent_session()
    p.setdefault("review", {})
    p["review"]["last_reviewed"] = d.isoformat()
    p["review"]["reviewed_by"] = args.by
    p["review"]["next_review_due"] = (d + dt.timedelta(days=REVIEW_DAYS)).isoformat()
    # The reviewer name is self-declared. Record where the command ran so a review "signed" from
    # inside an agent session is visible to validate and to auditors.
    p["review"]["recorded_from"] = "agent session" if agent else "human shell"
    log(p, "quarterly review" + (f": {args.notes}" if args.notes else ""), args.by)
    save(root, p)
    activity(root, "review", agent_id=args.agent_id, reviewer=args.by,
             recorded_from=p["review"]["recorded_from"], notes=clip(args.notes, 200) or None)
    print(f"{args.agent_id} reviewed, next review due {p['review']['next_review_due']}")
    if agent:
        print("Note: this review was recorded from inside an agent session. Validation will flag it until a "
              "human records the review from their own terminal.")


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
        if t["event"] == "file_change" and t["file"]:  # commands have no file
            touched.setdefault(t["actor"], []).append(t["file"])
    read_by, sens_by = {}, {}
    for r in read_ledger(root, agents)[0]:
        if r["kind"] == "file":
            read_by.setdefault(r["actor"], set()).add(r["path"])
        if r["sens"]:
            sens_by[r["actor"]] = sens_by.get(r["actor"], 0) + 1
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
            "files": sorted(set(touched.get(aid, []))), "role": role_of(p, agents),
            "reads": sorted(read_by.get(aid, [])), "sens_reads": sens_by.get(aid, 0),
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


def render_summary(rows, since=None):
    roles = {}
    for r in rows:
        g = roles.setdefault(r["role"], {"runs": 0, "running": 0, "stopped": 0, "tokens": 0, "files": set(), "last": "",
                                         "reads": set(), "sens": 0})
        g["runs"] += 1
        g["running"] += r["status"] == "production"
        g["stopped"] += r["status"] == "killed"
        g["tokens"] += r["tokens"] or 0
        g["files"].update(r["files"])
        g["reads"].update(r.get("reads") or [])
        g["sens"] += r.get("sens_reads") or 0
        g["last"] = max(g["last"], r["started"] or "")
    sessions = {r["session"] for r in rows if r["session"]}
    out = [f"Agent activity summary{' since ' + since if since else ''}: {len(rows)} subagent runs, "
           f"{len(roles)} roles, {len(sessions)} sessions.", "",
           "| Role | Runs | Running | Stopped | Tokens | Files changed | Files read | Sensitive reads | Last run |",
           "|---|---|---|---|---|---|---|---|---|"]
    for role, g in sorted(roles.items(), key=lambda kv: -kv[1]["runs"]):
        out.append(f"| {md_value(role)} | {g['runs']} | {g['running']} | {g['stopped']} | {g['tokens']} | "
                   f"{len(g['files'])} | {len(g['reads'])} | {g['sens']} | {g['last'][:16].replace('T', ' ')} |")
    out += ["", "Details per run: `report --since <date>` or open agent-passports/registry.html."]
    return "\n".join(out) + "\n"


def cmd_report(args):
    root = root_dir(args)
    since = args.since
    if since == "today":
        since = today().isoformat()
    rows, changes = report_rows(root, since, args.session)
    if args.summary:
        print(render_summary(rows, since))
        return
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
        if e.get("event") not in ("file_change", "audit_log_edit", "command"):
            continue
        sub = e.get("subagent_id")
        # A subagent's raw runtime id is resolved now, using the link PostToolUse made by tool_use_id.
        actor = (by_sub.get(sub) or f"unresolved:{sub}") if sub else (e.get("actor") or "unknown")
        event = "file_change" if e["event"] == "audit_log_edit" else e["event"]
        out.append({"ts": e.get("ts"), "event": event, "flag": "audit log edited" if e["event"] == "audit_log_edit" else None,
                    "actor": actor,
                    "actor_name": (agents.get(actor) or {}).get("name"), "tool": e.get("tool"),
                    "file": e.get("file"), "sha256": e.get("sha256"), "command": e.get("command"),
                    "failed": e.get("failed"), "session": str(e.get("session_id") or "")[:8]})
    return out


def read_ledger(root, agents=None, events=None):
    """Read events and per-agent read summaries, with the actor resolved to a passport."""
    if agents is None:
        agents, _ = load_all(root)
    by_sub = {get(p, "runtime.agent_id"): aid for aid, p in agents.items() if get(p, "runtime.agent_id")}
    reads, sums = [], []
    for e in (events if events is not None else read_activity(root)):
        ev = e.get("event")
        if ev not in ("read", "reads_summary"):
            continue
        sub = e.get("subagent_id")
        actor = (by_sub.get(sub) or f"unresolved:{sub}") if sub else (e.get("actor") or "unknown")
        if ev == "read":
            reads.append({"ts": e.get("ts"), "actor": actor, "actor_name": (agents.get(actor) or {}).get("name"),
                          "tool": e.get("tool"), "kind": e.get("kind"), "path": e.get("path"),
                          "sens": bool(e.get("sens")), "pattern": e.get("pattern"),
                          "session": str(e.get("session_id") or "")[:8]})
        else:
            sums.append({"actor": actor, "unique": e.get("unique", 0), "total": e.get("total", 0),
                         "repeats": e.get("repeats") or {}, "ts": e.get("ts")})
    return reads, sums


def declares_access(p, agents, path):
    """True when a passport's permissions.file_access or data_dependencies cover this path.
    A subagent run is judged by the passport of the agent it is an instance of."""
    if p is None:
        return False
    base = agents.get(p.get("instance_of")) or p
    cands = []
    fa = get(base, "permissions.file_access")
    if isinstance(fa, list):
        cands += [str(x) for x in fa]
    elif isinstance(fa, str):
        cands.append(fa)
    deps = base.get("data_dependencies")
    if isinstance(deps, list):
        cands += [str(d.get("source")) if isinstance(d, dict) else str(d) for d in deps]
    low = path.lower().replace("\\", "/")
    name = low.rsplit("/", 1)[-1]
    for c in cands:
        c = re.sub(r"\s*\([^)]*\)\s*$", "", c.strip()).lower().replace("\\", "/")
        if not c or c in ("none", "-", "unknown"):
            continue
        if (fnmatch.fnmatch(low, c) or fnmatch.fnmatch(name, c) or fnmatch.fnmatch(low, c.rstrip("/") + "/*")
                or low.startswith(c.rstrip("/") + "/") or c == low):
            return True
    return False


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
    rhits = [r for r in read_ledger(root, agents)[0]
             if (not args.since or (r["ts"] or "") >= args.since)
             and (q in (r["path"] or "").lower() or (r["kind"] == "file" and matches(r["path"])))]
    if args.json:
        print(json.dumps({"query": args.query, "file_changes": hits, "commands": cmds, "reads": rhits},
                         indent=2, ensure_ascii=False))
        return
    print(f"# Trace: {args.query}\n")
    if gi:
        print(f"Graphify graph: {gi['path']} (built {gi['built_at']}, read-only)\n")
    if not hits and not cmds and not rhits:
        print("No recorded file changes, reads or commands match.")
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
    if rhits:
        print("\n## Read by\n\n| When | Agent | Tool | What | Sensitive |\n|---|---|---|---|---|")
        for r in rhits[:200]:
            print(f"| {r['ts'].replace('T', ' ')} | {r['actor']} {r['actor_name'] or ''} | {r['tool']} | "
                  f"{md_value(r['path'])} | {('yes (' + r['pattern'] + ')') if r['sens'] else '-'} |")
        if len(rhits) > 200:
            print(f"... and {len(rhits) - 200} more")
    actors = sorted({t["actor"] for t in hits + cmds + rhits if t["actor"] in agents})
    if actors:
        print("\n## Agents involved\n")
        for aid in actors:
            p = agents[aid]
            print(f"- {aid} {p.get('name')} ({p.get('kind')}, {p.get('status')}): model "
                  f"{get(p, 'runtime.resolved_model') or get(p, 'model.name')}, tools {md_value(get(p, 'permissions.tools'))}, "
                  f"reports to {p.get('reports_to')}, owner {p.get('owner')}")


def read_anchors(paths):
    anchors = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        a = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(a, dict) and "entries" in a and "head" in a:
                        a["_source"] = str(path)
                        anchors.append(a)
        except OSError:
            continue
    return anchors


def cmd_verify(args):
    """Check the activity log's hash chain, then compare it with every anchor that can be found.
    The chain alone catches edits by someone who did not recompute it; anchors kept outside this
    folder also catch a recomputed chain, deleted entries at the end, or a deleted log."""
    root = root_dir(args)
    path = root / "activity.jsonl"
    project = project_root(root).name
    sources = [root / "anchors.jsonl"] + [Path(p) for p in (args.anchors or [])]
    if os.environ.get("PASSPORT_ANCHOR_FILE"):
        sources.append(Path(os.environ["PASSPORT_ANCHOR_FILE"]))
    anchors = [a for a in read_anchors(sources) if a.get("project") in (None, project)]
    for spec in args.head or []:
        count, _, head = spec.partition(":")
        anchors.append({"entries": int(count), "head": head, "_source": "--head"})
    external = [a for a in anchors if a["_source"] != str(root / "anchors.jsonl")]

    problems, forks, hashes = [], 0, []
    if not path.exists():
        if any(a["entries"] > 0 for a in anchors):
            problems.append("activity.jsonl is missing, but anchors show it had entries: the log was deleted")
    else:
        prev = "GENESIS"
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except ValueError:
                problems.append(f"line {i}: not valid JSON (partial write or manual edit)")
                prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                hashes.append(prev)
                continue
            if "hash" not in e or "prev" not in e:
                problems.append(f"line {i}: entry without hash chain (inserted or from an older format)")
                prev = hashlib.sha256(line.encode("utf-8")).hexdigest()
                hashes.append(prev)
                continue
            if entry_hash(e) != e["hash"]:
                problems.append(f"line {i} ({e.get('ts')} {e.get('event')}): content changed after it was written")
            elif e.get("prev") != prev:
                if e.get("lock") == "timeout":
                    forks += 1  # concurrent write without lock: a fork in the chain, not an edit
                else:
                    problems.append(f"line {i} ({e.get('ts')} {e.get('event')}): chain broken (entry removed, "
                                    "inserted or reordered before this line)")
            prev = e["hash"]
            hashes.append(prev)
        for a in anchors:
            n = a["entries"]
            where = f"anchor from {a.get('ts', '?')} ({Path(a['_source']).name})"
            if n > len(hashes):
                problems.append(f"{where} saw {n} entries, the log has {len(hashes)}: entries were removed from the end")
            elif n > 0 and hashes[n - 1] != a["head"]:
                problems.append(f"{where}: entry {n} does not match, the log was rewritten")

    if problems:
        print("AUDIT LOG NOT INTACT")
        for p in problems:
            print(f"  - {p}")
        sys.exit(1)
    print(f"Hash chain intact: {len(hashes)} entries" + (f" ({forks} concurrency forks, not edits)" if forks else "") + ".")
    print(f"Anchors checked: {len(anchors)} ({len(external)} external).")
    if not external:
        print("Limit: without an anchor stored outside this folder, someone who can write here could rewrite the whole "
              "log and recompute the chain. Set PASSPORT_ANCHOR_FILE or PASSPORT_ANCHOR_URL, or pass --head COUNT:HASH "
              "from a record you trust.")


def cmd_anchor(args):
    root = root_dir(args)
    rec, sent = anchor(root, args.reason or "manual anchor", by=args.by)
    print(f"Anchored {rec['entries']} entries, head {rec['head'][:16]}... ({rec['ts']})")
    print("Copies: " + (", ".join(sent) if sent else "local only (set PASSPORT_ANCHOR_FILE or PASSPORT_ANCHOR_URL "
                                                     "for an external copy)"))
    print(f"To check later against this record: passport.py verify --head {rec['entries']}:{rec['head']}")


# ---------------------------------------------------------------- build outputs

BUILD_INTERVAL = 30  # seconds: during busy sessions the page is rebuilt at most this often


def write_outputs(root, force=True):
    if not force:
        try:
            if time.time() - (root / "registry.html").stat().st_mtime < BUILD_INTERVAL:
                return None
        except OSError:
            pass
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
        # Agents read this to find who they can call: finished subagent runs are left out to keep it small.
        "directory": [d for d in directory_entries(agents) if d["kind"] != "ephemeral" or d["invocable"]],
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
    (root / "registry.html").write_text(render_html(dict(registry, _root=root), agents, gi), encoding="utf-8")
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


def role_of(p, agents):
    """Runs are grouped by role: the persistent agent they are an instance of, else their agent type."""
    inst = p.get("instance_of")
    if inst and inst in agents:
        return agents[inst].get("name") or inst
    return get(p, "runtime.agent_type") or p.get("name") or "subagent"


def view_data(reg, agents, gi):
    """Compact data for the organogram page. Runs and events are kept small so the page stays fast with
    thousands of runs; all grouping, period filtering and charts are done in the browser."""
    persistent, runs = {}, []
    for aid, p in sorted(agents.items()):
        if p.get("kind") == "ephemeral":
            rt = p.get("runtime") or {}
            tools = get(p, "permissions.tools")
            deps = p.get("data_dependencies")
            runs.append({
                "id": aid, "role": role_of(p, agents), "inst": p.get("instance_of"), "parent": p.get("reports_to"),
                "task": get(p, "task.purpose"), "prompt": clip((get(p, "task.in_scope") or [""])[0], 300),
                "status": p.get("status"), "inv": bool(p.get("invocable")) and bool(rt.get("agent_id")),
                "session": str(rt.get("session_id") or "")[:8], "start": rt.get("started_at") or p.get("created_at"),
                "end": rt.get("ended_at"), "ms": rt.get("duration_ms"), "tok": rt.get("tokens"),
                "model": rt.get("resolved_model") or get(p, "model.name"),
                "tools": ", ".join(tools) if isinstance(tools, list) else tools,
                "data": "; ".join(d.get("source", "") if isinstance(d, dict) else str(d) for d in deps) if isinstance(deps, list) else deps,
                "owner": p.get("owner"), "transcript": rt.get("transcript"), "result": clip(rt.get("result_summary"), 500),
                "agent": rt.get("agent_id"), "how": p.get("how_to_invoke"), "auto": bool(p.get("auto_registered")),
            })
        else:
            q = {k: v for k, v in p.items() if not k.startswith("_")}
            q["changelog"] = (q.get("changelog") or [])[-8:]
            persistent[aid] = q
    events, gfiles = [], {}
    for t in file_ledger_entries(reg["_root"], agents):
        e = {"t": t["ts"], "a": t["actor"], "k": "f" if t["event"] == "file_change" else "c", "tool": t["tool"],
             "s": str(t.get("session") or "")}
        if e["k"] == "f":
            e["p"] = t["file"]
            e["sha"] = (t["sha256"] or "")[:12]
            if t.get("flag"):
                e["flag"] = t["flag"]
            if gi and t["file"] in gi["files"] and t["file"] not in gfiles:
                g = gi["files"][t["file"]]
                gfiles[t["file"]] = {"c": sorted(set(g["communities"].values())), "n": g["nodes"][:8],
                                     "r": (gi["related"].get(t["file"]) or [])[:10]}
        else:
            e["p"] = t["command"]
            e["fail"] = t["failed"]
        events.append(e)
    rd, rsums = read_ledger(reg["_root"], agents)
    agg = {}
    for r in rd:  # one row per agent and item, however often it was read
        key = (r["actor"], r["kind"], r["path"])
        g = agg.get(key)
        if g is None:
            g = agg[key] = {"a": r["actor"], "k": (r["kind"] or "f")[0], "p": r["path"], "t": r["ts"], "n": 1, "x": r["tool"]}
            if r["sens"]:
                g.update(s=1, pt=r["pattern"])
        else:
            g["n"] += 1
            g["t"] = r["ts"]
    totals = {}
    for sm in rsums:
        t = totals.setdefault(sm["actor"], {"u": 0, "t": 0})
        t["u"] += sm["unique"]
        t["t"] += sm["total"]
        for text, n in sm["repeats"].items():
            for (actor, kind, path), g in agg.items():
                if actor == sm["actor"] and path == text and not g.get("s"):
                    g["n"] = max(g["n"], n)
    reads = sorted(agg.values(), key=lambda g: g["t"] or "")[-5000:]
    return {"generated_at": reg["generated_at"], "project": project_root(reg["_root"]).name,
            "summary": reg["summary"], "findings": reg["findings"], "persistent": persistent, "runs": runs,
            "events": events, "graph": gfiles, "reads": reads, "read_totals": totals,
            "graphify": {"path": gi["path"], "built_at": gi["built_at"]} if gi else None}


def render_html(reg, agents, gi):
    data = json.dumps(view_data(reg, agents, gi), ensure_ascii=False, separators=(",", ":"))
    data = data.replace("</", "<\\/")
    return HTML_TEMPLATE.replace("__DATA__", data).replace("__TITLE__", html.escape("Agent Organogram"))


HTML_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f5f1;--panel:#fff;--ink:#1d1d1b;--muted:#6d6c66;--line:#dedcd4;--soft:#efede6;--accent:#2f6fde;--heat:255,87,87;
--development:#6f8fd8;--test:#d39a2c;--production:#2b9466;--suspended:#c9663b;--killed:#c4423a;--ended:#9a9993;--human:#7c55c0}
@media (prefers-color-scheme:dark){:root{--bg:#131312;--panel:#1d1d1b;--ink:#ecebe5;--muted:#9d9c95;--line:#36352f;--soft:#26251f;--accent:#7aa5f0}}
*{box-sizing:border-box}html,body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 system-ui,-apple-system,sans-serif}
header{padding:14px 18px 0;border-bottom:1px solid var(--line);background:var(--panel)}
.top{display:flex;flex-wrap:wrap;gap:12px 24px;align-items:baseline;justify-content:space-between}
h1{font-size:18px;margin:0}.muted{color:var(--muted)}
.kpis{display:flex;flex-wrap:wrap;gap:8px}.kpi{background:var(--soft);border-radius:8px;padding:4px 10px;font-size:13px}.kpi b{font-size:15px;margin-right:4px}
select,input{font:inherit;color:var(--ink);background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:5px 8px}
nav{display:flex;gap:2px;margin-top:10px;overflow-x:auto}nav button{border:0;background:none;color:var(--muted);padding:8px 12px;font:inherit;cursor:pointer;border-bottom:2px solid transparent;white-space:nowrap}
nav button.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:600}
main{display:grid;grid-template-columns:1fr 400px;min-height:calc(100vh - 100px)}
@media (max-width:900px){main{grid-template-columns:1fr}}
section{padding:18px;overflow:auto;min-width:0}section[hidden]{display:none}
aside{border-left:1px solid var(--line);background:var(--panel);padding:16px;overflow:auto;max-height:calc(100vh - 100px);position:sticky;top:0}
@media (max-width:900px){aside{border-left:0;border-top:1px solid var(--line);max-height:none;position:static}}
aside h2{font-size:16px;margin:0 0 2px}aside h3{font-size:13px;margin:16px 0 6px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
aside dl{margin:6px 0 0}aside dt{color:var(--muted);font-size:11.5px;margin-top:8px;text-transform:uppercase;letter-spacing:.03em}aside dd{margin:2px 0 0;word-break:break-word}
a,.link{color:var(--accent);cursor:pointer;text-decoration:none}
/* tree */
.tree{display:flex;width:max-content;min-width:100%;justify-content:center;margin:0 auto;padding-bottom:24px}
.roles{display:grid;grid-template-columns:repeat(var(--cols,3),210px);gap:10px;padding:12px;border:1px dashed var(--line);border-radius:12px;background:color-mix(in srgb,var(--panel) 55%,transparent)}
.roles-hd{grid-column:1/-1;font-size:12px;color:var(--muted)}
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
.card{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--line));border-radius:9px;padding:8px 12px;width:210px;text-align:left;cursor:pointer;font:inherit;color:inherit}
.card:hover,.card.sel{border-color:var(--accent);box-shadow:0 0 0 2px color-mix(in srgb,var(--accent) 22%,transparent)}
.card b{display:block;font-size:13px}.card small{display:block;color:var(--muted);font-size:11.5px;line-height:1.35}
.card.human{border-left-color:var(--human);cursor:default}.card.idle{opacity:.55}
.role{border-style:dashed;border-left-style:solid;--c:var(--accent)}
.stats{display:flex;flex-wrap:wrap;gap:4px;margin-top:5px}.st{font-size:11px;padding:1px 7px;border-radius:9px;background:var(--soft)}
.st.run{background:color-mix(in srgb,var(--production) 22%,transparent)}.st.bad{background:color-mix(in srgb,var(--killed) 22%,transparent)}
.pill{display:inline-block;font-size:11px;padding:1px 8px;border-radius:9px;background:color-mix(in srgb,var(--c) 20%,transparent)}
/* tables */
.bar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;cursor:pointer;white-space:nowrap;user-select:none}th.sorted::after{content:" ▾"}th.sorted.asc::after{content:" ▴"}
tr.click{cursor:pointer}tr.click:hover{background:color-mix(in srgb,var(--accent) 6%,transparent)}
td.num{text-align:right;font-variant-numeric:tabular-nums}code{font-size:12px}
.btn{border:1px solid var(--line);background:var(--panel);color:var(--ink);border-radius:7px;padding:5px 10px;font:inherit;cursor:pointer}
.btn:hover{border-color:var(--accent)}.btn.pri{background:var(--accent);border-color:var(--accent);color:#fff}
/* timeline */
.sess{border:1px solid var(--line);border-radius:10px;background:var(--panel);margin-bottom:14px;overflow:hidden}
.sess .hd{display:flex;flex-wrap:wrap;gap:6px 16px;padding:9px 12px;border-bottom:1px solid var(--line);background:var(--soft);font-size:13px}
.lanes{padding:8px 12px 12px}.lane{display:grid;grid-template-columns:150px 1fr;align-items:center;gap:8px;min-height:24px}
.lane .nm{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.track{position:relative;height:20px;background:repeating-linear-gradient(90deg,transparent 0 calc(10% - 1px),var(--line) calc(10% - 1px) 10%);border-radius:4px}
.blk{position:absolute;top:2px;height:10px;border-radius:3px;background:var(--c);opacity:.8;cursor:pointer;min-width:3px}
.blk.bad{outline:2px solid var(--killed);opacity:1}.blk.live{outline:2px solid var(--production);opacity:1}
.blk:hover,.blk.sel{opacity:1;outline:2px solid var(--ink)}
.axis{display:grid;grid-template-columns:150px 1fr;gap:8px;font-size:11px;color:var(--muted)}.axis div:last-child{display:flex;justify-content:space-between}
/* map */
.heat td.cell{text-align:center;cursor:pointer;min-width:62px;font-variant-numeric:tabular-nums}
.heat th.col{writing-mode:vertical-rl;transform:rotate(180deg);height:120px;vertical-align:bottom;text-align:left}
.lvl-ERROR{color:#cf3f35;font-weight:600}.lvl-WARNING{color:#b9801b;font-weight:600}
.talk{margin:12px 0 4px;padding:10px;border:1px solid var(--line);border-radius:8px}
.talk textarea{width:100%;min-height:62px;font:12px ui-monospace,monospace;background:var(--bg);color:var(--ink);border:1px solid var(--line);border-radius:6px;padding:6px}
.list div{padding:5px 0;border-bottom:1px solid var(--line);font-size:12.5px}
.legend{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 14px;font-size:12px;color:var(--muted)}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
</style></head>
<body>
<header><div class="top"><div><h1>Agent Organogram</h1><div class="muted" id="sub"></div></div>
<div class="kpis" id="kpis"></div>
<label class="muted">Period <select id="period"><option value="1">Last 24 hours</option><option value="7" selected>Last 7 days</option><option value="30">Last 30 days</option><option value="q">This quarter</option><option value="all">All time</option></select></label></div>
<nav id="nav"><button data-tab="org" class="on">Organogram</button><button data-tab="runs">Runs</button><button data-tab="time">Timeline</button><button data-tab="map">Where agents work</button><button data-tab="files">Files</button><button data-tab="cmd">Commands</button><button data-tab="fin">Findings</button></nav></header>
<main>
<section id="org"></section><section id="runs" hidden></section><section id="time" hidden></section><section id="map" hidden></section>
<section id="files" hidden></section><section id="cmd" hidden></section><section id="fin" hidden></section>
<aside id="side"><h2>Select something</h2><p class="muted">Click an agent or a role card for its passport and its runs. Click any run for the full trail: task, model, files with hashes, commands and result.</p></aside>
</main>
<script>
const D=__DATA__, P=D.persistent, R=D.runs, E=D.events, RD=D.reads||[], RT=D.read_totals||{};
const esc=s=>String(s??'-').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const fmt=v=>{if(v==null||v===''||(Array.isArray(v)&&!v.length))return '-';if(Array.isArray(v))return v.map(fmt).join(', ');if(typeof v==='object')return Object.entries(v).filter(([k,x])=>x!=null&&x!=='').map(([k,x])=>k+': '+fmt(x)).join('; ');return String(v)};
const ts=s=>s?new Date(s).getTime():NaN, hm=s=>s?String(s).replace('T',' ').slice(0,16):'-';
const dur=ms=>ms==null?'-':ms<60000?Math.round(ms/1000)+'s':Math.round(ms/60000)+'m';
const num=n=>n==null?'-':n>=1e6?(n/1e6).toFixed(1)+'M':n>=1e3?(n/1e3).toFixed(1)+'k':String(n);
const byId=Object.fromEntries(R.map(r=>[r.id,r]));
const nameOf=id=>P[id]?P[id].name:(byId[id]?byId[id].role:id);
const roleOfActor=id=>byId[id]?byId[id].role:(P[id]?(P[id].role==='chief'?'chief':P[id].name):String(id||'').startsWith('unresolved:')?'unlinked subagent':String(id||'unknown'));
const PALETTE=['#4e79a7','#f28e2b','#59a14f','#b07aa1','#76b7b2','#edc948','#9c755f','#e15759','#ff9da7','#86bcb6'],roleCols={};
const roleColor=r=>roleCols[r]||(roleCols[r]=PALETTE[Object.keys(roleCols).length%PALETTE.length]);
const statusCol=s=>`var(--${s||'ended'})`;
const runEnd=r=>{const e=ts(r.end);if(!isNaN(e))return e;const s=ts(r.start);return isNaN(s)?NaN:s+(r.ms||60000)};
// ---------- period
let since=0;
function setPeriod(v){const now=Date.now();if(v==='all')since=0;else if(v==='q'){const d=new Date();since=new Date(d.getFullYear(),Math.floor(d.getMonth()/3)*3,1).getTime()}else since=now-(+v)*864e5;render()}
const inP=t=>since===0||ts(t)>=since;
document.getElementById('period').onchange=e=>setPeriod(e.target.value);
// ---------- tabs
const tabs=[...document.querySelectorAll('nav button')];
function show(tab){tabs.forEach(b=>b.classList.toggle('on',b.dataset.tab===tab));document.querySelectorAll('main>section').forEach(s=>s.hidden=s.id!==tab)}
tabs.forEach(b=>b.onclick=()=>show(b.dataset.tab));
// ---------- organogram: structure only, runs folded into role cards
function rolesUnder(parent,runs){const g={};runs.filter(r=>r.parent===parent).forEach(r=>{(g[r.role]=g[r.role]||[]).push(r)});return g}
function roleStats(list){const s={n:list.length,run:0,bad:0,tok:0,last:0};list.forEach(r=>{if(r.status==='production')s.run++;if(r.status==='killed')s.bad++;s.tok+=r.tok||0;s.last=Math.max(s.last,ts(r.start)||0)});return s}
function agentCard(id,pr){const p=P[id],n=R.filter(r=>r.inst===id&&inP(r.start)).length;
return `<button class="card" style="--c:var(--${p.status})" data-agent="${id}"><b>${esc(p.name)}</b><small>${id} · ${esc(p.kind)}${p.role==='chief'?' · chief':''}</small><small>${esc((p.task&&p.task.purpose||'').slice(0,64))}</small><div class="stats"><span class="pill" style="--c:var(--${p.status})">${esc(p.status)}</span>${n?`<span class="st">${n} runs</span>`:''}</div></button>`}
function roleCard(parent,role,list){const s=roleStats(list.filter(r=>inP(r.start))),all=list.length;
return `<button class="card role${s.n?'':' idle'}" data-role="${esc(role)}" data-parent="${esc(parent)}"><b>${esc(role)}</b><small>subagent role · ${all} run${all>1?'s':''} in total</small><div class="stats"><span class="st">${s.n} in period</span>${s.run?`<span class="st run">${s.run} running</span>`:''}${s.bad?`<span class="st bad">${s.bad} stopped</span>`:''}${s.tok?`<span class="st">${num(s.tok)} tok</span>`:''}</div>${s.last?`<small>last ${hm(new Date(s.last).toISOString())}</small>`:''}</button>`}
function nodeHtml(id){const kids=Object.keys(P).filter(k=>P[k].reports_to===id&&k!==id);const roles=rolesUnder(id,R);
const rl=Object.entries(roles).sort((a,b)=>b[1].length-a[1].length);
// all subagent roles of one agent sit in one wrapping grid, so ten or twenty roles stay readable
const inner=kids.map(nodeHtml).join('')+(rl.length?`<li><div class="roles" style="--cols:${Math.min(3,rl.length)}"><div class="roles-hd">${rl.length} subagent role${rl.length>1?'s':''} · ${rl.reduce((t,[,l])=>t+l.length,0)} runs in total</div>${rl.map(([role,list])=>roleCard(id,role,list)).join('')}</div></li>`:'');
return `<li>${agentCard(id)}${inner?`<ul>${inner}</ul>`:''}</li>`}
function renderOrg(){const roots={};Object.keys(P).sort().forEach(id=>{const up=P[id].reports_to;if(!(typeof up==='string'&&P[up]))(roots[up||P[id].owner||'unassigned']=roots[up||P[id].owner||'unassigned']||[]).push(id)});
document.getElementById('org').innerHTML=`<div class="legend">${['development','test','production','suspended','killed','ended','human'].map(s=>`<span><i style="background:var(--${s})"></i>${s}</span>`).join('')}<span>· dashed cards = subagent roles (runs folded together)</span></div><div class="tree"><ul>${Object.entries(roots).map(([h,ids])=>`<li><div class="card human"><b>${esc(h)}</b><small>accountable human</small></div><ul>${ids.map(nodeHtml).join('')}</ul></li>`).join('')}</ul></div>`}
// ---------- runs table
const RS={q:'',role:'',status:'',session:'',sort:'start',asc:false,limit:100};
function filteredRuns(){const q=RS.q.toLowerCase();return R.filter(r=>inP(r.start)&&(!RS.role||r.role===RS.role)&&(!RS.status||r.status===RS.status)&&(!RS.session||r.session===RS.session)&&(!q||[r.id,r.task,r.role,r.result,r.model].join(' ').toLowerCase().includes(q)))}
const readsBy={};RD.forEach(r=>(readsBy[r.a]=readsBy[r.a]||[]).push(r));
const nFiles=a=>(readsBy[a]||[]).filter(z=>z.k==='f').length;
const filesBy={},cmdsBy={};E.forEach(e=>{(e.k==='f'?filesBy:cmdsBy)[e.a]=((e.k==='f'?filesBy:cmdsBy)[e.a]||[]).concat([e])});
function renderRuns(){const rows=filteredRuns(),k=RS.sort;rows.sort((a,b)=>{let x=a[k],y=b[k];if(k==='files'){x=(filesBy[a.id]||[]).length;y=(filesBy[b.id]||[]).length}if(k==='reads'){x=nFiles(a.id);y=nFiles(b.id)}if(k==='start'){x=ts(x);y=ts(y)}return (x>y?1:x<y?-1:0)*(RS.asc?1:-1)});
const roles=[...new Set(R.map(r=>r.role))].sort(),sess=[...new Set(R.filter(r=>inP(r.start)).map(r=>r.session))].filter(Boolean).sort().reverse();
const opt=(v,l,cur)=>`<option value="${esc(v)}"${v===cur?' selected':''}>${esc(l)}</option>`;
const col=(k,l,c='')=>`<th data-k="${k}" class="${c} ${RS.sort===k?'sorted'+(RS.asc?' asc':''):''}">${l}</th>`;
document.getElementById('runs').innerHTML=`<div class="bar"><input id="rq" placeholder="Search task, result, model…" value="${esc(RS.q)}" style="min-width:240px">
<select id="rrole">${opt('','All roles',RS.role)}${roles.map(r=>opt(r,r,RS.role)).join('')}</select>
<select id="rstat">${opt('','All statuses',RS.status)}${['production','ended','killed'].map(s=>opt(s,s==='production'?'running':s,RS.status)).join('')}</select>
<select id="rsess">${opt('','All sessions',RS.session)}${sess.map(s=>opt(s,s,RS.session)).join('')}</select>
<span class="muted">${rows.length} runs</span><button class="btn" id="csv">Export CSV</button></div>
<table><tr>${col('start','Started')}${col('id','Run')}${col('role','Role')}<th>Task</th>${col('session','Session')}${col('ms','Time','num')}${col('tok','Tokens','num')}${col('model','Model')}${col('files','Files','num')}${col('reads','Reads','num')}${col('status','Status')}</tr>
${rows.slice(0,RS.limit).map(r=>`<tr class="click" data-run="${r.id}"><td>${hm(r.start)}</td><td>${r.id}</td><td>${esc(r.role)}</td><td>${esc((r.task||'').slice(0,90))}</td><td><code>${esc(r.session)}</code></td><td class="num">${dur(r.ms)}</td><td class="num">${num(r.tok)}</td><td>${esc(r.model)}</td><td class="num">${(filesBy[r.id]||[]).length||''}</td><td class="num">${nFiles(r.id)||''}</td><td><span class="pill" style="--c:${statusCol(r.status)}">${r.status==='production'?'running':esc(r.status)}</span></td></tr>`).join('')}</table>
${rows.length>RS.limit?`<p><button class="btn" id="more">Show ${Math.min(100,rows.length-RS.limit)} more</button></p>`:''}`;
const $=id=>document.getElementById(id);
$('rq').oninput=e=>{RS.q=e.target.value;RS.limit=100;renderRuns();const i=$('rq');i.focus();i.setSelectionRange(i.value.length,i.value.length)};
$('rrole').onchange=e=>{RS.role=e.target.value;renderRuns()};$('rstat').onchange=e=>{RS.status=e.target.value;renderRuns()};$('rsess').onchange=e=>{RS.session=e.target.value;renderRuns()};
if($('more'))$('more').onclick=()=>{RS.limit+=100;renderRuns()};
document.querySelectorAll('#runs th[data-k]').forEach(th=>th.onclick=()=>{RS.asc=RS.sort===th.dataset.k?!RS.asc:false;RS.sort=th.dataset.k;renderRuns()});
$('csv').onclick=()=>{const head=['run','role','task','session','started','ended','duration_s','tokens','model','files_changed','files_read','commands','status','result'];
const q=v=>'"'+String(v??'').replace(/"/g,'""')+'"';const lines=[head.join(',')].concat(rows.map(r=>[r.id,r.role,r.task,r.session,r.start,r.end,r.ms!=null?Math.round(r.ms/1000):'',r.tok,r.model,(filesBy[r.id]||[]).map(e=>e.p).join(' | '),nFiles(r.id),(cmdsBy[r.id]||[]).length,r.status,r.result].map(q).join(',')));
const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([lines.join('\n')],{type:'text/csv'}));a.download=`agent-runs-${D.project}.csv`;a.click()}}
// ---------- timeline per session
let tlLimit=8;
function renderTimeline(){const ss={};R.filter(r=>inP(r.start)&&r.session).forEach(r=>(ss[r.session]=ss[r.session]||[]).push(r));
const list=Object.entries(ss).map(([s,rs])=>{const a=Math.min(...rs.map(r=>ts(r.start))),b=Math.max(...rs.map(runEnd));return {s,rs,a,b}}).sort((x,y)=>y.a-x.a);
document.getElementById('time').innerHTML=list.length?`<p class="muted">Each block is one work session. Bars are subagent runs on a shared time axis, one lane per role; runs that overlapped are stacked. Colour = role · <span style="outline:2px solid var(--killed);padding:0 4px;border-radius:3px">red outline</span> = stopped · <span style="outline:2px solid var(--production);padding:0 4px;border-radius:3px">green outline</span> = still running. Click a bar for the run.</p>`+list.slice(0,tlLimit).map(({s,rs,a,b})=>{
 const span=Math.max(b-a,60000),lanes={};rs.forEach(r=>(lanes[r.role]=lanes[r.role]||[]).push(r));
 const pts=[];rs.forEach(r=>{pts.push([ts(r.start),1]);pts.push([runEnd(r),-1])});pts.sort((x,y)=>x[0]-y[0]||x[1]-y[1]);let c=0,peak=0;pts.forEach(p=>{c+=p[1];peak=Math.max(peak,c)});
 const tok=rs.reduce((t,r)=>t+(r.tok||0),0);
 return `<div class="sess"><div class="hd"><b>Session ${esc(s)}</b><span>${hm(new Date(a).toISOString())} – ${hm(new Date(b).toISOString()).slice(11)}</span><span>${rs.length} runs</span><span>max ${peak} in parallel</span><span>${num(tok)} tokens</span><span>${Object.keys(lanes).length} roles</span></div><div class="lanes">
 ${Object.entries(lanes).sort((x,y)=>y[1].length-x[1].length).map(([role,l])=>{
   // pack overlapping runs of the same role into sub-rows so parallel work stays visible
   const rowsEnd=[];const placed=l.slice().sort((p,q)=>ts(p.start)-ts(q.start)).map(r=>{let i=rowsEnd.findIndex(e=>e<=ts(r.start));if(i<0){i=rowsEnd.length;rowsEnd.push(0)}rowsEnd[i]=runEnd(r);return [r,i]});
   const h=Math.max(1,rowsEnd.length)*12+4;
   return `<div class="lane"><div class="nm" title="${esc(role)}">${esc(role)} · ${l.length}</div><div class="track" style="height:${h}px">${placed.map(([r,i])=>{const x=(ts(r.start)-a)/span*100,w=Math.max((runEnd(r)-ts(r.start))/span*100,.4);
   return `<div class="blk${r.status==='killed'?' bad':r.status==='production'?' live':''}" data-run="${r.id}" style="left:${x}%;width:${w}%;top:${2+i*12}px;--c:${roleColor(role)}" title="${r.id} · ${esc(r.task)} · ${dur(r.ms)}${r.status==='killed'?' · stopped':''}"></div>`}).join('')}</div></div>`}).join('')}
 <div class="axis"><div></div><div><span>${hm(new Date(a).toISOString()).slice(11)}</span><span>${dur(span)} total</span><span>${hm(new Date(a+span).toISOString()).slice(11)}</span></div></div></div></div>`}).join('')+(list.length>tlLimit?`<button class="btn" id="tlmore">Show more sessions (${list.length-tlLimit})</button>`:''):'<p class="muted">No sessions with subagent runs in this period.</p>';
 const m=document.getElementById('tlmore');if(m)m.onclick=()=>{tlLimit+=8;renderTimeline()}}
// ---------- where agents work: cluster x role
function clusterOf(path){const g=D.graph[path];if(g&&g.c.length)return g.c[0];const parts=String(path).split('/');return parts.length>1?parts[0]+'/':'(project root)'}
function renderMap(){const cells={},rows={},cols={};E.filter(e=>e.k==='f'&&inP(e.t)).forEach(e=>{const cl=clusterOf(e.p),ro=roleOfActor(e.a);const k=cl+'\u0000'+ro;(cells[k]=cells[k]||[]).push(e);rows[cl]=(rows[cl]||0)+1;cols[ro]=(cols[ro]||0)+1});
const rk=Object.keys(rows).sort((a,b)=>rows[b]-rows[a]),ck=Object.keys(cols).sort((a,b)=>cols[b]-cols[a]);const mx=Math.max(1,...Object.values(cells).map(c=>c.length));
const src=D.graphify?`Rows are graphify clusters (read-only from ${esc(D.graphify.path)}, built ${hm(D.graphify.built_at)}); files outside the graph are grouped by folder.`:'No graphify graph in this project, so rows are top-level folders. Add graphify for clusters by meaning.';
document.getElementById('map').innerHTML=rk.length?`<p class="muted">Which parts of the project each agent role changed in this period. ${src} Click a cell for the files.</p><table class="heat"><tr><th>Cluster / area</th>${ck.map(c=>`<th class="col">${esc(c)}</th>`).join('')}<th>Total</th></tr>
${rk.map(r=>`<tr><td>${esc(r)}</td>${ck.map(c=>{const l=cells[r+'\u0000'+c]||[];const a=l.length/mx;return `<td class="cell" ${l.length?`data-cell="${esc(r)}\u0000${esc(c)}"`:''} style="background:rgba(var(--heat),${l.length?.12+a*.6:0})">${l.length||''}</td>`}).join('')}<td class="num"><b>${rows[r]}</b></td></tr>`).join('')}</table>`:'<p class="muted">No file changes in this period.</p>';
document.querySelectorAll('#map [data-cell]').forEach(td=>td.onclick=()=>{const [r,c]=td.dataset.cell.split('\u0000');const l=cells[r+'\u0000'+c]||[];
side(`<h2>${esc(r)}</h2><div class="muted">changed by ${esc(c)} · ${l.length} change${l.length>1?'s':''}</div><div class="list">${l.slice().reverse().map(e=>`<div>${hm(e.t)} · <span class="link" data-file="${esc(e.p)}">${esc(e.p)}</span> · <span class="link" data-runlink="${esc(e.a)}">${esc(e.a)}</span></div>`).join('')}</div>`)})}
// ---------- files, commands, findings
let FM='changed';
function renderFiles(){
const bar=`<div class="bar"><button class="btn${FM==='changed'?' pri':''}" data-fm="changed">Changed</button><button class="btn${FM==='read'?' pri':''}" data-fm="read">Read</button></div>`;let body;
if(FM==='read'){const f={};RD.filter(r=>r.k==='f'&&inP(r.t)).forEach(r=>(f[r.p]=f[r.p]||[]).push(r));
const lastOf=rs=>rs.map(r=>r.t).sort().at(-1);
const l=Object.entries(f).sort((a,b)=>(b[1].some(r=>r.s)-a[1].some(r=>r.s))||(ts(lastOf(b[1]))-ts(lastOf(a[1]))));
body=l.length?`<p class="muted">Files agents read in this period. Each agent is counted once per session; sensitive paths (from sensitive-paths.txt and built-in patterns) are listed first and always logged. Reads through the shell are not seen.</p><table><tr><th>File</th><th>Cluster / area</th><th>Agents</th><th>Reads</th><th>Last read</th></tr>${l.map(([p,rs])=>{const sens=rs.find(r=>r.s);return `<tr class="click" data-file="${esc(p)}"><td>${esc(p)}${sens?' <span class="lvl-WARNING">⚠ sensitive</span>':''}</td><td>${esc(clusterOf(p))}</td><td class="num">${new Set(rs.map(r=>r.a)).size}</td><td class="num">${rs.reduce((t,r)=>t+(r.n||1),0)}</td><td>${hm(lastOf(rs))}</td></tr>`}).join('')}</table>`:'<p class="muted">No reads recorded in this period.</p>'}
else{const f={};E.filter(e=>e.k==='f'&&inP(e.t)).forEach(e=>(f[e.p]=f[e.p]||[]).push(e));const l=Object.entries(f).sort((a,b)=>ts(b[1].at(-1).t)-ts(a[1].at(-1).t));
body=l.length?`<p class="muted">Every file an agent changed in this period, newest first. Click a row for its trail.</p><table><tr><th>File</th><th>Cluster / area</th><th>Changes</th><th>Last change</th><th>Last by</th></tr>${l.map(([p,es])=>{const x=es.at(-1);return `<tr class="click" data-file="${esc(p)}"><td>${esc(p)}${es.some(e=>e.flag)?' ⚠':''}</td><td>${esc(clusterOf(p))}</td><td class="num">${es.length}</td><td>${hm(x.t)}</td><td>${esc(x.a)} ${esc(nameOf(x.a))}</td></tr>`}).join('')}</table>`:'<p class="muted">No file changes in this period.</p>'}
document.getElementById('files').innerHTML=bar+body;
document.querySelectorAll('#files [data-fm]').forEach(b=>b.onclick=()=>{FM=b.dataset.fm;renderFiles()})}
function renderCmds(){const c=E.filter(e=>e.k==='c'&&inP(e.t)).slice(-500).reverse();
document.getElementById('cmd').innerHTML=c.length?`<p class="muted">Shell commands and external (MCP) actions by agents, secrets redacted, newest first${c.length===500?' (latest 500)':''}.</p><table><tr><th>When</th><th>Agent</th><th>Command / action</th><th>Failed</th></tr>${c.map(e=>`<tr class="click" data-runlink="${esc(e.a)}"><td>${hm(e.t)}</td><td>${esc(e.a)} ${esc(nameOf(e.a))}</td><td><code>${esc(e.p)}</code></td><td>${e.fail?'<span class="lvl-ERROR">yes</span>':e.fail===false?'no':'-'}</td></tr>`).join('')}</table>`:'<p class="muted">No commands in this period.</p>'}
function renderFindings(){document.getElementById('fin').innerHTML=D.findings.length?`<table><tr><th>Level</th><th>Agent</th><th>Rule</th><th>Message</th></tr>${D.findings.map(f=>`<tr class="click" data-runlink="${esc(f.agent_id)}"><td class="lvl-${f.level}">${f.level}</td><td>${esc(f.agent_id)}</td><td>${esc(f.rule)}</td><td>${esc(f.message)}</td></tr>`).join('')}</table>`:'<p>No findings. All passports valid.</p>'}
// ---------- side panel
function side(h){document.getElementById('side').innerHTML=h}
function dl(rows){return `<dl>${rows.filter(([k,v])=>v!=null&&v!==''&&!(Array.isArray(v)&&!v.length)).map(([k,v])=>`<dt>${k}</dt><dd>${typeof v==='string'&&v.startsWith('<')?v:esc(fmt(v))}</dd>`).join('')}</dl>`}
function talkBox(text,why){return `<div class="talk"><b>Talk to this agent</b>${text?`<textarea id="msg">${esc(text)}</textarea><button class="btn pri" id="cp">Copy message</button> <span class="muted" id="cpok"></span>`:`<p class="muted">${esc(why)}</p>`}</div>`}
function bindCopy(){const cp=document.getElementById('cp');if(cp)cp.onclick=async()=>{const t=document.getElementById('msg');try{await navigator.clipboard.writeText(t.value)}catch(e){t.select();document.execCommand('copy')}document.getElementById('cpok').textContent='Copied'}}
function showRun(id){const r=byId[id];if(!r)return showAgent(id);const fs=filesBy[id]||[],cs=cmdsBy[id]||[],rs=readsBy[id]||[],rf=rs.filter(z=>z.k==='f'),ro=rs.filter(z=>z.k!=='f');
document.querySelectorAll('.blk.sel').forEach(b=>b.classList.remove('sel'));document.querySelectorAll(`.blk[data-run="${id}"]`).forEach(b=>b.classList.add('sel'));
side(`<h2>${esc(r.id)} · ${esc(r.role)}</h2><div><span class="pill" style="--c:${statusCol(r.status)}">${r.status==='production'?'running':esc(r.status)}</span> <span class="muted">session ${esc(r.session)}${r.auto?' · auto-registered':''}</span></div>
${r.inv&&r.agent?talkBox(`Continue subagent ${r.agent} (passport ${r.id}, "${r.task}") with SendMessage: `):''}
${dl([['Task',r.task],['Prompt (excerpt)',r.prompt],['Instance of',r.inst?`<span class="link" data-agentlink="${esc(r.inst)}">${esc(r.inst)} ${esc(nameOf(r.inst))}</span>`:null],['Reports to',r.parent?`<span class="link" data-agentlink="${esc(r.parent)}">${esc(r.parent)} ${esc(nameOf(r.parent))}</span>`:null],['Owner (human)',r.owner],['Model',r.model],['Started / ended',hm(r.start)+' → '+hm(r.end)],['Duration · tokens',dur(r.ms)+' · '+num(r.tok)],['Tools',r.tools],['Data',r.data],['Result',r.result],['Transcript',r.transcript]])}
<h3>Files changed (${fs.length})</h3><div class="list">${fs.map(e=>`<div><span class="link" data-file="${esc(e.p)}">${esc(e.p)}</span>${e.flag?' ⚠ '+esc(e.flag):''}<br><span class="muted">${hm(e.t)} · ${esc(e.tool)} · sha ${esc(e.sha)} · ${esc(clusterOf(e.p))}</span></div>`).join('')||'<div class="muted">none</div>'}</div>
<h3>Files read (${rf.length}${RT[id]?' · '+RT[id].t+' reads in total':''})</h3><div class="list">${rf.slice(0,40).map(z=>`<div><span class="link" data-file="${esc(z.p)}">${esc(z.p)}</span>${z.s?' <span class="lvl-WARNING">⚠ sensitive ('+esc(z.pt)+')</span>':''}${z.n>1?' ×'+z.n:''}<br><span class="muted">${hm(z.t)} · ${esc(z.x)} · ${esc(clusterOf(z.p))}</span></div>`).join('')||'<div class="muted">none recorded</div>'}${rf.length>40?`<div class="muted">+ ${rf.length-40} more</div>`:''}</div>
<h3>Searches & web (${ro.length})</h3><div class="list">${ro.slice(0,20).map(z=>`<div><code>${esc(z.p)}</code><br><span class="muted">${hm(z.t)} · ${esc(z.x)}</span></div>`).join('')||'<div class="muted">none recorded</div>'}</div>
<h3>Commands & actions (${cs.length})</h3><div class="list">${cs.map(e=>`<div><code>${esc(e.p)}</code><br><span class="muted">${hm(e.t)} · ${esc(e.tool)}${e.fail?' · failed':''}</span></div>`).join('')||'<div class="muted">none</div>'}</div>
<p class="muted" style="font-size:12px">CLI: python agent-passports/passport.py report --session ${esc(r.session)}</p>`);bindCopy()}
function talkFor(p,id){if(!p.invocable||['suspended','killed','ended'].includes(p.status))return [null,'Status is '+p.status+'; it cannot be invoked.'];
if(p.role==='chief')return ['Report who did what today: python agent-passports/passport.py report --since today --summary'];
if(p.platform==='claude-code')return [`Use the ${p.name} subagent (passport ${id}) to: `];return [`${p.how_to_invoke||'See passport'}\nTask for ${p.name} (${id}): `]}
function showAgent(id){const p=P[id];if(!p){if(byId[id])return showRun(id);return}document.querySelectorAll('.card.sel').forEach(c=>c.classList.remove('sel'));document.querySelectorAll(`.card[data-agent="${id}"]`).forEach(c=>c.classList.add('sel'));
const inst=R.filter(r=>r.inst===id&&inP(r.start)),fin=D.findings.filter(f=>f.agent_id===id),[t,why]=talkFor(p,id);
side(`<h2>${esc(p.name)}</h2><div class="muted">${id} · ${esc(p.kind)}${p.role==='chief'?' · chief':''}${p.auto_registered?' · auto-registered':''}</div>${fin.map(f=>`<p class="lvl-${f.level}" style="font-size:12.5px;margin:6px 0">${f.level}: ${esc(f.message)}</p>`).join('')}
${talkBox(t,why)}${inst.length?`<p><span class="link" data-rolelink="${esc(p.name)}">${inst.length} runs of this agent in the period →</span></p>`:''}
${dl([['Status',p.status],['Owner (human)',p.owner],['Reports to',p.reports_to],['Talks to',p.talks_to],['Task',p.task&&p.task.purpose],['Human in the loop',p.task&&p.task.human_in_the_loop],['Model',p.model],['Data',p.data_dependencies],['Permissions',p.permissions],['Who may invoke',p.access&&p.access.who_can_invoke],['How to invoke',p.how_to_invoke],['Kill switch',p.risk&&p.risk.kill_switch],['Review',p.review],['Created / updated',p.created_at+' / '+p.updated_at],['Last changes',(p.changelog||[]).slice(-4).map(c=>c.date+' '+c.change).join(' | ')]])}`);bindCopy()}
function showRole(role,parent){const list=R.filter(r=>r.role===role&&(!parent||r.parent===parent)),inp=list.filter(r=>inP(r.start)).sort((a,b)=>ts(b.start)-ts(a.start)),s=roleStats(inp);
const models=[...new Set(inp.map(r=>r.model).filter(Boolean))],avg=inp.filter(r=>r.ms).reduce((t,r)=>t+r.ms,0)/(inp.filter(r=>r.ms).length||1);const inst=list.find(r=>r.inst);
side(`<h2>${esc(role)}</h2><div class="muted">subagent role · reports to ${esc(parent||'-')} ${esc(nameOf(parent))}</div>
${dl([['In period',`${s.n} runs · ${s.run} running · ${s.bad} stopped`],['All time',list.length+' runs'],['Average duration',inp.length?dur(avg):'-'],['Tokens in period',num(s.tok)],['Models used',models],['Instance of',inst?`<span class="link" data-agentlink="${esc(inst.inst)}">${esc(inst.inst)} ${esc(nameOf(inst.inst))}</span>`:'no persistent passport (ad-hoc type)'],['Tools',inp[0]&&inp[0].tools]])}
<h3>Latest runs</h3><div class="list">${inp.slice(0,30).map(r=>`<div class="link" data-runlink="${r.id}">${hm(r.start)} · ${r.id} · ${esc((r.task||'').slice(0,70))} <span class="muted">· ${r.status==='production'?'running':esc(r.status)}</span></div>`).join('')||'<div class="muted">No runs in this period.</div>'}</div>
${inp.length>30?`<p><button class="btn" data-rolelink="${esc(role)}">All ${inp.length} in the Runs table →</button></p>`:''}`)}
function showFile(path){const es=E.filter(e=>e.k==='f'&&e.p===path),g=D.graph[path],rd=RD.filter(r=>r.k==='f'&&r.p===path);
side(`<h2>${esc(path)}</h2><div class="muted">file trail</div>${dl([['Cluster / area',clusterOf(path)],['Graph nodes',g&&g.n],['Connected files (graph)',g&&g.r.length?g.r.map(x=>`<span class="link" data-file="${esc(x)}">${esc(x)}</span>`).join(', '):null]])}
<h3>Changes (${es.length})</h3><div class="list">${es.slice().reverse().map(e=>`<div><span class="link" data-runlink="${esc(e.a)}">${esc(e.a)} ${esc(nameOf(e.a))}</span>${e.flag?' ⚠ '+esc(e.flag):''}<br><span class="muted">${hm(e.t)} · ${esc(e.tool)} · sha ${esc(e.sha)}</span></div>`).join('')}</div>
<h3>Read by (${rd.length})</h3><div class="list">${rd.slice().reverse().map(r=>`<div><span class="link" data-runlink="${esc(r.a)}">${esc(r.a)} ${esc(nameOf(r.a))}</span>${r.s?' <span class="lvl-WARNING">⚠ sensitive ('+esc(r.pt)+')</span>':''}${r.n>1?' ×'+r.n:''}<br><span class="muted">${hm(r.t)} · ${esc(r.x)}</span></div>`).join('')||'<div class="muted">no reads recorded</div>'}</div>
<p class="muted" style="font-size:12px">CLI: python agent-passports/passport.py trace "${esc(path)}"</p>`)}
document.addEventListener('click',e=>{const t=e.target.closest('[data-run],[data-runlink],[data-agent],[data-agentlink],[data-role],[data-rolelink],[data-file]');if(!t)return;
if(t.dataset.file!=null){e.preventDefault();return showFile(t.dataset.file)}
if(t.dataset.rolelink!=null){RS.role=t.dataset.rolelink;RS.limit=100;renderRuns();show('runs');return}
if(t.dataset.role!=null){document.querySelectorAll('.card.sel').forEach(c=>c.classList.remove('sel'));t.classList.add('sel');return showRole(t.dataset.role,t.dataset.parent)}
const id=t.dataset.run||t.dataset.runlink||t.dataset.agent||t.dataset.agentlink;if(byId[id])showRun(id);else showAgent(id)});
// ---------- header + render all
function render(){const inp=R.filter(r=>inP(r.start)),roles=new Set(inp.map(r=>r.role)),tok=inp.reduce((t,r)=>t+(r.tok||0),0),files=new Set(E.filter(e=>e.k==='f'&&inP(e.t)).map(e=>e.p));
document.getElementById('sub').textContent=`${D.project} · generated ${hm(D.generated_at)} · ${D.summary.errors} errors · ${D.summary.warnings} warnings`;
document.getElementById('kpis').innerHTML=[[Object.keys(P).length,'agents'],[roles.size,'active roles'],[inp.length,'runs'],[inp.filter(r=>r.status==='production').length,'running'],[num(tok),'tokens'],[files.size,'files changed']].concat(RD.some(r=>r.s&&inP(r.t))?[[RD.filter(r=>r.s&&inP(r.t)).length,'sensitive reads']]:[]).map(([n,l])=>`<span class="kpi"><b>${n}</b>${l}</span>`).join('');
renderOrg();renderRuns();renderTimeline();renderMap();renderFiles();renderCmds();renderFindings()}
setPeriod('7');
const chief=Object.keys(P).find(i=>P[i].role==='chief');if(chief)showAgent(chief);
// deep links: #runs #time #map #files #cmd #fin #org, #AGT-0004, #role=name, #file=path, #all (period)
function route(){const h=decodeURIComponent(location.hash.slice(1));if(!h)return;if(h==='all'){document.getElementById('period').value='all';return setPeriod('all')}
const tab=tabs.find(b=>b.dataset.tab===h);if(tab)return show(h);
if(h.startsWith('file=')){show('files');return showFile(h.slice(5))}if(h.startsWith('role=')){return showRole(h.slice(5))}
if(byId[h]){show('runs');return showRun(h)}if(P[h])showAgent(h)}
window.addEventListener('hashchange',route);route();
</script></body></html>
"""


SENSITIVE_TEMPLATE = """# Paths an agent should not touch without saying so in its passport.
# One pattern per line (* matches anything, a trailing / means a whole folder). Lines starting with # are comments.
# Reads of matching paths are always logged and flagged. Built in already: .env*, *.pem, *.key, id_rsa*, *secret*, *credentials*
# Add your own, for example:
# customers/
# data/exports/*.csv
# patient*
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
    p.add_argument("--global", dest="global_", action="store_true",
                   help="user level: every project gets agent-passports/ on its first agent activity")
    p.add_argument("--remove", action="store_true", help="remove the agent-passport hooks again")
    p.add_argument("--python", help="interpreter used by the hook (default: python/python3 per project, "
                                    "this interpreter's full path for --global)")
    p.set_defaults(fn=cmd_install_hooks)

    p = sub.add_parser("hook")
    p.add_argument("--global-hook", action="store_true", help=argparse.SUPPRESS)
    p.set_defaults(fn=cmd_hook)

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
    p.add_argument("--summary", action="store_true", help="totals per role only (short, cheap to read)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_report)

    sub.add_parser("build").set_defaults(fn=cmd_build)

    p = sub.add_parser("trace", help="who changed a file, folder or graphify cluster")
    p.add_argument("query", help="file path, folder, or graphify cluster/node name (substring)")
    p.add_argument("--since", help="YYYY-MM-DD")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_trace)

    p = sub.add_parser("verify", help="check the audit log's hash chain against all known anchors")
    p.add_argument("--anchors", nargs="*", help="extra anchor files (e.g. a copy kept outside the project)")
    p.add_argument("--head", nargs="*", help="COUNT:HASH from a record you trust (repeatable)")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("anchor", help="record the log's current head (and send it out if configured)")
    p.add_argument("--reason")
    p.add_argument("--by")
    p.set_defaults(fn=cmd_anchor)

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
