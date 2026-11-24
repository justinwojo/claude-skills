"""The decision log and the unknown-command log: the loggable input of a call
(what each tool's record shows, truncated), secret redaction for full-input
capture, the owner-only append with locked single-generation rotation, and
log_decision, which writes one record from what the hook call's state holds
(passed in; this module keeps no per-call state). A test that turns the log
off or points it elsewhere rebinds the DECISION_LOG_* names here."""
import json
import os
import re
from datetime import datetime

from .config import (
    DECISION_LOG_ENABLED, DECISION_LOG_FLAGGED_INPUT_CHARS, DECISION_LOG_FULL_INPUT,
    DECISION_LOG_FULL_INPUT_CHARS, DECISION_LOG_INPUT_CHARS, DECISION_LOG_MAX_BYTES, DECISION_LOG_PATH,
    HOOK_VERSION, UNKNOWN_LOG,
)


def log_unknown(kind, name):
    """Append an unknown tool or command to the review log."""
    try:
        os.makedirs(os.path.dirname(UNKNOWN_LOG), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(UNKNOWN_LOG, "a") as f:
            f.write(f"{ts}  {kind:8s}  {name}\n")
    except OSError:
        pass  # Don't block on logging failures


def _decision_log_input(tool, tool_input, limit=DECISION_LOG_INPUT_CHARS, redact=False):
    """Extract the human-meaningful input string for a tool, truncated to
    `limit` chars (None: whole).

    Bash → command, file tools → path, WebFetch → url, search tools →
    pattern, an MCP tool → its `command` (and `cwd`) when it has one, else
    its input as compact JSON; else the tool name. `redact`: secrets taken
    out (_redact_secrets; in JSON, each value, see _redact_values, so it
    stays valid JSON). Only tool inputs are ever logged (never API keys).
    """
    json_input = False
    if tool == "Bash":
        val = tool_input.get("command", "")
    elif tool in ("Write", "Edit", "NotebookEdit", "Read"):
        val = tool_input.get("file_path", "") or tool_input.get("notebook_path", "") or tool
    elif tool == "WebFetch":
        val = tool_input.get("url", "")
    elif tool in ("Grep", "Glob"):
        val = tool_input.get("pattern", "") or tool_input.get("target_directory", "") or tool
    elif isinstance(tool, str) and tool.startswith("mcp__") and tool_input:
        command, cwd = tool_input.get("command"), tool_input.get("cwd")
        if isinstance(command, str) and command:
            val = command + (f"  (cwd: {cwd})" if isinstance(cwd, str) and cwd else "")
        else:
            try:
                val = json.dumps(_redact_values(tool_input) if redact else tool_input,
                                 separators=(",", ":"), ensure_ascii=False, default=str)
                json_input = True
            except (TypeError, ValueError):
                val = tool if redact else str(tool_input)
    else:
        val = tool
    if not isinstance(val, str):
        val = str(val)
    if redact and not json_input:
        val = _redact_secrets(val)[0]
    return val if limit is None else val[:limit]


# What a name that holds a credential contains: a NAME_KEY=… value, and an
# MCP input's field (_redact_values, which adds the header names).
_CREDENTIAL_NAME = r"key|secret|token|passw(?:or)?d|pwd|credential"

# Secrets a full-capture record leaves out: private key blocks, bearer and
# basic auth headers, URL credentials, well-known token shapes, and the
# value of a NAME_KEY/SECRET/TOKEN/PASSWORD=… assignment or --password … flag
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
    re.compile(r"(?i)(\b(?:authorization|proxy-authorization|x-api-key|private-token|api-key)\s*:\s*)"
               r"(?:(?:bearer|basic|token)\s+)?[^\s'\"]+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?<=://)[^/\s:@'\"]+:[^/\s@'\"]+(?=@)"),
    re.compile(r"\b(?:sk-(?:ant-)?[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_\w{20,}"
               r"|glpat-[\w-]{16,}|xox[abposr]-[\w-]{10,}|AKIA[0-9A-Z]{16}|AIza[\w-]{30,}"
               r"|eyJ[\w-]{10,}\.[\w-]{10,}\.[\w-]{10,})"),
    # a name starts where a run of [\w.-] starts (one try per run, not per
    # position: linear on long dotted text)
    re.compile(r"(?i)((?<![\w.-])(?=[\w.-]*(?:" + _CREDENTIAL_NAME + r"))[\w.-]+"
               r"[\"']?\s*[=:]\s*)(?![\"']?\$)(\"(?:[^\"\\]|\\[\s\S])*\"?|'(?:[^'\\]|\\[\s\S])*'?|[^\s'\";&|]+)"),
    re.compile(r"(?i)(--?(?:password|passwd|token|secret|api-key|client-secret|key)(?:=|\s+))"
               r"(?![\"']?\$)(\"(?:[^\"\\]|\\[\s\S])*\"?|'(?:[^'\\]|\\[\s\S])*'?|[^\s'\";&|]+)"),
]


_SECRET_KEY_RE = re.compile(r"(?i)" + _CREDENTIAL_NAME + r"|authorization|cookie")


def _redact_values(value):
    """`value` (JSON-like) with each string in it passed through
    _redact_secrets, and a field named like a credential redacted whole."""
    if isinstance(value, dict):
        return {k: "[REDACTED]" if isinstance(k, str) and _SECRET_KEY_RE.search(k)
                else _redact_values(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_values(v) for v in value]
    return _redact_secrets(value)[0] if isinstance(value, str) else value


def _redact_secrets(text):
    """(text with obvious secrets replaced by [REDACTED], whether any was)."""
    count = 0
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            text, n = pattern.subn(lambda m: m.group(1) + "[REDACTED]", text)
        else:
            text, n = pattern.subn("[REDACTED]", text)
        count += n
    return text, bool(count)


def _append_log_line(path, line, max_bytes):
    """Append `line` to `path`, created owner-only (0600; an existing file
    that is group- or world-readable is narrowed), after rotating it to a
    single `.1` generation once it passes `max_bytes`. The rotation runs
    under an exclusive lock on `path.lock` and checks the size again inside
    it, so when both hooks pass the limit at once, only one rotates and the
    other doesn't move the new, short file over the generation just made.
    Where locks aren't available (Windows), the lock is skipped."""
    try:
        if os.path.getsize(path) > max_bytes:
            lock = None
            try:
                import fcntl
                lock = os.open(path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:
                pass
            except OSError:
                if lock is not None:
                    os.close(lock)
                lock = -1  # the other hook is rotating it
            if lock != -1:
                try:
                    if os.path.getsize(path) > max_bytes:
                        os.replace(path, path + ".1")
                        os.chmod(path + ".1", 0o600)  # a log from before 1.6.0 may be 0644
                finally:
                    if lock is not None:
                        os.close(lock)  # releases the lock
    except OSError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        if hasattr(os, "fchmod") and os.fstat(fd).st_mode & 0o077:
            os.fchmod(fd, 0o600)
        os.write(fd, line.encode("utf-8", "replace"))
    finally:
        os.close(fd)


def _loggable_reason(reason, script_texts):
    """`reason` for the decision log. When the judge was shown script
    contents (`script_texts`, see CallState), its own words may echo them, so
    only its category numbers are kept: script text never reaches the log."""
    if not (script_texts and isinstance(reason, str) and reason.startswith("LLM")) \
            or reason == "LLM approved":
        return reason
    cats = sorted(set(re.findall(r"category ([1-9])(?!\d)", reason)))  # the prompt's 1-9, not free text
    return ("LLM verdict; its words are not logged, as it was shown script contents"
            + (f" (category {', '.join(cats)})" if cats else ""))


def log_decision(hook, tool, tool_input, decision, source, reason,
                 duration_ms=None, llm_ms=None, rule_reason=None, hold=None, *, state):
    """Append one JSONL record describing a permission decision.

    Best-effort: never raises, never blocks the hook (blanket guard like
    log_unknown). The `input` field holds the tool input truncated to 500
    chars for an allow and 8000 for an ask or deny — it may embed secrets,
    so the log is the same trust class as shell history (see README privacy
    note). Rotates at 20 MB to a single `.1` generation. `source` is one of
    rule|llm|llm-recheck|llm-hold|hold-retry|learner|prompt-timeout (older logs also hold
    llm-cache, from the cache since removed). `provenance`
    (found|none|unavailable) is there when the judge was asked about a delete
    or reset it could name, here or on another machine (remote_provenance). `hold` says what a hold did: held, cleared,
    asked (flagged again), no-answer, retry-busy, or why a flag was not held;
    prompt-timeout on the learner's deny of a prompt nobody answered.
    `state` is the hook call's (see CallState): its client tool name, the
    provenance and the script texts the judge was shown.
    """
    if not DECISION_LOG_ENABLED:
        return
    try:
        limit = DECISION_LOG_FLAGGED_INPUT_CHARS if decision in ("ask", "deny") else DECISION_LOG_INPUT_CHARS
        if DECISION_LOG_FULL_INPUT:
            limit = DECISION_LOG_FULL_INPUT_CHARS
        full = _decision_log_input(tool, tool_input, None)
        shown, redacted = full, False
        if DECISION_LOG_FULL_INPUT:  # before the cut, so a secret cut short is still found
            shown = _decision_log_input(tool, tool_input, None, redact=True)
            redacted = shown != full
        logged = shown[:limit]
        record = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "v": HOOK_VERSION,
            "hook": hook,
            "tool": tool,
            "input": logged,
            "input_len": len(full),
            "truncated": len(shown) > limit,
            "decision": decision,
            "source": source,
            "reason": _loggable_reason(reason, state.script_texts),
        }
        if DECISION_LOG_FULL_INPUT:
            record["redacted"] = redacted
            record["incomplete"] = redacted or record["truncated"]
            if isinstance(record["reason"], str):
                record["reason"] = _redact_secrets(record["reason"])[0]
            if isinstance(rule_reason, str):
                rule_reason = _redact_secrets(rule_reason)[0]
        if duration_ms is not None:
            record["duration_ms"] = duration_ms
        if llm_ms is not None:
            record["llm_ms"] = llm_ms
        # Why the rules punted to the LLM — the LLM's own reason replaces it.
        # The learner keeps it on every record (its reason may be the same).
        if rule_reason and (rule_reason != reason or hook == "permission_request"):
            record["rule_reason"] = rule_reason
        if state.client_tool:
            record["client_tool"] = state.client_tool
        if hold:
            record["hold"] = hold
        # Whether the judge saw session provenance for a delete or reset
        # (see build_llm_context), so its effect on verdicts can be measured.
        if state.provenance:
            record["provenance"] = state.provenance
        os.makedirs(os.path.dirname(DECISION_LOG_PATH), exist_ok=True)
        _append_log_line(DECISION_LOG_PATH, json.dumps(record) + "\n", DECISION_LOG_MAX_BYTES)
    except Exception:
        pass  # Never block on logging failures
