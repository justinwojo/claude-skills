#!/usr/bin/env python3
"""
Claude Code PreToolUse hook — smart permission auto-approval.

Handles compound commands, path-based scripts, env-var prefixes,
and /tmp access that the built-in Bash(cmd:*) patterns can't express.

Decision flow:
  1. This hook runs first (PreToolUse)
  2. If "allow" → execute immediately, skip all permission checks
  3. If "deny"  → block the action
  4. If "ask"   → fall through to built-in Bash(cmd:*) rules
  5. If built-in rules don't match → user prompt (or LLM eval if configured)

Configuration:
  - Defaults loaded from config/defaults.json (ships with plugin)
  - User overrides from ~/.claude/smart-permissions-config.json (optional)
  - LLM fallback via env vars: SAFETY_HOOK_API_URL, SAFETY_HOOK_API_KEY,
    SAFETY_HOOK_MODEL (supports any OpenAI-compatible API).
    Optional: SAFETY_HOOK_REASONING_EFFORT (e.g. "none", "low") — only sent
    if set; otherwise the provider default applies.
"""

import sys
import json
import os
import re
import shlex
import time
import hashlib
from fnmatch import fnmatch
from datetime import datetime
import urllib.request
import urllib.error
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION LOADING
# ============================================================

# Resolve paths relative to this script's location
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PLUGIN_ROOT = os.path.dirname(SCRIPT_DIR)
HOME_DIR = os.path.expanduser("~")

DEFAULTS_PATH = os.environ.get(
    "SMART_PERMISSIONS_DEFAULTS",
    os.path.join(PLUGIN_ROOT, "config", "defaults.json"),
)
USER_CONFIG_PATH = os.environ.get(
    "SMART_PERMISSIONS_CONFIG",
    os.path.join(HOME_DIR, ".claude", "smart-permissions-config.json"),
)
UNKNOWN_LOG = os.path.join(HOME_DIR, ".claude", "hooks", "unknown-permissions.log")


# User-config keys from which remove_from_defaults may subtract. Restricted
# to positive allowlists — deny/prompt lists (dangerous_patterns,
# risky_patterns, sensitive_paths, always_ask_write_paths) are NOT
# subtractable so user config can never weaken a safety control.
SUBTRACTABLE_KEYS = frozenset({
    "safe_commands", "safe_write_paths", "safe_script_paths",
    "allowed_web_domains", "safe_mcp_tools", "safe_internal_tools",
})

# H6: safety-critical config keys and the container type each REQUIRES. The
# merge below unions list∪list but otherwise REPLACES — so a wrong-type
# user/agent value (e.g. {"dangerous_patterns": {}}) would silently gut a
# safety list (empty deny list → `sudo` downgrades deny→ask; empty
# interpreter_exec_flags → `python -c` slips to allow). Type-guard the merge:
# a value whose type doesn't match its key's expected container is IGNORED
# (defaults kept) with a stderr warning — config can only ADD to a safety
# control, never erase it. This also subsumes the old non-list import crash.
_SAFETY_LIST_KEYS = frozenset({
    "dangerous_patterns", "risky_patterns", "sensitive_paths",
    "always_ask_write_paths", "never_learn_commands", "safe_internal_tools",
    "safe_commands", "safe_write_paths", "safe_script_paths",
    "allowed_web_domains", "safe_mcp_tools",
})
_SAFETY_DICT_KEYS = frozenset({"interpreter_exec_flags"})


def load_config():
    """Load defaults and merge user overrides.

    Arrays are merged (union) so user additions extend defaults.
    Scalar values and objects are replaced by user overrides.
    Entries starting with '__ ' are section comments — stripped before use.

    Returns (config, defaults_safe_commands, removals):
      - config: the fully merged config (defaults + platform + user − removals)
      - defaults_safe_commands: the raw shipped safe_commands (defaults.json +
        platform overlay) BEFORE user merge/subtraction — anchors C0's
        restricted-family set so user config can never demote a shipped
        multi-word family back to unknown-allow.
      - removals: the user's remove_from_defaults map (allowlist keys only),
        used by C0 (subtracted safe_commands bases stay restricted) and by
        learn_to_config (never re-add an entry the user explicitly removed).
    """
    # Load defaults
    defaults_ok = True
    try:
        with open(DEFAULTS_PATH, "r") as f:
            config = json.load(f)
        if not isinstance(config, dict):
            raise ValueError("defaults.json is not a JSON object")
    except (OSError, json.JSONDecodeError, ValueError) as e:
        # their-M1: the shipped safety lists are gone. Don't proceed with empty
        # guards (that fails OPEN — every unknown command blanket-allows). Signal
        # fail-closed so both hooks ask for everything until defaults are fixed.
        print(f"Warning: Could not load defaults: {e}", file=sys.stderr)
        config = {}
        defaults_ok = False

    # Load platform-specific overlay (e.g., defaults-windows.json)
    if sys.platform == "win32":
        platform_path = DEFAULTS_PATH.replace("defaults.json", "defaults-windows.json")
        try:
            with open(platform_path, "r") as f:
                platform_config = json.load(f)
            for key, value in platform_config.items():
                if key.startswith("_"):
                    continue
                if isinstance(value, list) and isinstance(config.get(key), list):
                    existing = set(config[key])
                    config[key] = config[key] + [v for v in value if v not in existing]
                else:
                    config[key] = value
        except (OSError, json.JSONDecodeError):
            pass  # No platform overlay — use base defaults

    # Snapshot the shipped safe_commands (defaults + platform) before the
    # user's config can touch it — this is C0's subtraction-proof anchor.
    defaults_safe_commands = list(config.get("safe_commands", []))

    # Load user overrides, bootstrapping the file if it doesn't exist
    try:
        with open(USER_CONFIG_PATH, "r") as f:
            user = json.load(f)
    except FileNotFoundError:
        user = {}
        # Bootstrap the config file so users can find and edit it
        try:
            os.makedirs(os.path.dirname(USER_CONFIG_PATH), exist_ok=True)
            with open(USER_CONFIG_PATH, "w") as f:
                json.dump({
                    "_comment": "Smart Permissions user config. Arrays are merged with defaults, so only add what's unique to your workflow. Commands support multi-word entries (e.g. 'flutter doctor') and wildcards (e.g. 'kubectl get*').",
                    "safe_commands": [],
                    "_safe_commands_examples": ["flutter doctor", "flutter build", "kubectl get *", "terraform plan", "docker compose *", "ansible", "helm"],
                    "safe_write_paths": [],
                    "_safe_write_paths_examples": ["~/Projects/", "~/workspace/"],
                    "allowed_web_domains": [],
                    "_allowed_web_domains_examples": ["docs.flutter.dev", "pub.dev", "registry.terraform.io"],
                    "safe_mcp_tools": [],
                    "_safe_mcp_tools_examples": ["mcp__sentry__get_*", "mcp__sentry__list_*", "mcp__github__get_*", "mcp__github__list_*", "mcp__github__search_*"],
                    "_remove_from_defaults_help": "Subtract shipped allowlist entries (allowlist keys only). Example: {\"safe_commands\": [\"rm\", \"docker build *\"]}",
                }, f, indent=2)
                f.write("\n")
        except OSError:
            pass  # Non-fatal — config still works from defaults alone
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load user config: {e}", file=sys.stderr)
        user = {}

    # Merge: arrays are unioned, everything else is replaced
    for key, value in user.items():
        if key.startswith("_") or key == "remove_from_defaults":
            continue
        # H6: safety-critical keys keep their container type — a wrong-type
        # value is ignored (defaults kept) so it can never gut a safety list.
        if key in _SAFETY_LIST_KEYS:
            if not isinstance(value, list):
                print(f"Warning: smart-permissions ignoring non-list value for "
                      f"safety key '{key}' (keeping defaults)", file=sys.stderr)
                continue
            base = config[key] if isinstance(config.get(key), list) else []
            existing = set(base)
            config[key] = base + [v for v in value if v not in existing]
            continue
        if key in _SAFETY_DICT_KEYS:
            if not isinstance(value, dict):
                print(f"Warning: smart-permissions ignoring non-dict value for "
                      f"safety key '{key}' (keeping defaults)", file=sys.stderr)
                continue
            # Union per interpreter so config can add exec-flags to watch but
            # never remove a shipped one ({} therefore leaves defaults intact).
            base = dict(config[key]) if isinstance(config.get(key), dict) else {}
            for ik, iv in value.items():
                # A nested non-list (e.g. {"python": "wipe"} or {"python": {}})
                # must NOT replace or drop a shipped interpreter's flag set —
                # that would silently un-guard its inline-exec form. Ignore it
                # and keep the default for that interpreter.
                if not isinstance(iv, list):
                    print(f"Warning: smart-permissions ignoring non-list "
                          f"interpreter_exec_flags for '{ik}' (keeping default)",
                          file=sys.stderr)
                    continue
                if isinstance(base.get(ik), list):
                    ex = set(base[ik])
                    base[ik] = base[ik] + [v for v in iv if v not in ex]
                else:
                    base[ik] = list(iv)
            config[key] = base
            continue
        if isinstance(value, list) and isinstance(config.get(key), list):
            # Union: add user items not already in defaults
            existing = set(config[key])
            config[key] = config[key] + [v for v in value if v not in existing]
        else:
            config[key] = value

    # Apply remove_from_defaults LAST (after defaults + overlay + user union),
    # ONLY for allowlist keys. Deny/prompt lists are never subtractable.
    removals = {}
    raw_removals = user.get("remove_from_defaults", {})
    if isinstance(raw_removals, dict):
        for key, vals in raw_removals.items():
            if key not in SUBTRACTABLE_KEYS or not isinstance(vals, list):
                continue
            removals[key] = list(vals)
            if isinstance(config.get(key), list):
                drop = set(vals)
                config[key] = [x for x in config[key] if x not in drop]

    return config, defaults_safe_commands, removals, defaults_ok


IS_WINDOWS = sys.platform == "win32"


def _expand_path(p):
    """Expand ~ and normalize separators for the current platform."""
    if p.startswith("~/"):
        p = HOME_DIR + p[1:]
    # Normalize separators so Windows paths match consistently
    if IS_WINDOWS:
        p = p.replace("/", "\\")
    return p


def _as_list(v):
    """Coerce a config value to a list. A malformed non-list (e.g. a user typo
    like {"always_ask_write_paths": false}) would otherwise crash _strip_comments
    at import — hooks must never crash — so fall back to an empty list."""
    return v if isinstance(v, list) else []


def _strip_comments(items):
    """Remove section comment entries (starting with '__ ') from a list."""
    return [x for x in _as_list(items) if not (isinstance(x, str) and x.startswith("__ "))]


# Load configuration once at module level
_CONFIG, _DEFAULTS_SAFE_COMMANDS, _REMOVALS, _DEFAULTS_OK = load_config()

# their-M1: if the shipped defaults failed to load, all safety lists are empty.
# A permission hook must FAIL CLOSED — evaluate()/evaluate_for_learning() return
# ask for everything rather than blanket-allowing with no guards.
_FAIL_CLOSED = not _DEFAULTS_OK

_ALL_SAFE_COMMANDS = _strip_comments(_CONFIG.get("safe_commands", []))
# Single-word commands: "git", "npm", etc. — O(1) set lookup
SAFE_COMMANDS = set(c for c in _ALL_SAFE_COMMANDS if " " not in c and "*" not in c and "?" not in c)
# Multi-word exact entries: "flutter doctor", "docker compose up" — O(1) set lookup
SAFE_COMMANDS_MULTI = set(c for c in _ALL_SAFE_COMMANDS if " " in c and "*" not in c and "?" not in c)
# Wildcard entries (single or multi-word): "kubectl get*", "docker *" — fnmatch
SAFE_COMMANDS_WILD = [c for c in _ALL_SAFE_COMMANDS if "*" in c or "?" in c]
SAFE_WRITE_PATHS = [_expand_path(p) for p in _as_list(_CONFIG.get("safe_write_paths"))]
SAFE_SCRIPT_PATHS = [_expand_path(p) for p in _as_list(_CONFIG.get("safe_script_paths"))]
ALLOWED_WEB_DOMAINS = _as_list(_CONFIG.get("allowed_web_domains"))
SAFE_MCP_TOOLS = _as_list(_CONFIG.get("safe_mcp_tools"))
SENSITIVE_PATHS = _as_list(_CONFIG.get("sensitive_paths"))

# Real tool names can NEVER be marked "internal-safe" via config — an entry of
# "Bash"/"Write" here would short-circuit to allow in evaluate() BEFORE the
# Bash/Write/sensitive/dangerous checks ever run (H2). Subtract them at load so
# no config merge can escalate. safe_internal_tools is only for side-effect-free
# harness tools (TaskCreate, Skill, …).
RESERVED_TOOLS = frozenset({
    "Bash", "Write", "Edit", "NotebookEdit", "MultiEdit", "WebFetch",
    "Read", "Glob", "Grep", "Task", "Agent",
})
_configured_internal = set(_strip_comments(_CONFIG.get("safe_internal_tools")))
_reserved_attempt = _configured_internal & RESERVED_TOOLS
if _reserved_attempt:
    print("Warning: smart-permissions ignoring reserved tool name(s) in "
          "safe_internal_tools: " + ", ".join(sorted(_reserved_attempt)),
          file=sys.stderr)
SAFE_INTERNAL_TOOLS = _configured_internal - RESERVED_TOOLS

# Permission-config paths that must always prompt (never auto-allow, never
# learn) even when their parent is a safe_write_path — self-escalation guard.
ALWAYS_ASK_WRITE_PATHS = _strip_comments(_CONFIG.get("always_ask_write_paths"))
DANGEROUS_PATTERNS = _strip_comments(_CONFIG.get("dangerous_patterns"))
RISKY_PATTERNS = _strip_comments(_CONFIG.get("risky_patterns"))
# Commands never persisted to the allowlist regardless of family logic
# (they can still be LLM-approved per-call — just never made permanent).
NEVER_LEARN_COMMANDS = set(_strip_comments(_CONFIG.get("never_learn_commands")))

# Convert interpreter_exec_flags from JSON lists to sets. Guard the shapes
# (H6): a malformed top-level value or inner non-list must not crash at import.
_raw_interp = _CONFIG.get("interpreter_exec_flags", {})
INTERPRETER_EXEC_FLAGS = {
    k: set(v)
    for k, v in (_raw_interp.items() if isinstance(_raw_interp, dict) else [])
    if isinstance(v, list)
}


# ============================================================
# C0 — RESTRICTED-FAMILY ENFORCEMENT (learner-side)
# ============================================================
# A "restricted base" is a command whose destructive subcommands are gated:
# it appears only as multi-word/wildcard safe_commands entries, never as a
# bare single-word entry. The learner must never treat such a base as a
# plain unknown (which would blanket-approve `docker run`, `npm publish`, …).

def _restricted_first_word(entry):
    """First real word of a multi-word/wildcard safe_commands entry.

    "docker build *" → "docker"; "kubectl get*" → "kubectl";
    single-word wildcard "kube*" → "kube". Returns None for empties.
    """
    toks = entry.split()
    if not toks:
        return None
    first = toks[0].rstrip("*?")
    return first or None


def _compute_restricted_bases(safe_commands):
    """Bases that appear ONLY as multi-word/wildcard entries in `safe_commands`.

    A base present as a bare single-word entry is NOT restricted — explicit
    single-word trust is the documented override.
    """
    singles = set(
        c for c in safe_commands
        if isinstance(c, str) and not c.startswith("__ ")
        and " " not in c and "*" not in c and "?" not in c
    )
    restricted = set()
    for c in safe_commands:
        if not isinstance(c, str) or c.startswith("__ "):
            continue
        if " " in c or "*" in c or "?" in c:
            base = _restricted_first_word(c)
            if base and base not in singles:
                restricted.add(base)
    return restricted


# Two components (see plan C0, as amended — a plan defect fix):
#  1. defaults-anchored — from raw shipped defaults + overlay, immune to
#     user subtraction (docker/npm/… can never be demoted to unknown-allow).
#     Every known-dangerous family (docker, npm, gh, terraform, kubectl,
#     cargo, helm, pip, yarn, ansible*, …) ships here.
#  2. subtracted safe_commands first words — removing `rm`/`docker build *`
#     means "ask me", never "unknown → allow".
#
# The plan's third component — "merged-multi-only", any live-config base
# appearing only as multi-word entries — was DROPPED. In the merged config a
# self-learned 2-word entry (e.g. "foo bar", persisted by _auto_learn) is
# structurally identical to a hand-authored multi-only family, so including it
# made the learner poison its own future learning: once "foo bar" was learned,
# "foo" became restricted and every sibling subcommand ("foo baz") stopped
# learning and asked forever (no-LLM). Since the defaults component already
# covers all shipped-dangerous families subtraction-proof, dropping merged-
# multi-only costs only novel user-hand-authored multi-only families (rare,
# and indistinguishable from accumulation) while restoring sibling learning.
_DEFAULTS_RESTRICTED = _compute_restricted_bases(
    _strip_comments(_DEFAULTS_SAFE_COMMANDS))
_SUBTRACTED_FIRST_WORDS = set()
for _entry in _REMOVALS.get("safe_commands", []):
    _fw = _restricted_first_word(_entry) if isinstance(_entry, str) else None
    if _fw:
        _SUBTRACTED_FIRST_WORDS.add(_fw)
RESTRICTED_BASES = _DEFAULTS_RESTRICTED | _SUBTRACTED_FIRST_WORDS
# Case-folded view for matching (FIX 2): on a case-insensitive filesystem
# (macOS APFS default), `Docker`/`DOCKER` resolve to and execute the real
# `docker` binary, so an exact-case check let the learner auto-allow a
# restricted family. Fold to lower — this only ever makes the guard match
# MORE (fail-closed); a differently-cased name that ISN'T the real binary is
# simply asked instead of blanket-approved.
_RESTRICTED_BASES_LOWER = frozenset(b.lower() for b in RESTRICTED_BASES)


def is_restricted_base(basename):
    """True if `basename` is a restricted command family (see RESTRICTED_BASES).

    Consulted only for commands not already matched as safe — an explicit
    single-word allowlist entry short-circuits before this check. Case-folded
    so a cased variant (`Docker`) can't slip a restricted family past the
    learner's no-LLM path on a case-insensitive filesystem.
    """
    return isinstance(basename, str) and basename.lower() in _RESTRICTED_BASES_LOWER


# ============================================================
# DECISION LOG + LLM CACHE STATE PATHS
# ============================================================
# Both live beside the user config (…/.claude/hooks/ in production; a temp
# dir in tests where SMART_PERMISSIONS_CONFIG is redirected) so they are
# never touched during hermetic test runs. Overridable via config.
_HOOK_STATE_DIR = os.path.join(os.path.dirname(USER_CONFIG_PATH) or ".", "hooks")

DECISION_LOG_ENABLED = bool(_CONFIG.get("decision_log", True))
_decision_log_override = _CONFIG.get("decision_log_path")
DECISION_LOG_PATH = (
    _expand_path(_decision_log_override) if _decision_log_override
    else os.path.join(_HOOK_STATE_DIR, "smart-permissions-decisions.jsonl")
)
DECISION_LOG_MAX_BYTES = 5 * 1024 * 1024  # single-generation rotation at 5 MB

LLM_CACHE_ENABLED = bool(_CONFIG.get("llm_cache", True))
_llm_cache_override = _CONFIG.get("llm_cache_path")
LLM_CACHE_PATH = (
    _expand_path(_llm_cache_override) if _llm_cache_override
    else os.path.join(_HOOK_STATE_DIR, "smart-permissions-llm-cache.json")
)
LLM_CACHE_TTL_DAYS = _CONFIG.get("llm_cache_ttl_days", 7)
LLM_CACHE_MAX_ENTRIES = 500

# Persist exact MCP tool names to safe_mcp_tools on approval (C2). Gate lets
# users restore the previous "MCP tools are never auto-learned" behavior.
AUTO_LEARN_MCP_TOOLS = bool(_CONFIG.get("auto_learn_mcp_tools", True))

# M3: relocated state files must be covered by the C9 self-escalation guard.
# If the user moved the config, log, or cache off the default paths (via
# SMART_PERMISSIONS_CONFIG / decision_log_path / llm_cache_path), those resolved
# paths aren't substrings of the shipped always_ask_write_paths, so writes to
# them would sneak past C9. Append the resolved absolute paths (deduped) so both
# the Write/Edit guard and the H1 Bash-write guard cover them too.
for _state_path in (USER_CONFIG_PATH, DECISION_LOG_PATH,
                    DECISION_LOG_PATH + ".1", LLM_CACHE_PATH):
    if _state_path and _state_path not in ALWAYS_ASK_WRITE_PATHS:
        ALWAYS_ASK_WRITE_PATHS.append(_state_path)


# ============================================================
# LLM SAFETY EVALUATION (optional fallback)
# ============================================================

# Supports any OpenAI-compatible chat completions API.
# Set env vars to enable:
#   SAFETY_HOOK_API_URL  - Chat completions endpoint (required)
#   SAFETY_HOOK_API_KEY  - API key (required — LLM disabled if empty)
#   SAFETY_HOOK_MODEL    - Model name (required)
LLM_API_URL = os.environ.get("SAFETY_HOOK_API_URL", "")
LLM_API_KEY = os.environ.get("SAFETY_HOOK_API_KEY", "")
LLM_MODEL = os.environ.get(
    "SAFETY_HOOK_MODEL",
    ""
)
# Optional reasoning_effort param (e.g. "none", "low", "medium", "high").
# Only sent if set — otherwise the provider's default applies.
LLM_REASONING_EFFORT = os.environ.get("SAFETY_HOOK_REASONING_EFFORT", "").strip()

# When true, commands/paths/domains approved by the LLM are automatically
# added to ~/.claude/smart-permissions-config.json so they're auto-allowed
# next time without an LLM call. Set to "true" to enable.
AUTO_LEARN = os.environ.get("SAFETY_HOOK_AUTO_LEARN", "").lower() in ("true", "1", "yes")

# Enable verbose logging to stderr (LLM approved/denied, auto-learn events).
# Errors and unparseable responses always log regardless of this flag.
DEBUG = os.environ.get("SAFETY_HOOK_DEBUG", "").lower() in ("true", "1", "yes")

LLM_SAFETY_PROMPT = """\
You are a security evaluator for a software developer's CLI environment.

Context:
- User is a software developer
- Tool calls come from Claude Code, an AI coding assistant
- Normal operations: building code, running tests, git, file ops in project dirs, \
package management, reading docs, search, compilers, linters

Evaluate the tool call. Be PERMISSIVE for normal development operations.
Only reject operations that could:
1. Cause data loss outside project directories
2. Modify system configuration or security settings
3. Send sensitive data to unexpected external services
4. Execute untrusted remote code (curl|sh, etc.)

Respond with ONLY valid JSON (no markdown fencing, no explanation):
- Safe: {"safe": true}
- Unsafe: {"safe": false, "reason": "brief explanation"}"""


# ============================================================
# EVALUATION LOGIC
# ============================================================

def log_unknown(kind, name):
    """Append an unknown tool or command to the review log."""
    try:
        os.makedirs(os.path.dirname(UNKNOWN_LOG), exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(UNKNOWN_LOG, "a") as f:
            f.write(f"{ts}  {kind:8s}  {name}\n")
    except OSError:
        pass  # Don't block on logging failures


def _elapsed_ms(start):
    """Milliseconds since a time.monotonic() start marker (None on error)."""
    try:
        return int((time.monotonic() - start) * 1000)
    except Exception:
        return None


def _reason_is_risky(reason):
    """True if a local ask-reason came from a risky_pattern match.

    Risky means "confirm each time" — an LLM override on such a call must
    not be cached (C4″), so the cache is skipped for these on read and write.
    """
    return bool(reason) and "Risky" in reason


def _decision_log_input(tool, tool_input):
    """Extract the human-meaningful input string for a tool, truncated 500 chars.

    Bash → command, file tools → path, WebFetch → url, else the tool name.
    Only tool inputs are ever logged (never API keys).
    """
    if tool == "Bash":
        val = tool_input.get("command", "")
    elif tool in ("Write", "Edit", "NotebookEdit"):
        val = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
    elif tool == "WebFetch":
        val = tool_input.get("url", "")
    else:
        val = tool
    if not isinstance(val, str):
        val = str(val)
    return val[:500]


def log_decision(hook, tool, tool_input, decision, source, reason,
                 duration_ms=None, llm_ms=None, learned=None):
    """Append one JSONL record describing a permission decision.

    Best-effort: never raises, never blocks the hook (blanket guard like
    log_unknown). The `input` field holds the tool input truncated to 500
    chars — it may embed secrets, so the log is the same trust class as
    shell history (see README privacy note). Rotates at 5 MB to a single
    `.1` generation. `source` is one of rule|llm|llm-cache|learner.
    """
    if not DECISION_LOG_ENABLED:
        return
    try:
        record = {
            "ts": datetime.now().isoformat(timespec="seconds"),
            "hook": hook,
            "tool": tool,
            "input": _decision_log_input(tool, tool_input),
            "decision": decision,
            "source": source,
            "reason": reason,
        }
        if duration_ms is not None:
            record["duration_ms"] = duration_ms
        if llm_ms is not None:
            record["llm_ms"] = llm_ms
        if learned:
            record["learned"] = learned
        os.makedirs(os.path.dirname(DECISION_LOG_PATH), exist_ok=True)
        # Single-generation rotation before appending.
        try:
            if os.path.getsize(DECISION_LOG_PATH) > DECISION_LOG_MAX_BYTES:
                os.replace(DECISION_LOG_PATH, DECISION_LOG_PATH + ".1")
        except OSError:
            pass
        with open(DECISION_LOG_PATH, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass  # Never block on logging failures


# ============================================================
# C4″ — EXACT-MATCH LLM DECISION CACHE (allow-only, TTL'd)
# ============================================================
# Caches LLM "allow" decisions keyed on the exact tool call so identical
# repeats stop paying the LLM. Nothing is ever promoted to a permanent
# allowlist entry from this cache — expiry (TTL) and the 500-entry cap keep
# it bounded, and only allow decisions are stored (a cached false-deny would
# stick, so denies stay live).

def _llm_cache_key(tool, tool_input):
    """sha256 over the tool name + canonical JSON of the full tool input."""
    try:
        canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        canonical = str(tool_input)
    raw = tool + "\0" + canonical
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _llm_cache_load():
    """Load the cache dict, tolerating a missing/corrupt file (→ {})."""
    try:
        with open(LLM_CACHE_PATH, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError, ValueError):
        pass
    return {}


def _llm_cache_get(tool, tool_input):
    """Return a live cached allow record for this exact call, or None.

    Prunes expired entries on read. Only allow records are ever stored, so a
    hit always means "allow".
    """
    if not LLM_CACHE_ENABLED:
        return None
    try:
        cache = _llm_cache_load()
        entry = cache.get(_llm_cache_key(tool, tool_input))
        if not isinstance(entry, dict):
            return None
        ts = entry.get("ts", 0)
        if (time.time() - ts) > (LLM_CACHE_TTL_DAYS * 86400):
            return None
        if entry.get("decision") != "allow":
            return None
        return entry
    except Exception:
        return None


def _llm_cache_put(tool, tool_input, reason):
    """Store an allow decision for this exact call. Best-effort, never raises.

    Prunes expired entries and caps the file at LLM_CACHE_MAX_ENTRIES,
    evicting the oldest by timestamp on overflow.
    """
    if not LLM_CACHE_ENABLED:
        return
    try:
        cache = _llm_cache_load()
        now = time.time()
        cutoff = now - (LLM_CACHE_TTL_DAYS * 86400)
        # Drop expired entries.
        cache = {k: v for k, v in cache.items()
                 if isinstance(v, dict) and v.get("ts", 0) >= cutoff}
        cache[_llm_cache_key(tool, tool_input)] = {
            "decision": "allow",
            "reason": reason,
            "ts": now,
        }
        # Cap: evict oldest by ts on overflow.
        if len(cache) > LLM_CACHE_MAX_ENTRIES:
            ordered = sorted(cache.items(), key=lambda kv: kv[1].get("ts", 0))
            for k, _ in ordered[:len(cache) - LLM_CACHE_MAX_ENTRIES]:
                cache.pop(k, None)
        os.makedirs(os.path.dirname(LLM_CACHE_PATH), exist_ok=True)
        tmp_path = LLM_CACHE_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(cache, f)
        os.replace(tmp_path, LLM_CACHE_PATH)
    except Exception:
        pass  # Never block on cache failures


def llm_is_configured():
    """True if all three LLM env vars are set (URL, key, model)."""
    return bool(LLM_API_KEY and LLM_API_URL and LLM_MODEL)


def learn_to_config(key, value):
    """Add a value to the user's config file for future auto-approval.

    Reads ~/.claude/smart-permissions-config.json, appends `value` to the
    array at `key` (creating both if needed), and writes back. Silently
    no-ops on any error to avoid blocking tool execution. Returns True if
    the value was newly persisted, False otherwise.

    Never re-adds an entry the user explicitly subtracted via
    remove_from_defaults[key] — an explicit removal must not be undone by
    self-learning (C6).
    """
    try:
        # Read existing config
        try:
            with open(USER_CONFIG_PATH, "r") as f:
                user_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            user_config = {}

        # Respect an explicit user subtraction — don't re-learn it.
        removals = user_config.get("remove_from_defaults", {})
        if isinstance(removals, dict) and value in (removals.get(key) or []):
            return False

        # Ensure array exists
        if key not in user_config or not isinstance(user_config[key], list):
            user_config[key] = []

        # Don't duplicate
        if value in user_config[key]:
            return False

        user_config[key].append(value)

        # Write back (atomic via temp file)
        os.makedirs(os.path.dirname(USER_CONFIG_PATH), exist_ok=True)
        tmp_path = USER_CONFIG_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(user_config, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, USER_CONFIG_PATH)

        if DEBUG:
            print(f"Learned: {key} += {value!r}", file=sys.stderr)
        return True
    except OSError as e:
        print(f"Could not save to config: {e}", file=sys.stderr)
        return False


_LEARNABLE_WORD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
_LEARNABLE_WORD_MAX_LEN = 64


def _is_learnable_word(word):
    """Reject words that aren't clean command/subcommand identifiers.

    Auto-learn must never persist tokens like $VAR, DEPS+=("...", weird"
    fragments, or heredoc body words. We require strict identifier shape:
    leading letter/underscore, then letters/digits/_/./- only. Excessively
    long tokens are also rejected — a 200-char identifier may match the
    regex but is almost certainly heredoc/log content rather than a real
    command name.
    """
    if not word or len(word) > _LEARNABLE_WORD_MAX_LEN:
        return False
    return bool(_LEARNABLE_WORD_RE.match(word))


_LEARNABLE_MCP_RE = re.compile(r"^mcp__[A-Za-z0-9_.\-]+__[A-Za-z0-9_.\-]+$")


def _is_learnable_mcp_tool(tool):
    """Reject MCP tool names that aren't clean, wildcard-free identifiers.

    Auto-learn persists the EXACT tool name (never a glob), so anything with
    a '*'/'?' or odd shape is refused — a learned pattern must not broaden
    scope beyond the single tool that was approved.
    """
    if not tool or "*" in tool or "?" in tool or len(tool) > 200:
        return False
    return bool(_LEARNABLE_MCP_RE.match(tool))


def _normalize_flag_token(token):
    """Strip quoting wrappers from a token for flag matching.

    Handles plain quotes ('-c', "-c"), ANSI-C quoting ($'-c'), and
    Bash $"" locale-quoting ($"-c"). Returns the bare token content.
    """
    if token.startswith("$'") and token.endswith("'"):
        return token[2:-1]
    if token.startswith('$"') and token.endswith('"'):
        return token[2:-1]
    return token.strip("'\"")


_INTERPRETER_WRAPPERS = frozenset({
    "env", "command", "exec", "time", "timeout", "nohup",
    "stdbuf", "nice", "ionice", "taskset", "chrt", "setsid", "unbuffer",
    # H3: xargs runs its trailing argument as a command, so a single-word-safe
    # `xargs` would let `xargs docker run` skip C0. Peel it to the inner command.
    "xargs",
})

# H4: meta-execution builtins run their argument list as a command, so the
# real command family hides behind them (`eval docker run`, `source x`). The
# learner's no-LLM path must treat these as consult/ask, never unknown-allow.
# (exec/command are also peeled as wrappers above; eval/source/. are not.)
_META_EXEC_BUILTINS = frozenset({"eval", "exec", "source", ".", "command"})


def _shlex_split_safe(cmd):
    """shlex.split that doesn't raise on unbalanced quotes / unclosed
    expansions. Falls back to naive split() so resolver callers never
    crash on hostile inputs."""
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def _resolve_through_wrappers(cmd):
    """If `cmd` starts with a transparent wrapper (env, timeout, nohup, …),
    return the inner command string starting at the real basename.

    Wrappers are themselves safe but they execute an inner command. If
    the inner command is an interpreter with an exec flag (`env python -c`,
    `timeout 5 bash -c`, `nohup python -c`), the inline-exec detection
    must see the inner basename, not the wrapper. Returns the original
    `cmd` if no wrapper is detected, so callers can chain safely.

    Handles wrapper-specific positional arguments and flag values:
      - `env KEY=value KEY=value cmd …`  → skip VAR=value pairs (quote-aware)
      - `env -S "cmd args"`              → re-parse the -S value as cmd
      - `timeout [OPTS] DURATION cmd …`  → skip flags + the duration token
      - `command [-pVv] cmd …`           → skip flags
      - `exec [-cl] [-a NAME] cmd …`     → skip flags + -a's value
      - `taskset MASK cmd …`             → skip mask (numeric/hex/list)
      - `chrt [POLICY-FLAG] PRIO cmd …`  → skip priority
      - `nohup cmd …`                    → no options to skip

    Uses shlex so quoted env values like `env FOO="bar baz" python -c …`
    are tokenized correctly. Wrapper chains (`env timeout 5 python -c …`)
    are handled by tail-calling.
    """
    tokens = _shlex_split_safe(cmd)
    if not tokens:
        return cmd
    first = os.path.basename(tokens[0])
    if first not in _INTERPRETER_WRAPPERS:
        return cmd

    idx = 1
    # Skip wrapper-specific flags and positional arguments.
    while idx < len(tokens):
        tok = tokens[idx]
        # env KEY=value assignments — tokens are already shlex-decoded
        if first == "env" and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tok):
            idx += 1
            continue
        # Flags
        if tok.startswith("-"):
            # env -S / --split-string: the value IS a command string that
            # env will re-split. Any tokens after the -S value are appended
            # as additional args to the split command. So
            #   env -S "python -c" print(1)   → python -c print(1)
            #   env -S python -c "print(1)"   → python -c print(1)
            # Reassemble: split(-S value) + remaining tokens, then recurse.
            if first == "env" and tok in ("-S", "--split-string"):
                if idx + 1 < len(tokens):
                    s_value = tokens[idx + 1]
                    rest = tokens[idx + 2:]
                    inner_tokens = _shlex_split_safe(s_value) + rest
                    if inner_tokens:
                        inner_cmd = shlex.join(inner_tokens)
                        return _resolve_through_wrappers(inner_cmd)
                return cmd
            if first == "env" and (tok.startswith("-S") or tok.startswith("--split-string=")):
                # Attached form: -S"cmd" or --split-string=cmd
                if tok.startswith("--split-string="):
                    value = tok[len("--split-string="):]
                else:
                    value = tok[2:]
                rest = tokens[idx + 1:]
                inner_tokens = _shlex_split_safe(value) + rest
                if inner_tokens:
                    inner_cmd = shlex.join(inner_tokens)
                    return _resolve_through_wrappers(inner_cmd)
                return cmd
            # Wrappers with value-flags we care about
            if first == "env" and tok in ("-u", "--unset"):
                idx += 2
                continue
            if first == "timeout" and tok in ("-s", "-k", "--signal", "--kill-after"):
                idx += 2
                continue
            if first == "exec" and tok in ("-a",):
                idx += 2
                continue
            if first == "stdbuf" and tok in ("-i", "-o", "-e",
                                              "--input", "--output", "--error"):
                idx += 2
                continue
            if first == "nice" and tok in ("-n", "--adjustment"):
                idx += 2
                continue
            if first == "ionice" and tok in ("-c", "-n", "-p", "-P", "-u",
                                              "--class", "--classdata", "--pid"):
                idx += 2
                continue
            if first == "taskset" and tok in ("-p", "--pid", "-c", "--cpu-list"):
                idx += 2
                continue
            if first == "chrt" and tok in ("-p", "--pid"):
                idx += 2
                continue
            # xargs value-flags that consume the next token, so the real
            # command isn't mistaken for a flag value (attached forms like
            # -n1 / -I{} are single tokens and fall to the generic skip below).
            if first == "xargs" and tok in ("-I", "-i", "--replace", "-n",
                                            "--max-args", "-L", "-P",
                                            "--max-procs", "-s", "--max-chars",
                                            "-a", "--arg-file", "-E", "-d",
                                            "--delimiter"):
                idx += 2
                continue
            # Generic boolean flag for any wrapper
            idx += 1
            continue
        # timeout's required positional DURATION (e.g. "5", "1.5", "30s")
        if first == "timeout" and re.match(r"^[0-9]+(\.[0-9]+)?[smhd]?$", tok):
            idx += 1
            break
        # taskset's required positional MASK: hex (0x1), decimal (3), list
        # (0,2,4), or range (0-3). Must consume before reaching the command.
        if first == "taskset" and re.match(r"^(0x[0-9a-fA-F]+|[0-9][0-9,\-]*)$", tok):
            idx += 1
            break
        # chrt's required positional PRIORITY (integer)
        if first == "chrt" and re.match(r"^[0-9]+$", tok):
            idx += 1
            break
        # Non-flag, non-assignment token = the real command starts here
        break

    if idx >= len(tokens):
        return cmd  # nothing past the wrapper — return original

    # shlex.join reassembles with proper shell quoting so downstream
    # naive splits in _has_interpreter_exec_flag still see the structure
    inner = shlex.join(tokens[idx:])
    # Recurse to handle wrapper chains (env timeout 5 python -c …)
    inner_first = os.path.basename(tokens[idx])
    if inner_first in _INTERPRETER_WRAPPERS:
        return _resolve_through_wrappers(inner)
    return inner


def _has_interpreter_exec_flag(basename, cmd):
    """True if `cmd` invokes basename with an inline-exec flag.

    Recognizes every form an attacker could use to slip past the check:
      - Separate token:        python -c "code"      perl -e "code"
      - Attached short:        python -c"code"       perl -ecode
      - Long with value:       node --eval "code"    deno eval "code"
      - Long with equals:      node --eval=code      python --command=code
      - Quoted flag:           bash "-c" "code"      bash '-c' code
      - ANSI-C / locale quoted: bash $'-c' code       bash $"-c" code
      - Clustered short flags: bash -lc "code"       sh -ec "code"

    This must stay aligned with INTERPRETER_EXEC_FLAGS so anything we
    consider a "safe interpreter" doesn't have an unchecked exec form.
    """
    exec_flags = INTERPRETER_EXEC_FLAGS.get(basename)
    if not exec_flags:
        return False
    # Build the set of short flag *letters* (without leading dash) once.
    # bash treats `-lc` as `-l -c`, so we need to detect any of the
    # interpreter's short exec flags appearing anywhere inside a
    # clustered short-option token.
    short_letters = {f[1:] for f in exec_flags
                     if len(f) == 2 and f.startswith("-") and not f.startswith("--")}
    tokens = cmd.split()
    for raw in tokens[1:]:
        token = _normalize_flag_token(raw)
        if not token:
            continue
        # Exact match: -c, -e, --eval, eval (subcommand-style)
        if token in exec_flags:
            return True
        # --flag=value: split on the first '='
        if "=" in token:
            head = token.split("=", 1)[0]
            if head in exec_flags:
                return True
        # Clustered short-flag form: -lc"code", -ec, -fc, etc. Walk the
        # letters after the single leading dash and stop at the first
        # value boundary (quote, `=`, end of token). Any short exec
        # letter present in the cluster counts as inline-exec.
        if (token.startswith("-") and not token.startswith("--")
                and len(token) > 2 and short_letters):
            cluster = []
            for ch in token[1:]:
                if ch in ('"', "'", "="):
                    break
                cluster.append(ch)
            for ch in cluster:
                if ch in short_letters:
                    return True
    return False


def _contains_inline_interpreter(command):
    """True if the command invokes an inline interpreter (bash -c, python -c).

    When this is true, auto-learn must skip the entire command — the
    splitter can't reliably tokenize the contents of the -c string, and
    naive splits would persist heredoc/script fragments as 'commands'.
    """
    if not command or not command.strip():
        return False
    parts, _ = split_compound_command(command)
    for cmd in parts:
        first_word = get_first_command_word(cmd)
        if not first_word:
            continue
        basename = os.path.basename(first_word)
        if _has_interpreter_exec_flag(basename, cmd):
            return True
        # Also check through transparent wrappers (env, timeout, nohup, …)
        inner = _resolve_through_wrappers(cmd)
        if inner != cmd:
            inner_first = get_first_command_word(inner)
            if inner_first:
                inner_basename = os.path.basename(inner_first)
                if _has_interpreter_exec_flag(inner_basename, inner):
                    return True
    return False


def _auto_learn(tool, tool_input):
    """Determine what to learn from an approved tool call and persist it.

    Returns a list of entries actually persisted (for the decision log's
    `learned` field); empty list when nothing new was learned.
    """
    learned = []
    if tool == "Bash":
        command = tool_input.get("command", "")
        # Inline interpreter (bash -c, python -c, etc.) — the contents
        # of the -c string can't be reliably tokenized as shell, so any
        # words we'd extract are likely fragments (heredoc text, embedded
        # script, regex). Skip auto-learn entirely for these.
        if _contains_inline_interpreter(command):
            return learned
        commands, uncertain = split_compound_command(command)
        # Parser hit unbalanced quotes / incomplete heredoc — extracted
        # words can't be trusted, don't persist anything.
        if uncertain:
            return learned
        for cmd in commands:
            # Extract up to 3 words so we can DETECT (and reject) 3+ word
            # commands without persisting them. If we extracted with
            # max_words=2 and the input was actually 3-word, we'd
            # silently truncate to a 2-word entry that broadens scope
            # (approving "foo bar baz" should NOT auto-allow "foo bar
            # destructive"). Three-word patterns (docker compose up,
            # gh pr list) belong in defaults.json wildcards instead.
            words = get_command_words(cmd, max_words=3, flag_handling="stop")
            if not words:
                continue
            basename = os.path.basename(words[0])
            # Skip wrapper-prefixed forms (env kubectl, timeout ls, …) —
            # learning them would broaden scope (`nohup kubectl` then
            # auto-allows `nohup kubectl delete`). The inner command
            # should be learned on its own merits via a non-wrapped run.
            if basename in _INTERPRETER_WRAPPERS:
                continue
            # If the base command is already approved (single-word), skip
            if basename in SAFE_COMMANDS or words[0] in SAFE_COMMANDS:
                continue
            # Already covered by a multi-word entry (exact or wildcard)?
            if matches_safe_command(words[0], cmd):
                continue
            # Safety: never learn a single-word base command — if we only
            # extracted 1 word it may be because flags obscured the real
            # subcommand, and learning the base command would blanket-approve
            # all subcommands including dangerous ones.
            if len(words) < 2:
                continue
            # Refuse to learn 3+ word commands. Truncating to 2 would
            # broaden scope; the user (or defaults.json) should add the
            # full pattern explicitly. Also catches prose-shaped 3-word
            # fragments from misparsed heredocs.
            if len(words) > 2:
                continue
            # Reject anything that doesn't look like a clean command +
            # subcommand chain. Catches $VAR-prefixed, +=array assignments,
            # quoted heredoc fragments, words with punctuation.
            if not _is_learnable_word(basename):
                continue
            if not all(_is_learnable_word(w) for w in words[1:]):
                continue
            # C3: reject a subcommand shaped like a filename (extension tail).
            # "pdfinfo px1_check.pdf" dies; "docker compose"/"flutter doctor"
            # are unaffected. Collateral: version-shaped words like "v1.2".
            if re.search(r"\.[A-Za-z0-9]{1,5}$", words[1]):
                continue
            # C0: never persist a restricted family (npm publish, docker run,
            # …) or an explicitly never-learn command — these can still be
            # LLM-approved per call, they just can't become permanent.
            if basename in NEVER_LEARN_COMMANDS or is_restricted_base(basename):
                continue
            to_learn = " ".join([basename] + words[1:])
            if learn_to_config("safe_commands", to_learn):
                learned.append(to_learn)
    elif tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        # C9: never learn a parent that would cover a permission-config file.
        if path and not is_always_ask_write_path(path):
            # Learn the parent directory (not the specific file)
            parent = os.path.dirname(os.path.realpath(os.path.expanduser(path)))
            if not parent.endswith("/"):
                parent += "/"
            # Collapse home dir back to ~/
            if parent.startswith(HOME_DIR):
                parent = "~" + parent[len(HOME_DIR):]
            if learn_to_config("safe_write_paths", parent):
                learned.append(parent)
    elif tool == "WebFetch":
        url = tool_input.get("url", "")
        try:
            hostname = urlparse(url).hostname or ""
            if hostname and learn_to_config("allowed_web_domains", hostname):
                learned.append(hostname)
        except Exception:
            pass
    elif tool.startswith("mcp__"):
        # C2: persist the EXACT MCP tool name (never a wildcard) on approval,
        # gated by auto_learn_mcp_tools (default true).
        if AUTO_LEARN_MCP_TOOLS and _is_learnable_mcp_tool(tool):
            if learn_to_config("safe_mcp_tools", tool):
                learned.append(tool)
    return learned


def _extract_json_decision(content):
    """Extract a {"safe": bool} decision from LLM response content.

    Reasoning models (e.g. grok-*-reasoning) often include extra text,
    markdown fencing, or explanations around the JSON even when told to
    return only JSON. This function tries multiple extraction strategies.

    Returns the parsed dict or None.
    """
    # Strategy 1: direct parse (clean JSON response)
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        pass

    # Strategy 2: strip markdown code fencing
    if "```" in content:
        try:
            start = content.index("```")
            inner_start = content.index("\n", start) + 1
            end = content.index("```", inner_start)
            inner = content[inner_start:end].strip()
            return json.loads(inner)
        except (ValueError, json.JSONDecodeError):
            pass

    # Strategy 3: regex — find {"safe": true/false, ...} anywhere in text
    match = re.search(
        r'\{\s*"safe"\s*:\s*(true|false)(?:\s*,\s*"reason"\s*:\s*"(?:[^"\\]|\\.)*")?\s*\}',
        content,
    )
    if match:
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            pass

    # Strategy 4: looser regex for malformed JSON with extra fields
    match = re.search(r'\{\s*"safe"\s*:\s*(true|false)[^}]*\}', content)
    if match:
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def llm_evaluate(tool, tool_input, timeout=38, cacheable=True):
    """Call an LLM to evaluate a tool call that local rules couldn't decide.

    Returns (decision, reason, info) where info is a dict with:
      - source: "llm-cache" on a cache hit, else "llm"
      - llm_ms: HTTP round-trip time in ms (None on cache hit / not configured)

    `timeout` is the urlopen client timeout (38s for PreToolUse under the 45s
    hook budget; 15s from the learner). `cacheable` is False when the local
    decision was risky-class — the cache is then skipped on both read and
    write (an LLM override on a "confirm each time" call must not stick).

    Auto-learn is intentionally NOT performed here — callers decide whether
    to learn (PreToolUse/learner gate on SAFETY_HOOK_AUTO_LEARN; a cache hit
    never learns). Only live-LLM allow decisions are written to the cache.
    """
    # H5: the LLM env gate comes FIRST. The cache stores LLM allow decisions;
    # consulting it when no LLM is configured would let a planted or stale entry
    # grant an allow with neither LLM nor human in the loop (poisoned-cache
    # escalation). With no LLM set we always ask — the cache is never read.
    if not llm_is_configured():
        return ("ask",
                "LLM not configured — set SAFETY_HOOK_API_URL, SAFETY_HOOK_API_KEY, and SAFETY_HOOK_MODEL",
                {"source": "llm", "llm_ms": None})

    # Exact-match cache: identical repeats stop paying the LLM (allow-only).
    if cacheable:
        hit = _llm_cache_get(tool, tool_input)
        if hit is not None:
            return ("allow", hit.get("reason", "LLM approved (cached)"),
                    {"source": "llm-cache", "llm_ms": None})

    prompt = f"Tool: {tool}\nParameters:\n{json.dumps(tool_input, indent=2)}"

    payload = {
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": LLM_SAFETY_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
        **({"reasoning_effort": LLM_REASONING_EFFORT} if LLM_REASONING_EFFORT else {}),
        # Structured output — guarantees valid JSON matching this schema.
        # Supported by xAI Grok and OpenAI GPT models.
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "safety_evaluation",
                "schema": {
                    "type": "object",
                    "properties": {
                        "safe": {"type": "boolean"},
                        "reason": {"type": "string"},
                    },
                    "required": ["safe"],
                    "additionalProperties": False,
                },
            },
        },
    }
    body = json.dumps(payload).encode()

    req = urllib.request.Request(
        LLM_API_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {LLM_API_KEY}",
            "User-Agent": "ClaudeCode-SmartPermissions/1.0",
        },
        method="POST",
    )

    _t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode())
            content = result["choices"][0]["message"]["content"].strip()
            llm_ms = _elapsed_ms(_t0)

            # json_schema response_format guarantees valid JSON, but fall
            # back to _extract_json_decision for models that ignore it.
            try:
                decision = json.loads(content)
            except (json.JSONDecodeError, ValueError):
                decision = _extract_json_decision(content)

            if decision is None:
                # Always log — this indicates a real problem
                print(f"LLM response unparseable: {content[:300]}", file=sys.stderr)
                return ("ask", "LLM response could not be parsed as JSON",
                        {"source": "llm", "llm_ms": llm_ms})

            if decision.get("safe"):
                if DEBUG:
                    print(f"LLM APPROVED: {tool}", file=sys.stderr)
                # Cache only live-LLM allow decisions (allow-only cache).
                if cacheable:
                    _llm_cache_put(tool, tool_input, "LLM approved")
                return ("allow", "LLM approved", {"source": "llm", "llm_ms": llm_ms})
            else:
                reason = decision.get("reason", "LLM flagged as unsafe")
                if DEBUG:
                    print(f"LLM DENIED: {tool} — {reason}", file=sys.stderr)
                return ("deny", f"LLM: {reason}", {"source": "llm", "llm_ms": llm_ms})

    except Exception as e:
        # Always log — API failures need visibility
        print(f"LLM error: {e}", file=sys.stderr)
        return ("ask", f"LLM unavailable ({e}) — manual approval required",
                {"source": "llm", "llm_ms": _elapsed_ms(_t0)})


def main():
    start = time.monotonic()
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        log_decision("pretool", "", {}, "ask", "rule",
                     "Could not parse hook input", duration_ms=_elapsed_ms(start))
        output_decision("ask", "Could not parse hook input")
        return

    if not isinstance(input_data, dict):
        input_data = {}
    tool = input_data.get("tool_name", "")
    # their-M2: a JSON null tool_input ({"tool_input": null}) must not crash the
    # hook with AttributeError — coerce any non-dict to an empty dict.
    tool_input = input_data.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    decision, reason = evaluate(tool, tool_input)
    source = "rule"
    llm_ms = None
    learned = None

    # If local rules can't decide, hand off to LLM (if configured). Skip the
    # cache for risky-class asks — an LLM override there must not become sticky.
    if decision == "ask":
        # C9: permission-config writes NEVER consult the LLM (and never learn)
        # — an LLM cannot vouch for an edit to the hook's own permission rules.
        # Mirrors the learner, which routes these to a definite "ask".
        if tool in ("Write", "Edit", "NotebookEdit"):
            _p = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
            if is_always_ask_write_path(_p):
                log_decision("pretool", tool, tool_input, "ask", "rule", reason,
                             duration_ms=_elapsed_ms(start))
                sys.exit(0)
        # H1: same guard for a Bash command that writes to a config/state path.
        if tool == "Bash" and bash_writes_to_config_path(tool_input.get("command", "")):
            log_decision("pretool", tool, tool_input, "ask", "rule", reason,
                         duration_ms=_elapsed_ms(start))
            sys.exit(0)
        cacheable = not _reason_is_risky(reason)
        decision, reason, info = llm_evaluate(tool, tool_input, cacheable=cacheable)
        source = info["source"]
        llm_ms = info.get("llm_ms")
        # Auto-learn only on a live-LLM allow (never on a cache hit) and only
        # when SAFETY_HOOK_AUTO_LEARN is set.
        if decision == "allow" and source == "llm" and AUTO_LEARN:
            learned = _auto_learn(tool, tool_input)

    # If still "ask" after both local rules and LLM, exit silently
    # so the built-in permission system takes over (which includes
    # the "Always allow" option). Outputting "ask" would show a
    # hook-specific Yes/No dialog instead.
    if decision == "ask":
        log_decision("pretool", tool, tool_input, "ask", source, reason,
                     duration_ms=_elapsed_ms(start), llm_ms=llm_ms)
        sys.exit(0)

    log_decision("pretool", tool, tool_input, decision, source, reason,
                 duration_ms=_elapsed_ms(start), llm_ms=llm_ms, learned=learned)
    output_decision(decision, reason)


def output_decision(decision, reason=""):
    """Print the hook output JSON."""
    output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
        }
    }
    if reason and decision != "allow":
        output["hookSpecificOutput"]["permissionDecisionReason"] = reason
    print(json.dumps(output))


def evaluate(tool, tool_input):
    """Main evaluation dispatcher. Returns (decision, reason)."""

    # FIX 3: be safe regardless of caller — a non-dict tool_input would
    # AttributeError on the .get() calls below (main() already coerces, but
    # evaluate() may be called directly).
    if not isinstance(tool_input, dict):
        tool_input = {}

    # their-M1: shipped defaults failed to load → every safety list is empty.
    # Fail CLOSED (ask for everything) rather than blanket-allow through the
    # unguarded checks below.
    if _FAIL_CLOSED:
        return ("ask", "smart-permissions defaults unavailable — failing closed")

    # Read-only tools — always safe
    if tool in ("Read", "Glob", "Grep", "WebSearch"):
        return ("allow", "Read-only tool")

    # Subagent/agent tasks — always safe
    if tool in ("Task", "Agent"):
        return ("allow", "Subagent operation")

    # Claude Code internal tools — always safe (list lives in defaults.json
    # under safe_internal_tools; user-extensible via normal array merge).
    if tool in SAFE_INTERNAL_TOOLS:
        return ("allow", "Internal Claude Code tool")

    # Write/Edit/NotebookEdit — check file paths
    if tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        return evaluate_file_path(path)

    # WebFetch — check domains
    if tool == "WebFetch":
        return evaluate_web_fetch(tool_input)

    # Bash — compound command handling
    if tool == "Bash":
        return evaluate_bash(tool_input.get("command", ""))

    # Team management — auto-approve
    if tool in ("TeamCreate", "TeamDelete", "SendMessage"):
        return ("allow", "Team management tool")

    # MCP tools — match against safe_mcp_tools patterns
    if tool.startswith("mcp__"):
        return evaluate_mcp_tool(tool)

    # Unknown tool — log and let normal permissions handle it
    log_unknown("tool", tool)
    return ("ask", f"Unknown tool: {tool} (logged)")


def _file_path_check_variants(file_path):
    """Original + normalized (+ Windows forward-slash) variants of a path."""
    normalized = os.path.realpath(os.path.expanduser(file_path))
    check_paths = [file_path, normalized]
    if IS_WINDOWS:
        check_paths += [file_path.replace("\\", "/"), normalized.replace("\\", "/")]
    return normalized, check_paths


def is_always_ask_write_path(file_path):
    """True if a Write/Edit target is a permission-config file (C9).

    Substring match like sensitive_paths. These must always prompt — never
    auto-allow, never learn, never LLM-vouch — even when their parent is a
    safe_write_path, so the agent cannot rewrite its own permission rules.
    """
    if not file_path:
        return False
    _, check_paths = _file_path_check_variants(file_path)
    # Case-insensitive: realpath preserves the caller's case (".CLAUDE" stays
    # ".CLAUDE"), but on case-insensitive filesystems (macOS APFS, Windows) that
    # still resolves to the real settings/config file. Match fail-closed so a
    # cased variant can never slip past this self-escalation guard.
    for pattern in ALWAYS_ASK_WRITE_PATHS:
        pat = pattern.lower()
        for p in check_paths:
            if pat in p.lower():
                return True
    return False


# H1: file-writing commands whose effective first word signals write intent
# even without a shell redirect. `cat`/`jq`/`grep`/`less` are deliberately
# absent — reading the decision log (e.g. the /smart-permissions:stats command)
# must stay auto-allowed. A redirect (>, >>) is handled separately as write intent.
_FILE_WRITER_COMMANDS = frozenset({
    "cp", "mv", "dd", "tee", "install", "ln", "truncate",
    "touch", "rsync", "sed",
})


def _references_always_ask_path(text):
    """Case-insensitive: does the command text mention an always-ask path?"""
    if not text:
        return False
    low = text.lower()
    for pattern in ALWAYS_ASK_WRITE_PATHS:
        if pattern and pattern.lower() in low:
            return True
    return False


def bash_writes_to_config_path(command):
    """H1/C9: True if a Bash command shows WRITE intent toward a permission-
    config/state path (always_ask_write_paths).

    C9 previously guarded only the Write/Edit/NotebookEdit tools, so a Bash
    write to the same paths (`printf x > cfg`, `tee cache`, `cp /tmp/x cfg`)
    was auto-approved — the cache case is a live self-escalation (plant an
    allow-entry → next call gets a sticky cache allow with no LLM/human).

    Scoped to write intent so read-only inspection stays allowed: per
    sub-command, ask only when it references an always-ask path AND either
    contains an output redirection (`>`/`>>`) or its effective first word
    (after wrapper peel) is a known file-writer. `jq/cat/grep <log>` with no
    redirect is not flagged.
    """
    if not command or not _references_always_ask_path(command):
        return False
    try:
        commands, _unc = split_compound_command(command)
    except Exception:
        commands = None
    for cmd in (commands or [command]):
        if not _references_always_ask_path(cmd):
            continue
        if ">" in cmd:  # output redirection (> or >>) — clearest write signal
            return True
        inner = _resolve_through_wrappers(cmd)
        first = get_first_command_word(inner) or get_first_command_word(cmd)
        if first and os.path.basename(first) in _FILE_WRITER_COMMANDS:
            return True
    return False


def evaluate_file_path(file_path):
    """Evaluate Write/Edit/NotebookEdit operations."""
    if not file_path:
        return ("ask", "No file path provided")

    # Normalize path to resolve .., symlinks, and ~; build check variants.
    normalized, check_paths = _file_path_check_variants(file_path)

    # Deny sensitive paths (check both original and normalized). Case-insensitive
    # so ".SSH/id_rsa" can't slip past on a case-insensitive filesystem — this is
    # a security guard, so it fails closed (Linux can only over-deny, never leak).
    for pattern in SENSITIVE_PATHS:
        pat = pattern.lower()
        for p in check_paths:
            if pat in p.lower():
                return ("deny", f"Sensitive path: {pattern}")

    # Self-escalation guard: permission-config files always prompt — checked
    # AFTER sensitive deny but BEFORE the safe-path allow (C9). Returns "ask",
    # not "deny" — users legitimately ask Claude to edit settings.
    for pattern in ALWAYS_ASK_WRITE_PATHS:
        pat = pattern.lower()
        for p in check_paths:
            if pat in p.lower():
                return ("ask", f"Permission-config path requires confirmation: {pattern}")

    # Allow safe paths (use normalized path). Deliberately case-SENSITIVE: this
    # is the allow side, so loosening it would broaden trust — a cased variant
    # must fall through to "ask", never match a safe prefix it doesn't equal.
    for safe_path in SAFE_WRITE_PATHS:
        if normalized.startswith(safe_path):
            return ("allow", f"Safe path: {safe_path}")

    return ("ask", f"Path not in safe list: {normalized}")


def evaluate_web_fetch(tool_input):
    """Evaluate WebFetch operations."""
    url = tool_input.get("url", "")
    try:
        hostname = urlparse(url).hostname or ""
    except Exception:
        return ("ask", "Could not parse URL")
    # Exact match or subdomain match (e.g. "api.github.com" matches "github.com")
    for domain in ALLOWED_WEB_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return ("allow", f"Allowed domain: {domain}")
    return ("ask", f"Domain not in allow list: {hostname}")


def evaluate_mcp_tool(tool):
    """Evaluate MCP tool calls against safe_mcp_tools patterns.

    Patterns support fnmatch-style globs:
      "mcp__sentry__get_*"     — all get operations from sentry
      "mcp__sentry__list_*"    — all list operations from sentry
      "mcp__github__*"         — everything from github (full trust)
      "mcp__*__get_*"          — all get operations from any server
    """
    for pattern in SAFE_MCP_TOOLS:
        if fnmatch(tool, pattern):
            return ("allow", f"MCP tool matched: {pattern}")
    log_unknown("mcp_tool", tool)
    return ("ask", f"MCP tool not in safe list: {tool}")


def _is_destructive_rm(command):
    """Token-based check for rm targeting / with recursive flag.

    Catches variants that regex misses: rm -r -f /, rm -rf -- /,
    rm --recursive --force /, rm --no-preserve-root -rf /, etc.
    """
    tokens = command.split()
    i = 0
    while i < len(tokens):
        if tokens[i] == "rm":
            has_recursive = False
            targets = []
            j = i + 1
            while j < len(tokens):
                arg = tokens[j]
                # Stop at compound command separators
                if arg in ("&&", "||", ";", "|"):
                    break
                if arg == "--":
                    j += 1
                    continue
                if arg in ("--recursive", "--no-preserve-root"):
                    has_recursive = True
                elif arg.startswith("--"):
                    pass  # other long flags (--force, --verbose, etc.)
                elif arg.startswith("-") and not arg.startswith("--"):
                    if "r" in arg or "R" in arg:
                        has_recursive = True
                else:
                    targets.append(arg.strip("'\""))
                j += 1
            if has_recursive:
                for t in targets:
                    if t in ("/", "/*"):
                        return True
            i = j if j > i + 1 else i + 1
        else:
            i += 1
    return False


def evaluate_bash(command):
    """Evaluate Bash commands, including compound/piped commands."""
    if not command or not command.strip():
        return ("ask", "Empty command")

    # Check dangerous patterns first (against full command)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return ("deny", "Blocked dangerous pattern")

    # Token-based rm check — catches flag orderings regex can't
    if _is_destructive_rm(command):
        return ("deny", "Blocked destructive rm targeting /")

    # Check risky patterns (prompt, don't auto-allow)
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, command):
            return ("ask", "Risky command pattern — confirm before running")

    # C9/H1: a Bash command that WRITES to a permission-config/state path is a
    # self-escalation vector (rewrite settings, plant a cache allow-entry).
    # Reads of the same paths (jq/cat the log) stay allowed.
    if bash_writes_to_config_path(command):
        return ("ask", "Bash write to permission-config path")

    # Try to split into individual commands
    commands, parse_uncertain = split_compound_command(command)
    commands = merge_case_blocks(commands)

    if not commands:
        return ("ask", "Could not parse compound command")

    # If parser ended in an uncertain state (unbalanced quotes, incomplete
    # heredoc), don't trust partial results — prompt for confirmation
    if parse_uncertain:
        return ("ask", "Ambiguous parse — unbalanced quotes or incomplete heredoc")

    # First pass: collect shell function definitions
    defined_functions = set()
    for cmd in commands:
        func_name = get_function_definition_name(cmd)
        if func_name:
            defined_functions.add(func_name)

    # Check each sub-command
    unknown_words = []
    for cmd in commands:
        # Re-check dangerous/risky patterns on ALL sub-commands, including
        # function definitions and merged case blocks — their bodies could
        # contain dangerous commands that the first-word check would miss
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd):
                return ("deny", "Blocked dangerous pattern")
        if _is_destructive_rm(cmd):
            return ("deny", "Blocked destructive rm targeting /")
        for pattern in RISKY_PATTERNS:
            if re.search(pattern, cmd):
                return ("ask", "Risky command pattern — confirm before running")

        # For function definitions and case blocks, extract their inner
        # commands and feed them back through the same evaluation.
        # This catches unknown commands, $VAR words, interpreter flags,
        # and anything else that the first-word check would flag.
        if get_function_definition_name(cmd):
            body = _extract_function_body(cmd)
            if body:
                inner_result = _check_inner_commands(body, defined_functions)
                if inner_result:
                    return inner_result
            continue

        if _contains_case_start(cmd):
            arm_bodies = _extract_case_arm_bodies(cmd)
            for arm_body in arm_bodies:
                inner_result = _check_inner_commands(arm_body, defined_functions)
                if inner_result:
                    return inner_result
            continue

        first_word = get_first_command_word(cmd)
        if first_word is None:
            # Command substitution as the command itself (e.g. `$(which
            # bash) -c "…"` or `` `python -c "…"` ``) is unresolvable
            # statically and is a known interpreter-hiding bypass — ask.
            stripped = cmd.lstrip()
            if stripped.startswith("$(") or stripped.startswith("`") or stripped.startswith("\\`"):
                return ("ask", "Command substitution as command word")
            continue

        # Check for interpreter string execution (bash -c, python -c, etc.)
        # Must come BEFORE safe-command check since interpreters are in SAFE_COMMANDS.
        # Peel off transparent wrappers (env, timeout, nohup, …) so
        # `env python -c "…"` is detected the same as `python -c "…"`.
        basename = os.path.basename(first_word)
        inner_cmd = _resolve_through_wrappers(cmd)
        inner_first = get_first_command_word(inner_cmd) if inner_cmd != cmd else None
        inner_basename = os.path.basename(inner_first) if inner_first else basename
        if _has_interpreter_exec_flag(basename, cmd):
            return ("ask", f"Inline interpreter execution: {basename}")
        if inner_cmd != cmd and _has_interpreter_exec_flag(inner_basename, inner_cmd):
            return ("ask", f"Inline interpreter execution via wrapper: {basename} … {inner_basename}")

        # If a transparent wrapper was peeled, the inner command's safety
        # is what matters — the wrapper is no longer in SAFE_COMMANDS
        # exactly so that destructive inners like
        # `env kubectl delete` / `timeout 5 terraform apply` can't hide.
        if inner_cmd != cmd and inner_first is not None:
            if matches_safe_command(inner_first, inner_cmd):
                continue
            # Inner is not safe; switch first_word to the inner so the
            # subsequent unknown-command path logs and prompts on the
            # real command rather than the wrapper.
            first_word = inner_first
            cmd = inner_cmd
            basename = inner_basename

        # Check known-safe commands (supports multi-word like "flutter doctor")
        if matches_safe_command(first_word, cmd):
            continue

        # Check user-defined shell functions
        if first_word in defined_functions:
            continue

        # Check relative scripts (./build.sh, scripts/foo.sh)
        # Paths containing .. could traverse outside the project directory,
        # so only allow simple relative paths without parent traversal
        if first_word.startswith("./") or first_word.startswith("../"):
            if ".." not in first_word:
                continue
            # Has .. traversal — treat as unknown
            unknown_words.append(first_word)
            continue
        if "/" in first_word and not first_word.startswith("/"):
            if ".." not in first_word:
                continue
            unknown_words.append(first_word)
            continue

        # Check absolute paths in safe directories
        expanded = os.path.expanduser(first_word)
        if any(expanded.startswith(p) for p in SAFE_SCRIPT_PATHS):
            continue

        # Check tilde paths
        if first_word.startswith("~"):
            expanded = os.path.expanduser(first_word)
            if any(expanded.startswith(p) for p in SAFE_SCRIPT_PATHS):
                continue

        # This command word is unknown
        unknown_words.append(first_word)

    if unknown_words:
        for word in unknown_words:
            log_unknown("command", word)
        return ("ask", f"Unknown command(s): {', '.join(unknown_words)} (logged)")

    return ("allow", "All commands in safe list")


def _check_inner_commands(body_text, defined_functions):
    """Check commands extracted from function bodies and case arms.

    Splits the body into sub-commands and runs the same checks as the
    main evaluate_bash loop: dangerous/risky patterns, interpreter exec,
    known-safe commands, and unknown command detection.

    Returns (decision, reason) tuple if any check fails, or None if all safe.
    """
    inner_cmds, _ = split_compound_command(body_text)
    if not inner_cmds:
        return None

    for cmd in inner_cmds:
        # Dangerous/risky patterns
        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd):
                return ("deny", "Blocked dangerous pattern in compound block")
        if _is_destructive_rm(cmd):
            return ("deny", "Blocked destructive rm in compound block")
        for pattern in RISKY_PATTERNS:
            if re.search(pattern, cmd):
                return ("ask", "Risky pattern in compound block")

        first_word = get_first_command_word(cmd)
        if first_word is None:
            # Command substitution as the command itself (e.g. `$(which
            # bash) -c "…"` or `` `python -c "…"` ``) is unresolvable
            # statically and is a known interpreter-hiding bypass — ask.
            stripped = cmd.lstrip()
            if stripped.startswith("$(") or stripped.startswith("`") or stripped.startswith("\\`"):
                return ("ask", "Command substitution as command word")
            continue

        # Interpreter exec flags (peel off transparent wrappers first)
        basename = os.path.basename(first_word)
        inner_cmd = _resolve_through_wrappers(cmd)
        inner_first = get_first_command_word(inner_cmd) if inner_cmd != cmd else None
        inner_basename = os.path.basename(inner_first) if inner_first else basename
        if _has_interpreter_exec_flag(basename, cmd):
            return ("ask", f"Interpreter execution in compound block: {basename}")
        if inner_cmd != cmd and _has_interpreter_exec_flag(inner_basename, inner_cmd):
            return ("ask", f"Interpreter execution via wrapper in compound block: {basename} … {inner_basename}")

        # Wrapper peel: delegate safety to the inner command (env / timeout /
        # nohup are no longer single-word safe, so they must not hide
        # destructive inners like `env kubectl delete`)
        if inner_cmd != cmd and inner_first is not None:
            if matches_safe_command(inner_first, inner_cmd):
                continue
            first_word = inner_first
            cmd = inner_cmd
            basename = inner_basename

        # Known-safe commands (supports multi-word like "flutter doctor")
        if matches_safe_command(first_word, cmd):
            continue
        if first_word in defined_functions:
            continue

        # Relative scripts without traversal
        if first_word.startswith("./") or first_word.startswith("../"):
            if ".." not in first_word:
                continue
        elif "/" in first_word and not first_word.startswith("/"):
            if ".." not in first_word:
                continue

        # Absolute paths in safe dirs
        expanded = os.path.expanduser(first_word)
        if any(expanded.startswith(p) for p in SAFE_SCRIPT_PATHS):
            continue

        # Unknown command inside compound block
        return ("ask", f"Unknown command in compound block: {first_word}")

    return None


# ============================================================
# COMMAND PARSING
# ============================================================

def _in_arithmetic(command, pos):
    """Check if position is inside a $((...)) arithmetic context."""
    # Scan backwards from pos for the nearest unmatched $((
    depth = 0
    j = pos - 1
    while j >= 0:
        if command[j:j+3] == "$((":
            depth += 1
        elif command[j:j+2] == "))" and j + 2 <= pos:
            depth -= 1
        j -= 1
    return depth > 0


def split_compound_command(command):
    """
    Split a compound command into individual commands.
    Handles: &&, ||, ;, | (pipe), and newlines.
    Conservative: if it encounters complex quoting/heredocs, returns
    the parts it can parse.
    """
    command = command.strip()

    # Remove pure comment lines but keep inline content
    lines = command.split("\n")
    clean_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        clean_lines.append(line)
    command = "\n".join(clean_lines)

    if not command.strip():
        return [], False

    # Simple state machine to split on &&, ||, ;, | outside of quotes
    parts = []
    current = []
    i = 0
    in_single_quote = False
    in_double_quote = False
    in_heredoc = False
    heredoc_marker = None
    paren_level = 0
    brace_level = 0

    while i < len(command):
        c = command[i]

        # Handle heredoc detection (simplified)
        # Skip << inside arithmetic $((...)) to avoid misclassifying bit shifts
        if not in_single_quote and not in_double_quote and not in_heredoc:
            if command[i:i+2] == "<<" and not _in_arithmetic(command, i):
                in_heredoc = True
                j = i + 2
                if j < len(command) and command[j] == "-":
                    j += 1
                while j < len(command) and command[j] in " \t":
                    j += 1
                marker_start = j
                if j < len(command) and command[j] in "'\"":
                    quote_char = command[j]
                    j += 1
                    marker_start = j
                    while j < len(command) and command[j] != quote_char:
                        j += 1
                    heredoc_marker = command[marker_start:j]
                else:
                    while j < len(command) and command[j] not in " \t\n;|&)":
                        j += 1
                    heredoc_marker = command[marker_start:j]
                current.append(command[i:j+1] if j < len(command) else command[i:])
                i = j + 1 if j < len(command) else j
                continue

        # Inside heredoc — consume until marker
        if in_heredoc:
            if heredoc_marker and heredoc_marker in command[i:]:
                end_idx = command.index(heredoc_marker, i) + len(heredoc_marker)
                current.append(command[i:end_idx])
                i = end_idx
                in_heredoc = False
                heredoc_marker = None
                continue
            else:
                current.append(command[i:])
                i = len(command)
                continue

        # Quote tracking
        if c == "'" and not in_double_quote:
            in_single_quote = not in_single_quote
            current.append(c)
            i += 1
            continue
        if c == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
            current.append(c)
            i += 1
            continue
        if c == "\\" and in_double_quote and i + 1 < len(command):
            current.append(c)
            current.append(command[i+1])
            i += 2
            continue

        # Outside quotes — track nesting and check for operators
        if not in_single_quote and not in_double_quote:
            if c == '(':
                paren_level += 1
            elif c == ')':
                paren_level = max(0, paren_level - 1)
            elif c == '{':
                brace_level += 1
            elif c == '}':
                brace_level = max(0, brace_level - 1)

            # Only split on operators at top level
            if paren_level == 0 and brace_level == 0:
                if command[i:i+2] in ("&&", "||"):
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 2
                    continue
                if c == "\n":
                    if current and current[-1] == "\\":
                        current.pop()
                        i += 1
                        continue
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 1
                    continue
                if c == ";" and i + 1 < len(command) and command[i+1] == ";":
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 2
                    continue
                if c in (";", "|"):
                    if c == ";" and current and current[-1] == "\\":
                        current.append(c)
                        i += 1
                        continue
                    part = "".join(current).strip()
                    if part:
                        parts.append(part)
                    current = []
                    i += 1
                    continue

        current.append(c)
        i += 1

    part = "".join(current).strip()
    if part:
        parts.append(part)

    uncertain = (in_single_quote or in_double_quote or in_heredoc
                 or paren_level != 0 or brace_level != 0)

    # Post-process: unwrap top-level subshells/groups
    final_parts = []
    for p in parts:
        stripped = p.strip()
        if ((stripped.startswith('(') and stripped.endswith(')'))
                or (stripped.startswith('{') and stripped.endswith('}'))):
            inner = stripped[1:-1].strip()
            if inner:
                inner_parts, inner_uncertain = split_compound_command(inner)
                final_parts.extend(inner_parts if inner_parts else [inner])
                if inner_uncertain:
                    uncertain = True
        else:
            final_parts.append(p)

    return final_parts, uncertain


def _contains_case_start(part):
    """Check if a part contains a case block start."""
    tokens = part.split()
    if not tokens:
        return False
    if tokens[0] == "case":
        return True
    for idx, token in enumerate(tokens):
        if token == "case":
            for j in range(idx + 2, len(tokens)):
                if tokens[j] == "in":
                    return True
    return False


def merge_case_blocks(parts):
    """Merge parts that were split from inside case...esac blocks."""
    merged = []
    i = 0
    while i < len(parts):
        if _contains_case_start(parts[i]):
            block_parts = [parts[i]]
            i += 1
            while i < len(parts):
                block_parts.append(parts[i])
                part_tokens = parts[i].split()
                part_first = part_tokens[0] if part_tokens else ""
                if part_first == "esac":
                    i += 1
                    break
                i += 1
            merged.append(" ;; ".join(block_parts))
        else:
            merged.append(parts[i])
            i += 1
    return merged


def get_function_definition_name(cmd):
    """If cmd is a shell function definition, return the function name."""
    if not cmd:
        return None
    cmd = cmd.strip()
    m = re.match(r'^([A-Za-z_][A-Za-z0-9_-]*)\s*\(\s*\)', cmd)
    if m:
        return m.group(1)
    m = re.match(r'^function\s+([A-Za-z_][A-Za-z0-9_-]*)', cmd)
    if m:
        return m.group(1)
    return None


def _extract_function_body(cmd):
    """Extract the body of a function definition for inner-command checking.

    Given 'name() { body; }' or 'function name { body; }', returns 'body;'.
    Returns empty string if no body can be extracted.
    """
    # Find the opening { and extract everything between { and }
    brace_start = cmd.find('{')
    if brace_start == -1:
        return ""
    brace_end = cmd.rfind('}')
    if brace_end <= brace_start:
        return ""
    return cmd[brace_start + 1:brace_end].strip()


def _extract_case_arm_bodies(cmd):
    """Extract the bodies of case arms for inner-command checking.

    Handles both 'case $x in a) cmd1;; b) cmd2;; esac' and the merged
    format 'case $x in a) cmd1 ;; b) cmd2 ;; esac' from merge_case_blocks.
    """
    bodies = []
    # Split on ;; to get individual arms
    arms = cmd.split(';;')
    for arm in arms:
        arm = arm.strip()
        if arm == 'esac' or not arm:
            continue
        # The first segment may contain the 'case WORD in' header followed
        # by the first arm's pattern) body — strip the header
        if 'case ' in arm:
            in_match = re.search(r'\bin\b', arm)
            if in_match:
                arm = arm[in_match.end():].strip()
            else:
                continue
        if not arm:
            continue
        # Strip the pattern prefix: 'pattern) body' → 'body'
        paren_idx = arm.find(')')
        if paren_idx >= 0:
            body = arm[paren_idx + 1:].strip()
            if body:
                bodies.append(body)
        else:
            # No pattern prefix — could be continuation; check anyway
            bodies.append(arm)
    return bodies


def get_command_words(cmd, max_words=2, flag_handling="stop"):
    """Extract up to `max_words` command words from a single command.

    Skips env variable assignments (VAR=value), leading pipes, and
    redirections — same logic as get_first_command_word but returns a
    list of up to `max_words` words.

    flag_handling controls what happens when a flag token (starting with -)
    is encountered while scanning for subcommand words:

    - "stop" (default): Stop scanning at the first flag. Only immediately
      adjacent subcommand words are returned.  Safe for auto-learning.
    - "skip": Skip the flag but continue scanning. Handles boolean flags
      before subcommands (e.g. "docker --verbose build" → ["docker", "build"]).
    - "skip_with_value": Skip the flag AND the next token (presumed flag
      value). Handles value flags before subcommands (e.g. "docker --context
      prod build" → ["docker", "build"]).
    - "include": Treat the flag itself as a subcommand word. Handles tools
      where the "subcommand" is really a flag (e.g. "spctl --status",
      "codesign --verify ..."). Only used by matches_safe_command — never
      by auto-learn (we don't want to persist flag forms).

    matches_safe_command tries all four modes for matching; _auto_learn
    uses only "stop" to avoid persisting ambiguous extractions.
    """
    if not cmd:
        return []

    cmd = cmd.strip()
    if cmd.startswith("#"):
        return []

    tokens = cmd.split()
    if not tokens:
        return []

    idx = 0

    # Skip leading pipe tokens
    while idx < len(tokens) and tokens[idx] == "|":
        idx += 1

    # Skip env var assignments (VAR=value and bash += array/string append)
    while idx < len(tokens):
        token = tokens[idx]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=", token):
            idx += 1
            value_part = token.split("=", 1)[1]

            if value_part and value_part[0] in ('"', "'"):
                quote_char = value_part[0]
                if not (len(value_part) >= 2 and value_part.endswith(quote_char)):
                    while idx < len(tokens):
                        if tokens[idx].endswith(quote_char):
                            idx += 1
                            break
                        idx += 1
                    continue

            open_parens = value_part.count("(")
            close_parens = value_part.count(")")
            while open_parens > close_parens and idx < len(tokens):
                next_token = tokens[idx]
                open_parens += next_token.count("(")
                close_parens += next_token.count(")")
                idx += 1
        else:
            break

    if idx >= len(tokens):
        return []

    word = tokens[idx]

    if word.startswith("#"):
        return []
    if word.startswith(">") or word.startswith("<"):
        return []
    # Command substitution as the first word — see get_first_command_word.
    if word.startswith("$(") or word.startswith("`") or word.startswith("\\`"):
        return []
    if word.startswith("$") and not word.startswith("$("):
        return [word]
    if word == "-":
        return []

    word = word.lstrip("(")
    word = word.rstrip(";)")

    if len(word) >= 2 and word[0] in ('"', "'") and word[-1] == word[0]:
        word = word[1:-1]
    elif word and word[0] in ('"', "'"):
        return []

    if not word:
        return []

    result = [word]

    # Scan forward for subcommand words.
    subcommands_needed = max_words - 1
    scan_idx = idx
    max_scan = min(len(tokens), idx + 12)  # Don't scan too far into args
    while subcommands_needed > 0 and scan_idx + 1 < max_scan:
        scan_idx += 1
        w = tokens[scan_idx].rstrip(";)")

        # Handle flags
        if w.startswith("-"):
            if flag_handling == "include":
                # Treat the flag itself as the "subcommand" word.
                # Handles: spctl --status → ["spctl", "--status"],
                # codesign --verify file → ["codesign", "--verify"].
                # Strip = value (e.g. "--foo=bar" → "--foo") so that
                # entries like "codesign --verify" match invocations
                # with arguments.
                flag_word = w.split("=", 1)[0]
                result.append(flag_word)
                subcommands_needed -= 1
                continue
            elif flag_handling == "skip_with_value":
                # Skip the flag, and if no inline value (no =), also
                # skip the next token as a presumed flag value.
                # Handles: docker --context prod build → ["docker", "build"]
                if "=" not in w and scan_idx + 1 < max_scan:
                    scan_idx += 1  # skip presumed value
                continue
            elif flag_handling == "skip":
                # Skip the flag only, continue scanning.
                # Handles: docker --verbose build → ["docker", "build"]
                continue
            else:
                # "stop": conservative mode, stop at the first flag
                break

        # Strip surrounding quotes from subcommand candidates so
        # `docker "build"` / `kubectl 'get' pods` match the same multi-word
        # patterns as their unquoted forms.
        if len(w) >= 2 and w[0] in ('"', "'") and w[-1] == w[0]:
            w = w[1:-1]
        # Only treat as a subcommand if it's a plain word —
        # skip paths (/foo, ./bar), variables ($X),
        # redirections (>, <), and empty results
        if _is_subcommand_token(w):
            result.append(w)
            subcommands_needed -= 1
        else:
            break  # Stop at the first non-subcommand, non-flag token

    return result


def _is_subcommand_token(w):
    """Check if a token looks like a CLI subcommand (plain alphanumeric word)."""
    return (w
            and not w.startswith("/")
            and not w.startswith("./")
            and not w.startswith("$")
            and not w.startswith(">")
            and not w.startswith("<")
            and not w.startswith("#")
            and "=" not in w
            and w[0] not in ('"', "'")
            and "/" not in w)


def _build_candidates(words, longest_only=False):
    """Build candidate multi-word strings from extracted command words.

    ["docker", "compose", "up"] → ["docker compose up", "docker compose"]

    When longest_only=True, only the full-length candidate is returned. This is
    used for the "include" flag-handling mode so that an entry like
    `spctl --status` does not also match `spctl --status --master-disable`
    (where the trailing flag changes behavior).
    """
    if len(words) < 2:
        return []
    if longest_only:
        return [" ".join([os.path.basename(words[0])] + words[1:])]
    candidates = []
    for n in range(min(len(words), 3), 1, -1):
        candidates.append(" ".join([os.path.basename(words[0])] + words[1:n]))
    return candidates


def _check_candidates(basename, candidates):
    """Check if any candidate matches SAFE_COMMANDS_MULTI or SAFE_COMMANDS_WILD."""
    # Check exact multi-word entries first, longest match wins
    if SAFE_COMMANDS_MULTI:
        for candidate in candidates:
            if candidate in SAFE_COMMANDS_MULTI:
                return True

    # Check wildcard patterns (e.g. "kubectl get*", "docker *")
    # A pattern like "cargo build *" also matches bare "cargo build"
    # (trailing " *" means "with optional arguments").
    if SAFE_COMMANDS_WILD:
        for candidate in candidates:
            for pattern in SAFE_COMMANDS_WILD:
                if fnmatch(candidate, pattern):
                    return True
                if pattern.endswith(" *") and candidate == pattern[:-2]:
                    return True
        # Also test single-word against wildcards (e.g. "kube*")
        for pattern in SAFE_COMMANDS_WILD:
            if fnmatch(basename, pattern):
                return True
            if pattern.endswith(" *") and basename == pattern[:-2]:
                return True

    return False


def matches_safe_command(first_word, cmd):
    """Check if a command matches SAFE_COMMANDS, supporting multi-word entries.

    Uses four extraction strategies and accepts if any matches:
    1. "stop" (adjacent-only): handles "docker build -t myapp"
    2. "skip" (skip flags only): handles "docker --verbose build"
    3. "skip_with_value" (skip flag + value): handles "docker --context prod build"
    4. "include" (flag is the subcommand): handles "spctl --status",
       "codesign --verify file"

    This covers boolean flags, value flags, no-flag, and flag-as-subcommand
    cases without any strategy producing false positives that could bypass
    restrictions (matching is against the same allowlist either way).

    Args:
        first_word: The first command word (from get_first_command_word).
        cmd: The full single-command string (for extracting subcommand words).

    Returns:
        True if the command is in SAFE_COMMANDS or SAFE_COMMANDS_MULTI.
    """
    if first_word is None:
        return False

    basename = os.path.basename(first_word)

    # Try all four extraction strategies — accept if any matches
    for mode in ("stop", "skip", "skip_with_value", "include"):
        words = get_command_words(cmd, max_words=3, flag_handling=mode)
        # In include mode the flag IS the subcommand identity. Match only the
        # full-length candidate so a later flag (which may change behavior)
        # cannot be silently dropped to hit a shorter exact entry. Example:
        # `spctl --status --master-disable` must not match `spctl --status`.
        candidates = _build_candidates(words, longest_only=(mode == "include"))
        if _check_candidates(basename, candidates):
            return True

    # Fall back to single-word exact match
    return basename in SAFE_COMMANDS or first_word in SAFE_COMMANDS


def get_first_command_word(cmd):
    """Extract the first command word from a single command.

    Skips env variable assignments (VAR=value) and redirections.
    Returns None for comments and empty strings.
    """
    if not cmd:
        return None

    cmd = cmd.strip()

    if cmd.startswith("#"):
        return None

    tokens = cmd.split()
    if not tokens:
        return None

    idx = 0

    # Skip leading pipe tokens
    while idx < len(tokens) and tokens[idx] == "|":
        idx += 1

    # Skip env var assignments (VAR=value and bash += array/string append)
    while idx < len(tokens):
        token = tokens[idx]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\+?=", token):
            idx += 1
            value_part = token.split("=", 1)[1]

            if value_part and value_part[0] in ('"', "'"):
                quote_char = value_part[0]
                if not (len(value_part) >= 2 and value_part.endswith(quote_char)):
                    while idx < len(tokens):
                        if tokens[idx].endswith(quote_char):
                            idx += 1
                            break
                        idx += 1
                    continue

            open_parens = value_part.count("(")
            close_parens = value_part.count(")")
            while open_parens > close_parens and idx < len(tokens):
                next_token = tokens[idx]
                open_parens += next_token.count("(")
                close_parens += next_token.count(")")
                idx += 1
        else:
            break

    if idx >= len(tokens):
        return None

    word = tokens[idx]

    if word.startswith("#"):
        return None

    if word.startswith(">") or word.startswith("<"):
        return None

    # Command substitution as the FIRST word: `$(which bash) -c "evil"` or
    # `\`python -c …\`` selects the interpreter dynamically and previously
    # collapsed to the inner safe command (e.g. "which") — bypassing the
    # interpreter-exec check on the *actual* command that runs. Return None
    # so the caller treats the whole command as unknown and prompts.
    if word.startswith("$(") or word.startswith("`") or word.startswith("\\`"):
        return None

    # Variable expansion as first word — can't resolve statically, treat as
    # unknown so it gets prompted (prevents $CMD bypasses like $'\x73udo')
    if word.startswith("$") and not word.startswith("$("):
        return word

    if word == "-":
        return None

    word = word.lstrip("(")
    word = word.rstrip(";)")

    if len(word) >= 2 and word[0] in ('"', "'") and word[-1] == word[0]:
        word = word[1:-1]
    elif word and word[0] in ('"', "'"):
        return None

    return word if word else None


if __name__ == "__main__":
    main()
