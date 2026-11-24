"""Configuration: where the plugin and the user's files are, loading and
merging defaults.json, the platform overlay and the user config (type-guarded,
so user config can only add to a safety list), the constants derived from it,
and the paths of the hook's state files (decision log, flag store, holds), which
are added to the always-ask write paths. Everything here runs once, at import.
It imports nothing from this package."""
import sys
import json
import os


# ============================================================
# CONFIGURATION LOADING
# ============================================================

# Resolve paths relative to the entry scripts' folder (scripts/, which holds
# this package)
SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLUGIN_ROOT = os.path.dirname(SCRIPT_DIR)
# A manual install (README) puts config/ beside the scripts, not one level up
if (not os.path.isfile(os.path.join(PLUGIN_ROOT, "config", "defaults.json"))
        and os.path.isfile(os.path.join(SCRIPT_DIR, "config", "defaults.json"))):
    PLUGIN_ROOT = SCRIPT_DIR
# The plugin version (.claude-plugin/marketplace.json), on every log record
HOOK_VERSION = "1.8.3"
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
    "always_ask_write_paths", "safe_internal_tools",
    "safe_commands", "safe_write_paths", "safe_script_paths",
    "allowed_web_domains", "safe_mcp_tools", "protected_delete_paths",
})
_SAFETY_DICT_KEYS = frozenset({"interpreter_exec_flags"})


def load_config():
    """Load defaults and merge user overrides.

    Arrays are merged (union) so user additions extend defaults.
    Scalar values and objects are replaced by user overrides.
    Entries starting with '__ ' are section comments — stripped before use.

    Returns (config, defaults_ok): the fully merged config (defaults +
    platform + user − removals), and False when defaults.json failed to load.
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
    raw_removals = user.get("remove_from_defaults", {})
    if isinstance(raw_removals, dict):
        for key, vals in raw_removals.items():
            if key not in SUBTRACTABLE_KEYS or not isinstance(vals, list):
                continue
            if isinstance(config.get(key), list):
                drop = set(vals)
                config[key] = [x for x in config[key] if x not in drop]

    return config, defaults_ok


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
_CONFIG, _DEFAULTS_OK = load_config()

# their-M1: if the shipped defaults failed to load, all safety lists are empty.
# A permission hook must FAIL CLOSED — evaluate()/classify_request() return
# ask for everything rather than blanket-allowing with no guards.
_FAIL_CLOSED = not _DEFAULTS_OK

_ALL_SAFE_COMMANDS = _strip_comments(_CONFIG.get("safe_commands", []))
# Single-word commands: "git", "npm", etc. — O(1) set lookup
SAFE_COMMANDS = set(c for c in _ALL_SAFE_COMMANDS if " " not in c and "*" not in c and "?" not in c)
# Multi-word exact entries: "flutter doctor", "docker compose up" — O(1) set lookup
SAFE_COMMANDS_MULTI = set(c for c in _ALL_SAFE_COMMANDS if " " in c and "*" not in c and "?" not in c)
# Wildcard entries (single or multi-word): "kubectl get*", "docker *" — fnmatch
SAFE_COMMANDS_WILD = [c for c in _ALL_SAFE_COMMANDS if "*" in c or "?" in c]


def _has_interior_wildcard(pattern):
    """True for patterns like `az * list` whose wildcard is not in the last word."""
    return any("*" in w or "?" in w for w in pattern.split()[:-1])


# Interior-wildcard patterns (`az * show`, `az * * list`) match word by word —
# one `*` is one word — and only on flag-free subcommand chains, so the `*`
# can never swallow a verb (`az group delete -n show` is not `az * show`).
SAFE_COMMANDS_WORDWISE = [c.split() for c in SAFE_COMMANDS_WILD if _has_interior_wildcard(c)]
SAFE_COMMANDS_WILD = [c for c in SAFE_COMMANDS_WILD if not _has_interior_wildcard(c)]
SAFE_WRITE_PATHS = [_expand_path(p) for p in _as_list(_CONFIG.get("safe_write_paths"))]
SAFE_SCRIPT_PATHS = [_expand_path(p) for p in _as_list(_CONFIG.get("safe_script_paths"))]
ALLOWED_WEB_DOMAINS = _as_list(_CONFIG.get("allowed_web_domains"))
SAFE_MCP_TOOLS = _as_list(_CONFIG.get("safe_mcp_tools"))
# {MCP tool glob: a sentence the judge reads with a call to a matching tool}
# ("the developer's Windows bench; C:\\Users\\bench is its own account").
# Context only: it never allows anything by itself. A wrong type is ignored.
MCP_CONTEXT = {k: v.strip()[:500] for k, v in _CONFIG.get("mcp_context", {}).items()
               if isinstance(k, str) and isinstance(v, str) and v.strip()} \
    if isinstance(_CONFIG.get("mcp_context"), dict) else {}
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
# LLM-vouched) even when their parent is a safe_write_path — self-escalation guard.
ALWAYS_ASK_WRITE_PATHS = _strip_comments(_CONFIG.get("always_ask_write_paths"))
DANGEROUS_PATTERNS = _strip_comments(_CONFIG.get("dangerous_patterns"))
RISKY_PATTERNS = _strip_comments(_CONFIG.get("risky_patterns"))
# Folders a recursive rm may never delete, or delete anything above. Globs are
# expanded against the filesystem at check time (see protected_delete_check).
PROTECTED_DELETE_PATHS = [
    HOME_DIR if p == "~" else _expand_path(p)
    for p in _strip_comments(_CONFIG.get("protected_delete_paths"))
    if isinstance(p, str) and p
]

# Convert interpreter_exec_flags from JSON lists to sets. Guard the shapes
# (H6): a malformed top-level value or inner non-list must not crash at import.
_raw_interp = _CONFIG.get("interpreter_exec_flags", {})
INTERPRETER_EXEC_FLAGS = {
    k: set(v)
    for k, v in (_raw_interp.items() if isinstance(_raw_interp, dict) else [])
    if isinstance(v, list)
}


# ============================================================
# DECISION LOG + LLM FLAG STATE PATHS
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
DECISION_LOG_MAX_BYTES = 20 * 1024 * 1024  # single-generation rotation at 20 MB
# An allow keeps the start of its input; an ask or deny keeps up to this
# much, so the calls that stopped someone can be read in full later.
DECISION_LOG_INPUT_CHARS = 500
DECISION_LOG_FLAGGED_INPUT_CHARS = 8000
# Opt-in fuller capture (`decision_log_full_input`): every input up to this
# many chars, with obvious secrets redacted (see _redact_secrets)
DECISION_LOG_FULL_INPUT = _CONFIG.get("decision_log_full_input") is True
DECISION_LOG_FULL_INPUT_CHARS = 64 * 1024

# Calls both LLM passes flagged. PreToolUse records them so the
# PermissionRequest hook that fires for the resulting prompt goes straight to
# the human instead of paying for (and possibly overruling) a third opinion.
LLM_FLAG_PATH = os.path.join(_HOOK_STATE_DIR, "smart-permissions-llm-flags.json")
LLM_FLAG_TTL_S = 300

# Holds (see HOLDS below): one small file per held call, so two hooks never
# rewrite each other's entries.
HOLDS_ENABLED = _CONFIG.get("holds") is True
HOLD_DIR = os.path.join(_HOOK_STATE_DIR, "smart-permissions-holds")

# A permission prompt nobody answers: after this long the PermissionRequest
# hook denies it with a message that parks the call for the developer, so
# the session moves on instead of freezing. 0 turns it off. hooks.json gives
# the learner a timeout above the maximum.
PROMPT_TIMEOUT_DEFAULT_MINUTES = 10
PROMPT_TIMEOUT_MAX_MINUTES = 60


def _prompt_timeout_s(value):
    """Seconds for config `prompt_timeout_minutes`: 0 (off) for 0 or less,
    else 1 to 60 minutes; not a number → the default."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        value = PROMPT_TIMEOUT_DEFAULT_MINUTES
    if value <= 0:
        return 0
    return min(max(value, 1), PROMPT_TIMEOUT_MAX_MINUTES) * 60


PROMPT_TIMEOUT_S = _prompt_timeout_s(_CONFIG.get("prompt_timeout_minutes", PROMPT_TIMEOUT_DEFAULT_MINUTES))

# M3: relocated state files must be covered by the C9 self-escalation guard.
# If the user moved the config or log off the default paths (via
# SMART_PERMISSIONS_CONFIG / decision_log_path), those resolved
# paths aren't substrings of the shipped always_ask_write_paths, so writes to
# them would sneak past C9. Append the resolved absolute paths (deduped) so both
# the Write/Edit guard and the H1 Bash-write guard cover them too.
# The judge's key file (see _load_llm_env_file) is state too, and a secret:
# reading it asks like any sensitive path.
LLM_ENV_FILE = os.path.join(os.path.dirname(USER_CONFIG_PATH) or ".", "smart-permissions-llm.env")
for _state_path in (USER_CONFIG_PATH, DECISION_LOG_PATH,
                    DECISION_LOG_PATH + ".1", LLM_FLAG_PATH, LLM_ENV_FILE, HOLD_DIR):
    if _state_path and _state_path not in ALWAYS_ASK_WRITE_PATHS:
        ALWAYS_ASK_WRITE_PATHS.append(_state_path)
if LLM_ENV_FILE not in SENSITIVE_PATHS:
    SENSITIVE_PATHS.append(LLM_ENV_FILE)
