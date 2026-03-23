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
    SAFETY_HOOK_MODEL (supports any OpenAI-compatible API)
"""

import sys
import json
import os
import re
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

DEFAULTS_PATH = os.path.join(PLUGIN_ROOT, "config", "defaults.json")
USER_CONFIG_PATH = os.path.join(HOME_DIR, ".claude", "smart-permissions-config.json")
UNKNOWN_LOG = os.path.join(HOME_DIR, ".claude", "hooks", "unknown-permissions.log")


def load_config():
    """Load defaults and merge user overrides.

    Arrays are merged (union) so user additions extend defaults.
    Scalar values and objects are replaced by user overrides.
    Entries starting with '__ ' are section comments — stripped before use.
    """
    # Load defaults
    try:
        with open(DEFAULTS_PATH, "r") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load defaults: {e}", file=sys.stderr)
        config = {}

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
                    "_comment": "Smart Permissions user config. Arrays are merged with defaults, so only add what's unique to your workflow.",
                    "safe_commands": [],
                    "_safe_commands_examples": ["flutter", "dart", "gradle", "kubectl", "terraform", "ansible", "helm"],
                    "safe_write_paths": [],
                    "_safe_write_paths_examples": ["~/Projects/", "~/workspace/"],
                    "allowed_web_domains": [],
                    "_allowed_web_domains_examples": ["docs.flutter.dev", "pub.dev", "registry.terraform.io"],
                    "safe_mcp_tools": [],
                    "_safe_mcp_tools_examples": ["mcp__sentry__get_*", "mcp__sentry__list_*", "mcp__github__get_*", "mcp__github__list_*", "mcp__github__search_*"],
                }, f, indent=2)
                f.write("\n")
        except OSError:
            pass  # Non-fatal — config still works from defaults alone
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load user config: {e}", file=sys.stderr)
        user = {}

    # Merge: arrays are unioned, everything else is replaced
    for key, value in user.items():
        if key.startswith("_"):
            continue
        if isinstance(value, list) and isinstance(config.get(key), list):
            # Union: add user items not already in defaults
            existing = set(config[key])
            config[key] = config[key] + [v for v in value if v not in existing]
        else:
            config[key] = value

    return config


IS_WINDOWS = sys.platform == "win32"


def _expand_path(p):
    """Expand ~ and normalize separators for the current platform."""
    if p.startswith("~/"):
        p = HOME_DIR + p[1:]
    # Normalize separators so Windows paths match consistently
    if IS_WINDOWS:
        p = p.replace("/", "\\")
    return p


def _strip_comments(items):
    """Remove section comment entries (starting with '__ ') from a list."""
    return [x for x in items if not (isinstance(x, str) and x.startswith("__ "))]


# Load configuration once at module level
_CONFIG = load_config()

SAFE_COMMANDS = set(_strip_comments(_CONFIG.get("safe_commands", [])))
SAFE_WRITE_PATHS = [_expand_path(p) for p in _CONFIG.get("safe_write_paths", [])]
SAFE_SCRIPT_PATHS = [_expand_path(p) for p in _CONFIG.get("safe_script_paths", [])]
ALLOWED_WEB_DOMAINS = _CONFIG.get("allowed_web_domains", [])
SAFE_MCP_TOOLS = _CONFIG.get("safe_mcp_tools", [])
SENSITIVE_PATHS = _CONFIG.get("sensitive_paths", [])
DANGEROUS_PATTERNS = _CONFIG.get("dangerous_patterns", [])
RISKY_PATTERNS = _CONFIG.get("risky_patterns", [])

# Convert interpreter_exec_flags from JSON lists to sets
_raw_interp = _CONFIG.get("interpreter_exec_flags", {})
INTERPRETER_EXEC_FLAGS = {k: set(v) for k, v in _raw_interp.items()}


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

# When true, commands/paths/domains approved by the LLM are automatically
# added to ~/.claude/smart-permissions-config.json so they're auto-allowed
# next time without an LLM call. Set to "true" to enable.
AUTO_LEARN = os.environ.get("SAFETY_HOOK_AUTO_LEARN", "").lower() in ("true", "1", "yes")

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


def learn_to_config(key, value):
    """Add a value to the user's config file for future auto-approval.

    Reads ~/.claude/smart-permissions-config.json, appends `value` to the
    array at `key` (creating both if needed), and writes back. Silently
    no-ops on any error to avoid blocking tool execution.
    """
    try:
        # Read existing config
        try:
            with open(USER_CONFIG_PATH, "r") as f:
                user_config = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            user_config = {}

        # Ensure array exists
        if key not in user_config or not isinstance(user_config[key], list):
            user_config[key] = []

        # Don't duplicate
        if value in user_config[key]:
            return

        user_config[key].append(value)

        # Write back (atomic via temp file)
        os.makedirs(os.path.dirname(USER_CONFIG_PATH), exist_ok=True)
        tmp_path = USER_CONFIG_PATH + ".tmp"
        with open(tmp_path, "w") as f:
            json.dump(user_config, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, USER_CONFIG_PATH)

        print(f"Learned: {key} += {value!r}", file=sys.stderr)
    except OSError as e:
        print(f"Could not save to config: {e}", file=sys.stderr)


def _auto_learn(tool, tool_input):
    """Determine what to learn from an approved tool call and persist it."""
    if tool == "Bash":
        command = tool_input.get("command", "")
        commands, _ = split_compound_command(command)
        for cmd in commands:
            word = get_first_command_word(cmd)
            if word and os.path.basename(word) not in SAFE_COMMANDS and word not in SAFE_COMMANDS:
                learn_to_config("safe_commands", os.path.basename(word))
    elif tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        if path:
            # Learn the parent directory (not the specific file)
            parent = os.path.dirname(os.path.realpath(os.path.expanduser(path)))
            if not parent.endswith("/"):
                parent += "/"
            # Collapse home dir back to ~/
            if parent.startswith(HOME_DIR):
                parent = "~" + parent[len(HOME_DIR):]
            learn_to_config("safe_write_paths", parent)
    elif tool == "WebFetch":
        url = tool_input.get("url", "")
        try:
            hostname = urlparse(url).hostname or ""
            if hostname:
                learn_to_config("allowed_web_domains", hostname)
        except Exception:
            pass


def llm_evaluate(tool, tool_input):
    """Call an LLM to evaluate a tool call that local rules couldn't decide."""
    if not LLM_API_KEY or not LLM_API_URL or not LLM_MODEL:
        return ("ask", "LLM not configured — set SAFETY_HOOK_API_URL, SAFETY_HOOK_API_KEY, and SAFETY_HOOK_MODEL")

    prompt = f"Tool: {tool}\nParameters:\n{json.dumps(tool_input, indent=2)}"

    body = json.dumps({
        "model": LLM_MODEL,
        "messages": [
            {"role": "system", "content": LLM_SAFETY_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
    }).encode()

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

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            result = json.loads(resp.read().decode())
            content = result["choices"][0]["message"]["content"].strip()

            # Strip markdown code fencing if present
            if content.startswith("```"):
                content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()

            decision = json.loads(content)

            if decision.get("safe"):
                print(f"LLM APPROVED: {tool}", file=sys.stderr)
                if AUTO_LEARN:
                    _auto_learn(tool, tool_input)
                return ("allow", "LLM approved")
            else:
                reason = decision.get("reason", "LLM flagged as unsafe")
                print(f"LLM DENIED: {tool} — {reason}", file=sys.stderr)
                return ("deny", f"LLM: {reason}")

    except Exception as e:
        print(f"LLM error: {e}", file=sys.stderr)
        return ("ask", f"LLM unavailable ({e}) — manual approval required")


def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        output_decision("ask", "Could not parse hook input")
        return

    tool = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    decision, reason = evaluate(tool, tool_input)

    # If local rules can't decide, hand off to LLM (if configured)
    if decision == "ask":
        decision, reason = llm_evaluate(tool, tool_input)

    # If still "ask" after both local rules and LLM, exit silently
    # so the built-in permission system takes over (which includes
    # the "Always allow" option). Outputting "ask" would show a
    # hook-specific Yes/No dialog instead.
    if decision == "ask":
        sys.exit(0)

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

    # Read-only tools — always safe
    if tool in ("Read", "Glob", "Grep", "WebSearch"):
        return ("allow", "Read-only tool")

    # Subagent/agent tasks — always safe
    if tool in ("Task", "Agent"):
        return ("allow", "Subagent operation")

    # Claude Code internal tools — always safe
    if tool in ("TaskCreate", "TaskUpdate", "TaskList", "TaskGet",
                "AskUserQuestion", "Skill", "EnterPlanMode", "ExitPlanMode",
                "TaskOutput", "TaskStop", "ToolSearch",
                "CronCreate", "CronDelete", "CronList"):
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


def evaluate_file_path(file_path):
    """Evaluate Write/Edit/NotebookEdit operations."""
    if not file_path:
        return ("ask", "No file path provided")

    # Normalize path to resolve .., symlinks, and ~
    normalized = os.path.realpath(os.path.expanduser(file_path))

    # On Windows, also check with forward slashes so sensitive path
    # patterns like "/.ssh/" match regardless of separator style
    check_paths = [file_path, normalized]
    if IS_WINDOWS:
        check_paths += [file_path.replace("\\", "/"), normalized.replace("\\", "/")]

    # Deny sensitive paths (check both original and normalized)
    for pattern in SENSITIVE_PATHS:
        for p in check_paths:
            if pattern in p:
                return ("deny", f"Sensitive path: {pattern}")

    # Allow safe paths (use normalized path)
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
            continue

        # Check for interpreter string execution (bash -c, python -c, etc.)
        # Must come BEFORE safe-command check since interpreters are in SAFE_COMMANDS
        basename = os.path.basename(first_word)
        exec_flags = INTERPRETER_EXEC_FLAGS.get(basename)
        if exec_flags:
            tokens = cmd.split()
            # Strip quotes so bash "-c", bash '-c', and bash $'-c' are caught
            stripped = set()
            for t in tokens[1:]:
                if t.startswith("$'") and t.endswith("'"):
                    stripped.add(t[2:-1])  # ANSI-C quoting
                else:
                    stripped.add(t.strip("'\""))
            matched = exec_flags & stripped
            if matched:
                flag = next(iter(matched))
                return ("ask", f"Inline interpreter execution: {basename} {flag}")

        # Check known-safe commands
        if basename in SAFE_COMMANDS or first_word in SAFE_COMMANDS:
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
            continue

        # Interpreter exec flags
        basename = os.path.basename(first_word)
        exec_flags = INTERPRETER_EXEC_FLAGS.get(basename)
        if exec_flags:
            tokens = cmd.split()
            stripped = set()
            for t in tokens[1:]:
                if t.startswith("$'") and t.endswith("'"):
                    stripped.add(t[2:-1])
                else:
                    stripped.add(t.strip("'\""))
            if exec_flags & stripped:
                flag = next(iter(exec_flags & stripped))
                return ("ask", f"Interpreter execution in compound block: {basename} {flag}")

        # Known-safe commands
        if basename in SAFE_COMMANDS or first_word in SAFE_COMMANDS:
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

    # Skip env var assignments
    while idx < len(tokens):
        token = tokens[idx]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
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

            open_parens = value_part.count("$(")
            close_parens = value_part.count(")")
            while open_parens > close_parens and idx < len(tokens):
                next_token = tokens[idx]
                open_parens += next_token.count("$(")
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

    if word.startswith("$("):
        inner = word[2:].rstrip(")")
        return inner if inner else None

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
