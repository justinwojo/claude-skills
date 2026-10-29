#!/usr/bin/env python3
"""
Claude Code PermissionRequest hook — LLM-consulting permission approval.

This hook fires when a permission dialog is about to be shown (meaning
PreToolUse returned "ask" and no built-in rule matched). Trust order is
rules → LLM → human: the learner re-checks the local rules, then consults
the LLM for anything genuinely unknown, and only falls back to a manual
prompt as the true last resort.

  1. Re-checks dangerous patterns as a safety net → deny.
  2. Classifies everything else as "consult":
     - LLM configured → call it (client timeout 15s, inside the hook budget).
       allow → approve; a flag the second pass confirms, error or
       unparseable → manual prompt (logged). A call PreToolUse already
       flagged skips the LLM and prompts.
     - LLM NOT configured → manual prompt.
  3. Permission-config writes (C9) always prompt — never consult the LLM
     (an LLM cannot vouch for a permission-rule edit).

Nothing is ever written to the user config: an approval covers this one call.
(The hook keeps its old file name so existing hook registrations still work.)

Every exit path writes a structured decision-log record (C1); the learner's
"ask" records ARE the manual-approval history.
"""

import sys
import json
import os
import re
import time

# Import shared logic from pretool-safety.py (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pretool_safety  # noqa: E402
from pretool_safety import (  # noqa: E402
    DANGEROUS_PATTERNS,
    RISKY_PATTERNS,
    INTERPRETER_EXEC_FLAGS,
    SAFE_COMMANDS,
    SAFE_COMMANDS_MULTI,
    SAFE_COMMANDS_WILD,
    evaluate_file_path,
    evaluate_web_fetch,
    split_compound_command,
    merge_case_blocks,
    get_first_command_word,
    get_command_words,
    matches_safe_command,
    get_function_definition_name,
    is_restricted_base,
    is_always_ask_write_path,
    bash_writes_to_config_path,
    build_llm_context,
    llm_evaluate,
    llm_is_configured,
    _flag_get,
    log_decision,
    parse_hook_payload,
    _elapsed_ms,
    _reason_is_risky,
    _is_destructive_rm,
    protected_delete_check,
    unguarded_delete_check,
    _STEER_PREFIX,
    set_hook_cwd,
    _contains_case_start,
    _extract_function_body,
    _extract_case_arm_bodies,
    _check_inner_commands,
    _has_interpreter_exec_flag,
    _resolve_through_wrappers,
    _META_EXEC_BUILTINS,
    _FAIL_CLOSED,
)


def _emit_allow():
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "allow"},
        }
    }))


def _emit_deny(message="Blocked by safety hook"):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": message},
        }
    }))


def main():
    start = time.monotonic()
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        # Can't parse — let the normal prompt show, but still record it.
        log_decision("permission_request", "", {}, "ask", "learner",
                     "Could not parse hook input", duration_ms=_elapsed_ms(start))
        sys.exit(0)

    if not isinstance(input_data, dict):
        input_data = {}
    # their-M2: a JSON null tool_input must not crash the hook — coerced to {}.
    tool, tool_input = parse_hook_payload(input_data)

    set_hook_cwd(input_data)
    verdict, reason = classify_request(tool, tool_input)

    if verdict == "deny":
        log_decision("permission_request", tool, tool_input, "deny", "learner",
                     reason, duration_ms=_elapsed_ms(start))
        # A steer carries rewrite instructions the agent needs to see.
        _emit_deny(reason if reason.startswith(_STEER_PREFIX) else "Blocked by safety hook")
        return

    # A definite ask (C9 config write, empty/ambiguous), or nothing to consult:
    # without an LLM every call the rules could not settle goes to the human.
    if verdict == "ask" or not llm_is_configured():
        log_decision("permission_request", tool, tool_input, "ask", "learner",
                     reason, duration_ms=_elapsed_ms(start))
        sys.exit(0)

    # verdict == "consult": lean on the LLM, human as last resort.
    # PreToolUse already ran both LLM passes on this exact call and
    # confirmed a flag — this prompt is the human decision it asked for.
    flagged = _flag_get(tool, tool_input)
    if flagged:
        log_decision("permission_request", tool, tool_input, "ask", "llm-recheck",
                     flagged, duration_ms=_elapsed_ms(start))
        sys.exit(0)
    cacheable = not _reason_is_risky(reason)
    decision, llm_reason, info = llm_evaluate(
        tool, tool_input, timeout=15, cacheable=cacheable,
        context=build_llm_context(input_data))
    source = info["source"]
    llm_ms = info.get("llm_ms")
    if decision == "allow":
        log_decision("permission_request", tool, tool_input, "allow",
                     source, llm_reason, duration_ms=_elapsed_ms(start),
                     llm_ms=llm_ms, rule_reason=reason)
        _emit_allow()
        return
    # Confirmed flag, LLM error or unparseable → manual prompt.
    log_decision("permission_request", tool, tool_input, "ask", source,
                 llm_reason, duration_ms=_elapsed_ms(start), llm_ms=llm_ms,
                 rule_reason=reason)
    sys.exit(0)


def classify_request(tool, tool_input):
    """Classify a tool call for the PermissionRequest hook.

    Returns (verdict, reason):
      - ("deny", reason)     → block outright
      - ("ask", reason)      → manual prompt, never consult the LLM
      - ("consult", reason)  → consult the LLM; without one, manual prompt
    The reason says which rule settled or punted the call; on a consult it is
    logged as `rule_reason` beside the LLM's own reason.
    """
    # FIX 3: safe regardless of caller — a non-dict tool_input would
    # AttributeError on the .get() calls below.
    if not isinstance(tool_input, dict):
        tool_input = {}

    # their-M1: shipped defaults failed to load → fail closed (never consult
    # the LLM with empty guards); route everything to a manual prompt.
    if _FAIL_CLOSED:
        return ("ask", "smart-permissions defaults unavailable — failing closed")

    if tool == "Bash":
        return classify_bash(tool_input.get("command", ""))

    if tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        # C9: permission-config writes always prompt — no LLM.
        if is_always_ask_write_path(path):
            return ("ask", "Permission-config path requires confirmation")
        result, reason = evaluate_file_path(path)
        if result == "deny":
            return ("deny", reason)
        if result == "allow":
            return ("consult", reason)
        normalized = os.path.realpath(os.path.expanduser(path)) if path else ""
        home = os.path.expanduser("~")
        if (normalized.startswith(home + os.sep)
                or normalized.startswith("/tmp/")
                or normalized.startswith("/private/tmp/")):
            return ("consult", "Home/temp directory write")
        return ("consult", "Write outside safe paths")

    if tool == "WebFetch":
        result, reason = evaluate_web_fetch(tool_input)
        if result == "deny":
            return ("deny", reason)
        return ("consult", reason)

    # MCP tools and any other tool type: consult the LLM.
    return ("consult", f"Tool requires evaluation: {tool}")


def classify_bash(command):
    """Classify a bash command for the learner. See classify_request.

    A recursive delete of a protected folder is denied; one whose target leans
    on a possibly-empty variable is denied with a guarded rewrite (the LLM can
    only guess at what an unguarded variable holds); any other recursive
    delete consults the LLM under the guard's reason.
    """
    # Same order as evaluate_bash: plain deny, rewrite, then the empty case.
    guard = protected_delete_check(command, pretool_safety.HOOK_CWD, empty_side=False)
    if guard and guard[0] == "deny":
        return ("deny", guard[1])
    steer = unguarded_delete_check(command)
    if steer:
        return ("deny", steer[1])
    guard = protected_delete_check(command, pretool_safety.HOOK_CWD)
    if guard and guard[0] == "deny":
        return ("deny", guard[1])
    verdict, reason = _bash_rules(command)
    if guard and verdict == "consult":
        return ("consult", guard[1])
    return (verdict, reason)


def _bash_rules(command):
    """The pattern and allowlist rules behind classify_bash."""
    if not command or not command.strip():
        return ("ask", "Empty command")

    # Dangerous patterns — deny (safety net, should have been caught upstream)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return ("deny", "Blocked dangerous pattern")

    if _is_destructive_rm(command):
        return ("deny", "Blocked destructive rm targeting /")

    # Risky patterns — "confirm each time". Consult the LLM, but never cache
    # its verdict (_reason_is_risky keys on this reason).
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, command):
            return ("consult", "Risky command pattern — confirm before running")

    # C9/H1: a Bash command that WRITES to a permission-config/state path is a
    # self-escalation vector — definite ask (no LLM), mirroring the
    # Write/Edit C9 guard. Reads of the same paths stay allowed.
    if bash_writes_to_config_path(command):
        return ("ask", "Bash write to permission-config path")

    # Split compound command and check each part
    commands, parse_uncertain = split_compound_command(command)
    commands = merge_case_blocks(commands)

    if not commands or parse_uncertain:
        return ("ask", "Ambiguous parse — unbalanced quotes or incomplete heredoc")

    # Collect defined functions so _check_inner_commands can trust calls to them
    defined_functions = set()
    for cmd in commands:
        func_name = get_function_definition_name(cmd)
        if func_name:
            defined_functions.add(func_name)

    # Check each sub-command, including compound block bodies
    restricted_found = False
    for cmd in commands:
        # Function definitions — check body for unsafe inner commands
        if get_function_definition_name(cmd):
            body = _extract_function_body(cmd)
            if body:
                inner_result = _check_inner_commands(body, defined_functions)
                if inner_result:
                    decision, _r = inner_result
                    if decision == "deny":
                        return ("deny", "Blocked dangerous pattern in compound block")
                    return ("consult", "Unsafe command in compound block")
            continue

        # Case blocks — check arm bodies
        if _contains_case_start(cmd):
            arm_bodies = _extract_case_arm_bodies(cmd)
            for arm_body in arm_bodies:
                inner_result = _check_inner_commands(arm_body, defined_functions)
                if inner_result:
                    decision, _r = inner_result
                    if decision == "deny":
                        return ("deny", "Blocked dangerous pattern in compound block")
                    return ("consult", "Unsafe command in compound block")
            continue

        # Regular commands — interpreter exec + wrapper peeling, mirroring
        # PreToolUse. The restricted-base check (C0) runs on the inner
        # basename AFTER wrapper peeling, per-subcommand.
        first_word = get_first_command_word(cmd)
        if first_word is None:
            stripped = cmd.lstrip()
            if stripped.startswith("$(") or stripped.startswith("`") or stripped.startswith("\\`"):
                return ("consult", "Command substitution as command word")
            continue

        basename = os.path.basename(first_word)
        if _has_interpreter_exec_flag(basename, cmd):
            return ("consult", f"Inline interpreter execution: {basename}")

        # Peel transparent wrappers (env, timeout, nohup, …) and evaluate the
        # inner command — the wrapper must not hide a non-safe inner.
        inner = _resolve_through_wrappers(cmd)
        eff_first, eff_cmd = first_word, cmd
        if inner != cmd:
            inner_first = get_first_command_word(inner)
            if inner_first:
                inner_basename = os.path.basename(inner_first)
                if _has_interpreter_exec_flag(inner_basename, inner):
                    return ("consult",
                            f"Inline interpreter execution via wrapper: {inner_basename}")
                eff_first, eff_cmd = inner_first, inner

        eff_base = os.path.basename(eff_first) if eff_first else basename
        # H4(b): normalize a backslash-escaped command name (`\docker`,
        # `\\docker`) so the restricted-base check below sees the real family
        # instead of a literal that C0 can't match.
        eff_base = eff_base.lstrip("\\")

        # M1: a variable/indirect command word ($DOCKER, ${X}, $'docker') is
        # inherently unknown — C0's literal-basename match can't classify it.
        # Mirror the $()/backtick handling above.
        if first_word.startswith("$") or (eff_first and eff_first.startswith("$")):
            return ("consult", "Variable/indirect command word")

        # H4(c): a meta-execution builtin (eval/exec/source/./command) runs its
        # arguments as a command, hiding the real family behind it. Check the
        # raw first word too, since eval/source/. are not peeled as
        # transparent wrappers.
        if (basename.lstrip("\\") in _META_EXEC_BUILTINS
                or eff_base in _META_EXEC_BUILTINS):
            return ("consult", "Meta-execution command word")

        # Explicitly safe (incl. user single-word override) — short-circuit
        # before the restricted-base check.
        if matches_safe_command(eff_first, eff_cmd):
            continue

        # M2: a transparent wrapper (env/timeout/nohup/…) hid a NON-safe inner
        # command (e.g. `env evil-tool --wipe`).
        if inner != cmd:
            return ("consult", f"Wrapped non-safe command: {eff_base}")

        # C0: a restricted command family (docker/npm/gh/… with only
        # multi-word entries) is NOT a plain unknown.
        if is_restricted_base(eff_base):
            restricted_found = True

    if restricted_found:
        return ("consult", "Restricted command family — LLM or manual approval")

    # Plain unknown Bash — consult the LLM; without one, the human.
    return ("consult", "Unknown command")


if __name__ == "__main__":
    main()
