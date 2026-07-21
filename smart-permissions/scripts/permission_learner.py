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
       allow → approve (+ learn only if SAFETY_HOOK_AUTO_LEARN); deny → deny;
       error/unparseable → manual prompt (logged).
     - LLM NOT configured → keep the historical self-learning blanket-approve
       for unknown Bash / home-dir writes / WebFetch, EXCEPT restricted
       command families (C0) which now ask; MCP/other tools keep asking.
  3. Permission-config writes (C9) always prompt — never consult the LLM,
     never learn (an LLM cannot vouch for a permission-rule edit).

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
from pretool_safety import (  # noqa: E402
    DANGEROUS_PATTERNS,
    RISKY_PATTERNS,
    INTERPRETER_EXEC_FLAGS,
    SAFE_COMMANDS,
    SAFE_COMMANDS_MULTI,
    SAFE_COMMANDS_WILD,
    AUTO_LEARN,
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
    llm_evaluate,
    llm_is_configured,
    log_decision,
    _elapsed_ms,
    _reason_is_risky,
    _is_destructive_rm,
    _auto_learn,
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


def _emit_deny():
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {"behavior": "deny", "message": "Blocked by safety hook"},
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
    tool = input_data.get("tool_name", "")
    # their-M2: a JSON null tool_input must not crash the hook — coerce to {}.
    tool_input = input_data.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}

    verdict, fallback, reason = evaluate_for_learning(tool, tool_input)

    if verdict == "deny":
        log_decision("permission_request", tool, tool_input, "deny", "learner",
                     reason, duration_ms=_elapsed_ms(start))
        _emit_deny()
        return

    if verdict == "ask":
        # Definite ask (C9 config write, empty/ambiguous) — no LLM, no learn.
        log_decision("permission_request", tool, tool_input, "ask", "learner",
                     reason, duration_ms=_elapsed_ms(start))
        sys.exit(0)

    # verdict == "consult": lean on the LLM, human as last resort.
    if llm_is_configured():
        cacheable = not _reason_is_risky(reason)
        decision, llm_reason, info = llm_evaluate(
            tool, tool_input, timeout=15, cacheable=cacheable)
        source = info["source"]
        llm_ms = info.get("llm_ms")
        if decision == "allow":
            # Learn only on a live-LLM allow with AUTO_LEARN (never on a
            # cache hit — a cached decision is not a fresh approval).
            learned = None
            if AUTO_LEARN and source == "llm":
                learned = _auto_learn(tool, tool_input)
            log_decision("permission_request", tool, tool_input, "allow",
                         source, llm_reason, duration_ms=_elapsed_ms(start),
                         llm_ms=llm_ms, learned=learned)
            _emit_allow()
            return
        if decision == "deny":
            log_decision("permission_request", tool, tool_input, "deny",
                         source, llm_reason, duration_ms=_elapsed_ms(start),
                         llm_ms=llm_ms)
            _emit_deny()
            return
        # LLM error/unparseable → manual prompt.
        log_decision("permission_request", tool, tool_input, "ask", source,
                     llm_reason, duration_ms=_elapsed_ms(start), llm_ms=llm_ms)
        sys.exit(0)

    # LLM not configured — historical self-learning fallback.
    if fallback == "allow":
        # Non-LLM mode keeps the always-learn behavior (restricted bases and
        # config writes never reach here — they map to fallback "ask").
        learned = _auto_learn(tool, tool_input)
        log_decision("permission_request", tool, tool_input, "allow", "learner",
                     reason, duration_ms=_elapsed_ms(start), learned=learned)
        _emit_allow()
        return

    log_decision("permission_request", tool, tool_input, "ask", "learner",
                 reason, duration_ms=_elapsed_ms(start))
    sys.exit(0)


def evaluate_for_learning(tool, tool_input):
    """Classify a tool call for the learner.

    Returns (verdict, fallback, reason):
      - ("deny", None, reason)          → block outright
      - ("ask", None, reason)           → manual prompt, never consult the LLM
      - ("consult", "allow", reason)    → consult LLM; without it, approve+learn
      - ("consult", "ask", reason)      → consult LLM; without it, manual prompt
    """
    # FIX 3: safe regardless of caller — a non-dict tool_input would
    # AttributeError on the .get() calls below.
    if not isinstance(tool_input, dict):
        tool_input = {}

    # their-M1: shipped defaults failed to load → fail closed (never learn or
    # blanket-approve with empty guards); route everything to a manual prompt.
    if _FAIL_CLOSED:
        return ("ask", None, "smart-permissions defaults unavailable — failing closed")

    if tool == "Bash":
        return evaluate_bash_for_learning(tool_input.get("command", ""))

    if tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        # C9: permission-config writes always prompt — no LLM, no learn.
        if is_always_ask_write_path(path):
            return ("ask", None, "Permission-config path requires confirmation")
        result, reason = evaluate_file_path(path)
        if result == "deny":
            return ("deny", None, reason)
        if result == "allow":
            return ("consult", "allow", reason)
        # result == "ask" (not in a safe write path). Only auto-approve/learn
        # writes under the home or temp dirs; system paths ask without an LLM.
        normalized = os.path.realpath(os.path.expanduser(path)) if path else ""
        home = os.path.expanduser("~")
        if (normalized.startswith(home + os.sep)
                or normalized.startswith("/tmp/")
                or normalized.startswith("/private/tmp/")):
            return ("consult", "allow", "Home/temp directory write")
        return ("consult", "ask", "Write outside safe paths")

    if tool == "WebFetch":
        result, reason = evaluate_web_fetch(tool_input)
        if result == "deny":
            return ("deny", None, reason)
        return ("consult", "allow", reason)

    # MCP tools and any other tool type: consult the LLM; without it, ask.
    return ("consult", "ask", f"Tool requires evaluation: {tool}")


def evaluate_bash_for_learning(command):
    """Classify a bash command for the learner. See evaluate_for_learning."""
    if not command or not command.strip():
        return ("ask", None, "Empty command")

    # Dangerous patterns — deny (safety net, should have been caught upstream)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return ("deny", None, "Blocked dangerous pattern")

    if _is_destructive_rm(command):
        return ("deny", None, "Blocked destructive rm targeting /")

    # Risky patterns — "confirm each time". Consult the LLM but the no-LLM
    # fallback (and the cache-skip) is ask.
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, command):
            return ("consult", "ask", "Risky command pattern — confirm before running")

    # C9/H1: a Bash command that WRITES to a permission-config/state path is a
    # self-escalation vector — definite ask (no LLM, no learn), mirroring the
    # Write/Edit C9 guard. Reads of the same paths stay allowed.
    if bash_writes_to_config_path(command):
        return ("ask", None, "Bash write to permission-config path")

    # Split compound command and check each part
    commands, parse_uncertain = split_compound_command(command)
    commands = merge_case_blocks(commands)

    if not commands or parse_uncertain:
        return ("ask", None, "Ambiguous parse — unbalanced quotes or incomplete heredoc")

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
                        return ("deny", None, "Blocked dangerous pattern in compound block")
                    return ("consult", "ask", "Unsafe command in compound block")
            continue

        # Case blocks — check arm bodies
        if _contains_case_start(cmd):
            arm_bodies = _extract_case_arm_bodies(cmd)
            for arm_body in arm_bodies:
                inner_result = _check_inner_commands(arm_body, defined_functions)
                if inner_result:
                    decision, _r = inner_result
                    if decision == "deny":
                        return ("deny", None, "Blocked dangerous pattern in compound block")
                    return ("consult", "ask", "Unsafe command in compound block")
            continue

        # Regular commands — interpreter exec + wrapper peeling, mirroring
        # PreToolUse. The restricted-base check (C0) runs on the inner
        # basename AFTER wrapper peeling, per-subcommand.
        first_word = get_first_command_word(cmd)
        if first_word is None:
            stripped = cmd.lstrip()
            if stripped.startswith("$(") or stripped.startswith("`") or stripped.startswith("\\`"):
                return ("consult", "ask", "Command substitution as command word")
            continue

        basename = os.path.basename(first_word)
        if _has_interpreter_exec_flag(basename, cmd):
            return ("consult", "ask", f"Inline interpreter execution: {basename}")

        # Peel transparent wrappers (env, timeout, nohup, …) and evaluate the
        # inner command — the wrapper must not hide a non-safe inner.
        inner = _resolve_through_wrappers(cmd)
        eff_first, eff_cmd = first_word, cmd
        if inner != cmd:
            inner_first = get_first_command_word(inner)
            if inner_first:
                inner_basename = os.path.basename(inner_first)
                if _has_interpreter_exec_flag(inner_basename, inner):
                    return ("consult", "ask",
                            f"Inline interpreter execution via wrapper: {inner_basename}")
                eff_first, eff_cmd = inner_first, inner

        eff_base = os.path.basename(eff_first) if eff_first else basename
        # H4(b): normalize a backslash-escaped command name (`\docker`,
        # `\\docker`) so the restricted-base check below sees the real family
        # instead of a literal that C0 can't match.
        eff_base = eff_base.lstrip("\\")

        # M1: a variable/indirect command word ($DOCKER, ${X}, $'docker') is
        # inherently unknown — C0's literal-basename match can't classify it, so
        # never blanket-approve. Mirror the $()/backtick handling above.
        if first_word.startswith("$") or (eff_first and eff_first.startswith("$")):
            return ("consult", "ask", "Variable/indirect command word")

        # H4(c): a meta-execution builtin (eval/exec/source/./command) runs its
        # arguments as a command, hiding the real family behind it. Never
        # unknown-allow — consult/ask. Check the raw first word too, since
        # eval/source/. are not peeled as transparent wrappers.
        if (basename.lstrip("\\") in _META_EXEC_BUILTINS
                or eff_base in _META_EXEC_BUILTINS):
            return ("consult", "ask", "Meta-execution command word")

        # Explicitly safe (incl. user single-word override) — short-circuit
        # before the restricted-base check.
        if matches_safe_command(eff_first, eff_cmd):
            continue

        # M2: a transparent wrapper (env/timeout/nohup/…) hid a NON-safe inner
        # command — restore the old conservative guard. Bare unwrapped unknowns
        # keep their historic consult/allow; only the WRAPPED case re-tightens
        # to ask (e.g. `env evil-tool --wipe` → ask, not blanket-approve).
        if inner != cmd:
            return ("consult", "ask", f"Wrapped non-safe command: {eff_base}")

        # C0: a restricted command family (docker/npm/gh/… with only
        # multi-word entries) is NOT a plain unknown — never blanket-approve.
        if is_restricted_base(eff_base):
            restricted_found = True

    if restricted_found:
        return ("consult", "ask", "Restricted command family — LLM or manual approval")

    # Plain unknown Bash — consult; without an LLM, approve + learn (historic).
    return ("consult", "allow", "Unknown command")


if __name__ == "__main__":
    main()
