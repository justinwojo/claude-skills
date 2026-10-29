#!/usr/bin/env python3
"""
Claude Code PermissionRequest hook — LLM-consulting permission approval.

This hook fires when a permission dialog is about to be shown (meaning
PreToolUse returned "ask" and no built-in rule matched). Trust order is
rules → LLM → human: the learner re-checks the local rules, then consults
the LLM for anything genuinely unknown, and only falls back to a manual
prompt as the true last resort.

  1. Re-runs PreToolUse's own rules (evaluate_bash, evaluate_file_path, …)
     as a safety net: what they deny is denied here too.
  2. Permission-config writes (C9) always prompt — never consult the LLM
     (an LLM cannot vouch for a permission-rule edit). So do an empty Bash
     command and one the parser can't read with confidence.
  3. Classifies everything else as "consult" — even a call the rules would
     allow, since it reached a prompt anyway:
     - LLM configured → call it (client timeout 15s, inside the hook budget).
       allow → approve; a flag the second pass confirms, error or
       unparseable → manual prompt (logged). A call PreToolUse already
       flagged skips the LLM and prompts.
     - LLM NOT configured → manual prompt.

Nothing is ever written to the user config: an approval covers this one call.
(The hook keeps its old file name so existing hook registrations still work.)

Every exit path writes a structured decision-log record (C1); the learner's
"ask" records ARE the manual-approval history.
"""

import sys
import json
import os
import time

# Import shared logic from pretool-safety.py (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pretool_safety import (  # noqa: E402
    evaluate_bash,
    evaluate_file_path,
    evaluate_web_fetch,
    bash_parse_uncertain,
    human_required_reason,
    build_llm_context,
    llm_evaluate,
    llm_is_configured,
    _flag_get,
    log_decision,
    parse_hook_payload,
    _elapsed_ms,
    set_hook_cwd,
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
    """The hook. Any failure inside (a RecursionError on a deeply nested
    command, a parser bug) falls through to the normal permission prompt:
    never an allow, never a crash with no verdict."""
    try:
        _main()
    except Exception as e:
        try:
            log_decision("permission_request", "", {}, "ask", "learner",
                         f"smart-permissions could not evaluate this call ({type(e).__name__})")
        except Exception:
            pass
        sys.exit(0)


def _main():
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
        # The reason says what to do instead (a steer's rewrite, or the
        # alternative to a blocked pattern), as PreToolUse shows it.
        _emit_deny(reason)
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
    decision, llm_reason, info = llm_evaluate(
        tool, tool_input, timeout=15, context=build_llm_context(input_data),
        rule_reason=reason)
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
        result, reason = evaluate_file_path(path)
        if result == "deny":
            return ("deny", reason)
        # C9: permission-config writes always prompt — no LLM.
        human = human_required_reason(tool, tool_input)
        if human:
            return ("ask", human)
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

    The rules are PreToolUse's own (evaluate_bash), so both hooks deny the
    same commands, steer the same rewrites and send the same C9 writes to
    the human. Only the outcome differs: here a rules allow is not an allow
    — the call reached a prompt anyway, so the LLM (or the human) decides.
    The learner adds definite asks for an empty command and for one the
    parser can't read with confidence.
    """
    if not command or not command.strip():
        return ("ask", "Empty command")
    verdict, reason = evaluate_bash(command, log_unknowns=False)
    if verdict == "deny":
        return ("deny", reason)
    human = human_required_reason("Bash", {"command": command})
    if human:
        return ("ask", human)
    if bash_parse_uncertain(command):
        return ("ask", "Ambiguous parse — unbalanced quotes or incomplete heredoc")
    return ("consult", reason)


if __name__ == "__main__":
    main()
