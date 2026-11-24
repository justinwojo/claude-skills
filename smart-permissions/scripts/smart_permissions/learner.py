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
       put to the developer (a confirmed flag, a held call flagged again, a
       developer-only or remote-exec ask) skips the LLM and prompts. Remote
       or production execution is approved only on a confident verdict with
       its whole payload visible.
     - LLM NOT configured → manual prompt.

A call left to the developer waits for their answer at most
prompt_timeout_minutes (default 10, 0 = off; never in `claude -p`): if the
prompt is still unanswered then, the hook denies it with a message that tells
Claude why it needed the developer, not to retry it or work around it, to move
on, and to list it in its final reply for the developer. Never an allow.

Nothing is ever written to the user config: an approval covers this one call.
(The hook keeps its old file name so existing hook registrations still work.)

Every exit path writes a structured decision-log record (C1); the learner's
"ask" records ARE the manual-approval history.
"""

import sys
import json
import os
import time

# Shared logic from the PreToolUse hook (smart_permissions/core.py)
from .core import (
    evaluate_bash,
    evaluate_file_path,
    evaluate_web_fetch,
    bash_parse_uncertain,
    human_required_reason,
    build_llm_context,
    llm_evaluate,
    llm_is_configured,
    llm_not_configured_reason,
    _flag_get,
    remote_exec,
    remote_gap,
    remote_exec_verdict,
    script_hazard,
    scrub_script_text,
    acting_transcript,
    log_decision,
    parse_hook_payload,
    _elapsed_ms,
    _loggable_reason,
    _quietly,
    set_hook_cwd,
    _FAIL_CLOSED,
    CONTEXT_TRANSCRIPT_TAIL_BYTES,
    PROMPT_TIMEOUT_S,
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
            "decision": {"behavior": "deny", "message": message, "interrupt": False},
        }
    }))


# ── An unanswered prompt ────────────────────────────────────────────────────
# Claude Code shows the permission dialog while this hook still runs: the
# developer's answer applies at once and a later hook decision is ignored;
# with no answer, the hook's deny closes the dialog and Claude reads its
# message as the tool error and carries on (Claude Code 2.1.328). So a call
# left to the developer waits PROMPT_TIMEOUT_S (config prompt_timeout_minutes)
# and is then denied with a message that parks it: the session moves on to
# other work instead of freezing until the developer returns. Never an allow.

def _sleep(seconds):
    time.sleep(seconds)


def _unattended():
    """True in a run nobody watches: `claude -p` sets
    CLAUDE_CODE_SESSION_ATTENDED=0 (and the sdk-cli entrypoint), and denies
    a prompt there itself."""
    attended = os.environ.get("CLAUDE_CODE_SESSION_ATTENDED")
    if attended is not None:
        return attended.strip() == "0"
    return os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk")


def parked_message(reason, minutes):
    """The deny text Claude reads when the developer left the prompt unanswered."""
    why = " ".join(str(reason or "it needs the developer's decision").split()).rstrip(".")
    return (f"smart-permissions: this call needed the developer, who did not answer the "
            f"permission prompt within {minutes:g} minutes, so it was denied for now. This is "
            f"not a judgment that it is wrong. Why it could not be auto-approved: {why}. "
            "Do not retry it, and do not route around the restriction with an equivalent "
            "command, another tool or a script. Move on to other work that does not depend on "
            "it, and leave this item until the developer returns: list it in your final reply "
            "under \"Parked for the developer\", with the exact call, what it was for, and the "
            "reason above.")


def _prompt_answered(input_data):
    """True when the acting agent's transcript already holds the result of
    this call (every tool_use with its name and input has one: the prompt
    has no id to tell identical calls apart): the developer answered, and
    Claude Code ignores a later hook decision. False when it does not, or
    can't be read."""
    path = acting_transcript(input_data)
    name, call = input_data.get("tool_name"), input_data.get("tool_input")
    if not path or not isinstance(name, str):
        return False
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            start = max(0, f.tell() - CONTEXT_TRANSCRIPT_TAIL_BYTES)
            f.seek(start)
            lines = f.read().decode("utf-8", "replace").splitlines()[1 if start else 0:]
    except (OSError, ValueError):
        return False
    calls, results = [], set()
    for line in lines:
        if '"tool_use"' not in line and '"tool_result"' not in line:
            continue
        try:
            rec = json.loads(line)
            content = rec["message"]["content"]
        except (ValueError, KeyError, TypeError):
            continue
        for block in content if isinstance(content, list) else ():
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_use" and block.get("name") == name \
                    and block.get("input") == call:
                calls.append(block.get("id"))
            elif block.get("type") == "tool_result":
                results.add(block.get("tool_use_id"))
    return bool(calls) and all(c in results for c in calls)


def _developer_prompt(input_data, tool, tool_input, reason, start, rule_reason):
    """Leave the call to the developer's prompt (the ask is logged already).
    With a prompt timeout, in a session someone attends: wait out the rest
    of it in one sleep, then deny with parked_message, unless the developer
    answered or Claude Code is gone."""
    if PROMPT_TIMEOUT_S <= 0 or _unattended():
        sys.exit(0)
    parent = os.getppid()
    remaining = PROMPT_TIMEOUT_S - (time.monotonic() - start)
    if remaining > 0:
        _sleep(remaining)
    if os.getppid() != parent or _prompt_answered(input_data):
        sys.exit(0)
    minutes = PROMPT_TIMEOUT_S / 60
    log_decision("permission_request", tool, tool_input, "deny", "prompt-timeout",
                 f"No answer to the prompt within {minutes:g} min; denied and parked for the "
                 f"developer ({_loggable_reason(reason)})",
                 duration_ms=_elapsed_ms(start), rule_reason=rule_reason, hold="prompt-timeout")
    try:
        _emit_deny(parked_message(scrub_script_text(reason), minutes))
        sys.stdout.flush()
    except (BrokenPipeError, OSError):  # Claude Code stopped listening
        pass
    sys.exit(0)


def main():
    """The hook. Any failure inside (a RecursionError on a deeply nested
    command, a parser bug) falls through to the normal permission prompt:
    never an allow, never a crash with no verdict."""
    try:
        _main()
    except Exception as e:
        try:
            log_decision("permission_request", "", {}, "ask", "learner",
                         f"smart-permissions could not evaluate this call ({type(e).__name__})",
                         rule_reason="hook error")
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
                     "Could not parse hook input", duration_ms=_elapsed_ms(start),
                     rule_reason="malformed hook input")
        sys.exit(0)

    if not isinstance(input_data, dict):
        input_data = {}
    # their-M2: a JSON null tool_input must not crash the hook — coerced to {}.
    tool, tool_input = parse_hook_payload(input_data)

    set_hook_cwd(input_data)
    # The built-in question tool (this exact name; an MCP tool ending in
    # it is an ordinary tool): its prompt is the question itself, so no
    # decision and no judge
    if tool == "AskUserQuestion":
        log_decision("permission_request", tool, tool_input, "ask", "learner",
                     "AskUserQuestion is answered by the human", duration_ms=_elapsed_ms(start),
                     rule_reason="built-in question tool")
        sys.exit(0)
    verdict, reason = classify_request(tool, tool_input)

    if verdict == "deny":
        log_decision("permission_request", tool, tool_input, "deny", "learner",
                     reason, duration_ms=_elapsed_ms(start), rule_reason=reason)
        # The reason says what to do instead (a steer's rewrite, or the
        # alternative to a blocked pattern), as PreToolUse shows it.
        _emit_deny(reason)
        return

    # A definite ask (C9 config write, empty/ambiguous), or nothing to consult:
    # without an LLM every call the rules could not settle goes to the human.
    flagged = _flag_get(tool, tool_input) if verdict != "ask" else None
    if verdict == "ask" or not llm_is_configured() and not flagged:
        shown = reason if verdict == "ask" else llm_not_configured_reason()
        log_decision("permission_request", tool, tool_input, "ask", "learner",
                     shown, duration_ms=_elapsed_ms(start), rule_reason=reason)
        _developer_prompt(input_data, tool, tool_input, shown, start, reason)

    # verdict == "consult": lean on the LLM, human as last resort.
    # PreToolUse already ran both LLM passes on this exact call and
    # confirmed a flag — this prompt is the human decision it asked for.
    # PreToolUse put it to the developer explicitly (a confirmed flag, a held
    # call flagged again, a developer-only or remote-exec ask): never overrule
    # that here. The prompt has no tool_use_id, so the store is keyed by the
    # call itself.
    if flagged:
        log_decision("permission_request", tool, tool_input, "ask", "llm-recheck",
                     flagged, duration_ms=_elapsed_ms(start), rule_reason=reason)
        _developer_prompt(input_data, tool, tool_input, flagged, start, reason)
    remote = remote_exec(tool_input.get("command", "")) if tool == "Bash" else None
    gap = remote and remote_gap(tool_input.get("command"), remote)
    # …or in a local shell script the call runs
    in_script, script_gap, _destroy = (_quietly(script_hazard, tool_input.get("command", ""))
                                       if tool == "Bash" else None) or (None, None, None)
    if script_gap and not gap:
        remote, gap = in_script, script_gap
    remote = remote or in_script
    if gap:  # a payload the judge can't see: the developer's, no judge call
        shown = f"Remote or production execution ({remote}): {gap}"
        log_decision("permission_request", tool, tool_input, "ask", "rule",
                     shown, duration_ms=_elapsed_ms(start), rule_reason=reason)
        _developer_prompt(input_data, tool, tool_input, shown, start, reason)
    decision, llm_reason, info = llm_evaluate(
        tool, tool_input, timeout=15, context=build_llm_context(input_data),
        rule_reason=reason)
    source = info["source"]
    llm_ms = info.get("llm_ms")
    if remote:  # the same strict policy as PreToolUse: confident, payload visible
        decision, llm_reason, _ = remote_exec_verdict(decision, llm_reason, info, remote)
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
    _developer_prompt(input_data, tool, tool_input, llm_reason, start, reason)


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
