#!/usr/bin/env python3
"""
Claude Code PermissionRequest hook — self-learning permission approval.

This hook fires when a permission dialog is about to be shown (meaning
PreToolUse returned "ask" and no built-in rule matched). It:

  1. Re-checks dangerous/risky patterns as a safety net
  2. If the command is just "unknown" (not dangerous/risky):
     → Auto-approves the tool call
     → Learns the command/path/domain into the user's config file
  3. If the command is dangerous → denies
  4. If the command is risky → lets the normal prompt show

This creates a self-learning cycle: the first time an unknown-but-safe
command runs, it gets auto-approved and added to the config. Next time,
PreToolUse handles it directly without reaching this hook.
"""

import sys
import json
import os

# Import shared logic from pretool-safety.py (same directory)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pretool_safety import (  # noqa: E402
    DANGEROUS_PATTERNS,
    RISKY_PATTERNS,
    INTERPRETER_EXEC_FLAGS,
    SAFE_COMMANDS,
    evaluate_file_path,
    evaluate_web_fetch,
    split_compound_command,
    merge_case_blocks,
    get_first_command_word,
    get_function_definition_name,
    _is_destructive_rm,
    _auto_learn,
    learn_to_config,
    _contains_case_start,
    _extract_function_body,
    _extract_case_arm_bodies,
    _check_inner_commands,
)
import re


def main():
    try:
        input_data = json.loads(sys.stdin.read())
    except json.JSONDecodeError:
        # Can't parse — let normal prompt show
        sys.exit(0)

    tool = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    decision = evaluate_for_learning(tool, tool_input)

    if decision == "allow":
        _auto_learn(tool, tool_input)
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "allow",
                }
            }
        }
        print(json.dumps(output))
    elif decision == "deny":
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": "Blocked by safety hook"
                }
            }
        }
        print(json.dumps(output))
    else:
        # "ask" — exit cleanly to let the normal permission prompt show
        sys.exit(0)


def evaluate_for_learning(tool, tool_input):
    """Decide whether to auto-approve and learn, deny, or show the prompt.

    This is a lighter check than PreToolUse — we only need to verify the
    command isn't dangerous/risky. If it's just unknown, we approve + learn.
    """
    if tool == "Bash":
        return evaluate_bash_for_learning(tool_input.get("command", ""))

    if tool in ("Write", "Edit", "NotebookEdit"):
        path = tool_input.get("file_path", "") or tool_input.get("notebook_path", "")
        result, _ = evaluate_file_path(path)
        if result == "deny":
            return "deny"
        # Only auto-approve and learn writes under the home directory or
        # temp dirs — system paths like /etc/ should still prompt the user
        normalized = os.path.realpath(os.path.expanduser(path))
        home = os.path.expanduser("~")
        if (normalized.startswith(home + os.sep)
                or normalized.startswith("/tmp/")
                or normalized.startswith("/private/tmp/")):
            return "allow"
        return "ask"  # System paths should not be auto-learned

    if tool == "WebFetch":
        result, _ = evaluate_web_fetch(tool_input)
        if result == "deny":
            return "deny"
        return "allow"

    # For any other tool type that reached here, let the prompt show
    return "ask"


def evaluate_bash_for_learning(command):
    """Check if a bash command is safe enough to auto-approve and learn."""
    if not command or not command.strip():
        return "ask"

    # Dangerous patterns — deny (safety net, should have been caught by PreToolUse)
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, command):
            return "deny"

    if _is_destructive_rm(command):
        return "deny"

    # Risky patterns — let the user decide
    for pattern in RISKY_PATTERNS:
        if re.search(pattern, command):
            return "ask"

    # Split compound command and check each part
    commands, parse_uncertain = split_compound_command(command)
    commands = merge_case_blocks(commands)

    if not commands or parse_uncertain:
        return "ask"

    # Collect defined functions so _check_inner_commands can trust calls to them
    defined_functions = set()
    for cmd in commands:
        func_name = get_function_definition_name(cmd)
        if func_name:
            defined_functions.add(func_name)

    # Check each sub-command, including compound block bodies
    for cmd in commands:
        # Function definitions — check body for unsafe inner commands
        if get_function_definition_name(cmd):
            body = _extract_function_body(cmd)
            if body:
                inner_result = _check_inner_commands(body, defined_functions)
                if inner_result:
                    decision, _ = inner_result
                    if decision == "deny":
                        return "deny"
                    return "ask"  # any non-allow from inner check → prompt
            continue

        # Case blocks — check arm bodies
        if _contains_case_start(cmd):
            arm_bodies = _extract_case_arm_bodies(cmd)
            for arm_body in arm_bodies:
                inner_result = _check_inner_commands(arm_body, defined_functions)
                if inner_result:
                    decision, _ = inner_result
                    if decision == "deny":
                        return "deny"
                    return "ask"
            continue

        # Regular commands — check interpreter exec flags
        first_word = get_first_command_word(cmd)
        if first_word:
            basename = os.path.basename(first_word)
            exec_flags = INTERPRETER_EXEC_FLAGS.get(basename)
            if exec_flags:
                tokens = cmd.split()
                # Strip quotes so bash "-c" and bash $'-c' are caught
                stripped = set()
                for t in tokens[1:]:
                    if t.startswith("$'") and t.endswith("'"):
                        stripped.add(t[2:-1])
                    else:
                        stripped.add(t.strip("'\""))
                if exec_flags & stripped:
                    return "ask"

    # If we got here, the command is just unknown — safe to approve and learn
    return "allow"


if __name__ == "__main__":
    main()
