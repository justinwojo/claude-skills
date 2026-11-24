"""Normalizing a hook payload: other agent CLIs that load Claude Code hooks
send their own tool names and camelCase keys; parse_hook_payload maps them to
the Claude Code tool with the same semantics. It imports nothing from this
package."""


# ============================================================
# HOOK PAYLOAD NORMALIZATION (other agent CLIs)
# ============================================================
# Other agent CLIs that load Claude Code hooks (e.g. the Grok CLI) send their
# own tool names, and sometimes camelCase payload keys. Without a mapping
# every one of their calls is an "Unknown tool" and goes to the LLM — which
# was the bulk of LLM traffic. Map each to the Claude tool with the same
# semantics so the same rules apply. Names that are purely agent-internal
# (todo lists, polling a background task) live in safe_internal_tools.
_FOREIGN_TOOL_ALIASES = {
    "run_terminal_command": "Bash",
    "run_command": "Bash",
    "read_file": "Read",
    "grep": "Grep",
    "list_dir": "Glob",
    "glob": "Glob",
    "web_search": "WebSearch",
    "web_fetch": "WebFetch",
    "spawn_subagent": "Task",
}
# File-mutating aliases: Edit if the call carries old/new strings, else Write.
_FOREIGN_FILE_TOOLS = frozenset({"search_replace", "write", "write_file",
                                  "create_file", "edit_file", "str_replace"})


def parse_hook_payload(input_data):
    """Return (tool, tool_input, client_tool) from a hook payload, normalized
    to Claude Code tool names and input keys. Accepts snake_case or camelCase
    keys; a non-dict tool_input (JSON null, etc.) is coerced to {}.
    `client_tool` is the client's own tool name when it was mapped (the
    decision log keeps it), else None."""
    if not isinstance(input_data, dict):
        return "", {}, None
    tool = input_data.get("tool_name") or input_data.get("toolName") or ""
    if not isinstance(tool, str):
        tool = ""
    tool_input = input_data.get("tool_input")
    if tool_input is None:
        tool_input = input_data.get("toolInput")
    if not isinstance(tool_input, dict):
        tool_input = {}

    mapped = _FOREIGN_TOOL_ALIASES.get(tool)
    if mapped is None and tool in _FOREIGN_FILE_TOOLS:
        mapped = "Edit" if "old_string" in tool_input or "old_str" in tool_input else "Write"
    if mapped is None:
        return tool, tool_input, None

    client_tool = tool
    tool_input = dict(tool_input)
    if mapped in ("Edit", "Write", "Read") and not tool_input.get("file_path"):
        for key in ("target_file", "path", "filePath", "file"):
            if isinstance(tool_input.get(key), str) and tool_input[key]:
                tool_input["file_path"] = tool_input[key]
                break
    if mapped == "Bash" and not isinstance(tool_input.get("command"), str):
        tool_input["command"] = str(tool_input.get("cmd") or "")
    return mapped, tool_input, client_tool
