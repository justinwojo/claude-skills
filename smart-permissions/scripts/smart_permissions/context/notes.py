"""Short judge-context notes: a subagent's brief, whether a /tmp folder is
private, the configured notes for an MCP tool, and which copy of the guard
is live."""
import json
import os
import re
from fnmatch import fnmatch

from ..config import MCP_CONTEXT, PLUGIN_ROOT
from ..transcript import _SYSTEM_REMINDER_RE
from ..core import _temp_top
from ..util import one_line


# ── Judge context: a subagent's brief, local scripts, stashes, /tmp, MCP ──
# Evidence only: none of it changes a rule's verdict, and none of it is
# written to the decision log (log_decision records the tool input alone).

# A subagent's brief: its first message, head and tail kept when long.
CONTEXT_BRIEF_CHARS = 4000
CONTEXT_BRIEF_TAIL_CHARS = 1000
CONTEXT_BRIEF_HEAD_BYTES = 1024 * 1024


def subagent_brief(path, limit=CONTEXT_BRIEF_CHARS):
    """The task prompt a subagent works from (the first user message of its
    transcript at `path`), capped at `limit` characters, or None. Its first
    message is written by the agent that started it, never a tool result.
    Never raises."""
    try:
        return _subagent_brief(path, limit)
    except Exception:  # a malformed transcript is no brief; never break the hook
        return None


def _subagent_brief(path, limit):
    if not (isinstance(path, str) and os.path.isabs(path) and os.path.isfile(path)):
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        head = os.read(fd, CONTEXT_BRIEF_HEAD_BYTES)
    finally:
        os.close(fd)
    for line in head.decode("utf-8", "replace").splitlines()[:200]:
        try:
            record = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(record, dict) or record.get("type") != "user" \
                or record.get("isMeta") or record.get("isCompactSummary"):
            continue
        message = record.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, list):
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
                return None
            content = "\n".join(b["text"] for b in content if isinstance(b, dict)
                                and b.get("type") == "text" and isinstance(b.get("text"), str))
        if not isinstance(content, str):
            return None
        text = _SYSTEM_REMINDER_RE.sub("", content).strip()
        if not text:
            return None
        if len(text) > limit:
            tail = CONTEXT_BRIEF_TAIL_CHARS
            text = (text[:limit - tail] + f"\n[… {len(text) - limit} characters left out …]\n"
                    + text[-tail:])
        return text
    return None


# /tmp: a folder there may be private (`/private/tmp/claude-<uid>`, 0700,
# the developer's) or shared and world-writable. Say which.
_TEMP_PATH_RE = re.compile(r"(?<![\w.-])(?:/private)?/tmp/[^\s'\"`;&|<>()$*?\[]+")


def _temp_privacy(top, st):
    """One sentence on who can write into `top`, a folder under /tmp."""
    import stat as _stat
    if _stat.S_ISLNK(st.st_mode):
        return f"{one_line(top)} is a symbolic link."
    if not _stat.S_ISDIR(st.st_mode):
        return None
    mine = hasattr(os, "getuid") and st.st_uid == os.getuid()
    mode = st.st_mode & 0o7777
    owner = "the developer" if mine else f"another user (uid {st.st_uid})"
    if mode & 0o002:
        kind = "world-writable"
    elif mine and not mode & 0o077:
        kind = "private: no other user can read it or create or change anything in it"
    elif mine and not mode & 0o022:
        kind = "no other user can create or change anything in it"
    else:
        kind = "writable by its group" if mode & 0o020 else "not world-writable"
    return f"{one_line(top)} is a folder owned by {owner}, mode {mode:o} ({kind})."


def temp_privacy_context(paths):
    """A block on the folders under /tmp that `paths` are in, or ''."""
    notes, seen = [], set()
    for path in paths:
        found = _temp_top(path)
        if not found or found[0] in seen:
            continue
        seen.add(found[0])
        note = _temp_privacy(*found)
        if note:
            notes.append(f"- {note}")
        if len(notes) >= 3:
            break
    return "Folders under /tmp this call names:\n" + "\n".join(notes) if notes else ""


def _mcp_context_notes(tool):
    """The developer's mcp_context sentences for an MCP tool."""
    notes = []
    for pattern, sentence in MCP_CONTEXT.items():
        if fnmatch(tool, pattern) and sentence not in notes:
            notes.append(sentence)
    return notes[:5]


_HOOK_FILES_RE = re.compile(r"smart-permissions|smart_permissions|pretool_safety|permission_learner")


def live_hook_note(tool_input):
    """A note for the judge when the call touches this plugin's files: which
    copy is the running guard (PLUGIN_ROOT), and that editing another copy
    (a source checkout or worktree) changes nothing until it is installed.
    '' otherwise."""
    try:
        text = json.dumps(tool_input)
    except (TypeError, ValueError):
        text = str(tool_input)
    if not _HOOK_FILES_RE.search(text):
        return ""
    return (f"The smart-permissions guard running now is the copy at {PLUGIN_ROOT}. Editing "
            "another copy of its files (a source checkout or git worktree) does not change the "
            "active guard until that copy is installed; edits to the copy above or to the user's "
            "smart-permissions config do.")
