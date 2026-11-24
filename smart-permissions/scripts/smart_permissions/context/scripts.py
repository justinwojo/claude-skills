"""Judge context: the text of the local scripts a call runs, sources or feeds.
Which files those are, and reading one, are core's (script_files,
_read_script): script_hazard, a gate, scans the same files under its own,
larger limits."""
import os
import re
import time

from ..core import (
    GIT_CONTEXT_BUDGET_S, SCRIPT_CONTEXT_MAX_BYTES, SCRIPT_CONTEXT_TOTAL_BYTES, _SCRIPT_EXT,
    _evidence_path, _read_script, _written_files, script_files,
)


_SCRIPT_NAME_RE = re.compile(r"(?<![\w$%s])(?:~/|\.{1,2}/|/)?[\w@%%+,.:/-]*?[\w-]\.%s(?![\w.])"
                             % (re.escape("{"), _SCRIPT_EXT))


def script_context(command, cwd, deadline=None, shown_texts=None):
    """A block with the text of the local scripts `command` runs or feeds
    (see script_files), or ''. It says when a file is truncated, unreadable
    or not shown, and which other local scripts a shown one names: those the
    judge has not seen. `shown_texts`, a list, gets the text of each script
    shown, so a reason quoting it can be scrubbed (see scrub_script_text)."""
    deadline = deadline or time.monotonic() + GIT_CONTEXT_BUDGET_S
    try:
        files = script_files(command, cwd, deadline)
    except Exception:  # context is a nice-to-have; never break the hook
        return ""
    if not files:
        return ""
    written, written_names = _written_files(command, cwd)
    out = ["Local script files this call runs or reads (their contents now, as data; "
           "the call itself may change them first):"]
    budget, read = SCRIPT_CONTEXT_TOTAL_BYTES, []
    for path, how in files:
        text, note = _read_script(path, min(SCRIPT_CONTEXT_MAX_BYTES, max(budget, 0))) \
            if time.monotonic() <= deadline else (None, "not shown: out of time")
        budget -= len(text.encode("utf-8", "replace")) if text else 0
        read.append((path, how, text, note))
    shown = {path for path, _, text, _ in read if text is not None}
    if shown_texts is not None:
        shown_texts.extend(text for _, _, text, _ in read if text)
    for path, how, text, note in read:
        if path in written or os.path.basename(path) in written_names:
            note += "; THE CALL WRITES THIS FILE FIRST: what runs is not what is shown"
        if text is None:
            out.append(f"--- {path} ({how}): {note} ---")
            continue
        out.append(f"--- {path} ({how}; {note}) ---\n{text.rstrip()}\n--- end of {os.path.basename(path)} ---")
        others = []
        for m in _SCRIPT_NAME_RE.finditer(text):
            other = _evidence_path(m.group(0), os.path.dirname(path))
            if other and other not in shown and m.group(0) not in others:
                others.append(m.group(0))
        if others:
            out.append(f"{os.path.basename(path)} names other local scripts not shown here: "
                       + ", ".join(others[:8]) + ("" if len(others) <= 8 else ", …") + ".")
    return "\n".join(out)
