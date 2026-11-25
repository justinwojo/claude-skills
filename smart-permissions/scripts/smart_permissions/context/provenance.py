"""Judge context on who made a target: this session's own earlier commands
that named the path (session_provenance), earlier calls to the same MCP
server for a command on another machine (remote_provenance), and the
stashes a stash drop or clear would discard (stash_context). Read from the
session's transcripts, the agent's command text only, never tool output."""
import json
import os
import re
import time
import functools
from datetime import datetime

from ..config import HOME_DIR
from ..log import _redact_secrets, _redact_values
from ..transcript import _ts_seconds
from ..core import (
    SCRIPT_CONTEXT_MAX_BYTES, SCRIPT_CONTEXT_MAX_FILES, SCRIPT_CONTEXT_TOTAL_BYTES, _SCRIPT_EXT,
    _commands_words, _comment_lines_dropped, _git_command_dirs, _git_probe, _literal_paths,
    _spell_names, _tilde_masked, split_compound_command,
)
from .git import _git_context_dirs


# ============================================================
# LLM CONTEXT — what a delete or reset would lose, and who made the target
# ============================================================
# A delete or reset that reaches the judge gets two kinds of evidence for each
# folder it targets. Loss: what git knows is there (repositories inside a
# deleted folder, a deleted branch's own commits). Provenance: whether this
# session's own earlier commands made or used the path, and when the folder
# was created. Both are evidence for the judge only; no rule reads them, so
# nothing here can allow a call. Provenance reads the agent's command text and
# never tool output: a file's contents must not be able to vouch for a path.

# Transcript reading for provenance: its share of GIT_CONTEXT_BUDGET_S, and
# how much of each transcript (newest part) and of all of them is read.
PROVENANCE_BUDGET_S = 1.0
PROVENANCE_TAIL_BYTES = 16 * 1024 * 1024
PROVENANCE_TOTAL_BYTES = 48 * 1024 * 1024
PROVENANCE_MAX_FILES = 12
PROVENANCE_MAX_TARGETS = 4
PROVENANCE_SHOW_FIRST = 3
PROVENANCE_SHOW_LAST = 2
PROVENANCE_SNIPPET_CHARS = 240


# An absolute or ~/ path in command text, not the tail of a relative one, of
# a `$NAME/…` left unread, or of a `~` _tilde_masked swapped out (`'~'/x`).
_PATH_MENTION_RE = re.compile(r"(?<![\w.$}~\x04-])(?<!\x04[\"'])(?:~(?=/))?/[\w.@%+,/-]*")
_CD_TARGET_RE = re.compile(r"(?:^|[;&|(\s])(?:cd|pushd)\s+([\"']?)((?:~(?=/)|/)[^\s\"';&|)]*)\1")
_RELATIVE_WORD_RE = re.compile(r"[\w.@%+,-][\w./@%+,-]*")
_TOOL_RESULT_ID_RE = re.compile(r'"tool_use_id"\s*:\s*"([^"]+)"')
_TIMESTAMP_RE = re.compile(r'"timestamp"\s*:\s*"([^"]+)"')


def _local_time(seconds, fmt="%m-%d %H:%M"):
    return datetime.fromtimestamp(seconds).strftime(fmt)


def _span(seconds):
    """A rough length of time: `40 min`, `3 h`, `2 days`."""
    minutes = int(abs(seconds) // 60)
    if minutes < 90:
        return f"{minutes} min"
    if minutes < 48 * 60:
        return f"{minutes // 60} h"
    return f"{minutes // 1440} days"


def _session_transcripts(input_data):
    """This session's transcripts, the main one first: Claude Code keeps each
    subagent's in <session>/subagents/agent-*.jsonl beside it (newest first)."""
    main = input_data.get("transcript_path")
    if not (isinstance(main, str) and os.path.isabs(main) and os.path.isfile(main)):
        return []
    files = [main]
    agent = input_data.get("agent_transcript_path")
    if isinstance(agent, str) and os.path.isabs(agent) and agent != main and os.path.isfile(agent):
        files.append(agent)
    try:
        with os.scandir(os.path.join(os.path.splitext(main)[0], "subagents")) as it:
            subs = [e for e in it if e.name.endswith(".jsonl") and e.is_file(follow_symlinks=False)]
        subs.sort(key=lambda e: e.stat().st_mtime, reverse=True)
        files += [e.path for e in subs if e.path not in files]
    except OSError:
        pass
    return files[:PROVENANCE_MAX_FILES]


def _session_start(path):
    """When the transcript at `path` starts: its first record's timestamp."""
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as f:
            head = f.read(256 * 1024).decode("utf-8", "replace")
    except OSError:
        return None
    for line in head.splitlines():
        m = _TIMESTAMP_RE.search(line)
        if m and _ts_seconds(m[1]):
            return _ts_seconds(m[1])
    return None


def _too_broad(path, cwd):
    """True for a folder too general for naming it to say anything about a
    path under it: /, home and the folders holding it or its children (~/Dev),
    the temp roots and their children, the working directory and up."""
    if path.count("/") < 3 and not path.startswith(("/tmp/", "/private/tmp/")):
        return True
    for root in (HOME_DIR, "/tmp", "/private/tmp", _temp_root()):
        if path == root or root.startswith(path + "/") or os.path.dirname(path) == root:
            return True
    return bool(cwd) and (path == cwd or cwd.startswith(path + "/"))


@functools.lru_cache(maxsize=1)
def _temp_root():
    """The system temp folder, resolved ($TMPDIR on macOS: /var/folders/…/T)."""
    import tempfile
    return os.path.realpath(tempfile.gettempdir())


def _provenance_target(path, label, cwd):
    """What a transcript line must name to count for `path`: the path itself
    or what it resolves to (`keys`), and its parent and grandparent unless
    they are too broad (`parents`); `needles` are their last components, a
    cheap first test on each raw line."""
    keys = {path, os.path.realpath(path)}
    parents = set()
    for key in list(keys):
        p = key
        for _ in range(2):
            p = os.path.dirname(p)
            if _too_broad(p, cwd):
                break
            parents.add(p)
    needles = {os.path.basename(p) for p in keys | parents if os.path.basename(p)}
    return {"path": path, "label": label, "keys": keys, "parents": parents, "needles": needles}


def _named_paths(text, needles):
    """The paths a command's text names: absolute and ~/ ones, with names set
    to one literal path written out, and relative words after a `cd` to an
    absolute folder taken from there (`cd /x && git init -q arms`). Only a
    relative word holding one of `needles` can name a target the `cd` path
    itself doesn't, so only those are joined."""
    text = _spell_names(_tilde_masked(text), _literal_paths(text))
    named = {os.path.normpath(os.path.expanduser(m)) for m in _PATH_MENTION_RE.findall(text)}
    bases = [os.path.expanduser(m[1]) for m in _CD_TARGET_RE.findall(text)]
    if bases:
        words = [w for w in re.split(r"[\s\"'`;&|<>(){}=]+", text)
                 if _RELATIVE_WORD_RE.fullmatch(w) and not w.startswith("-")
                 and any(n in w for n in needles)][:50]
        named.update(os.path.normpath(os.path.join(b, w)) for b in bases[:4] for w in words)
    return named


def _relation(named, target):
    """How a command that names `named` relates to `target`, or None."""
    best = None
    for p in named:
        if p in target["keys"]:
            return "names it", p
        if any(p.startswith(k + "/") for k in target["keys"]):
            best = ("names a path inside it", p)
        elif best is None and p in target["parents"]:
            best = (f"names its folder {os.path.basename(p)}", p)
    return best


def _snippet(text, mark, fold=False):
    """`text` on one line, secrets redacted, cut to a window around the first
    `mark` (`fold`: found without case)."""
    flat = re.sub(r"[ \t]+", " ", re.sub(r"\s*\n\s*", " / ", _redact_secrets(text.strip())[0]))
    if len(flat) <= PROVENANCE_SNIPPET_CHARS:
        return flat
    at = max(0, (flat.lower().find(mark.lower()) if fold else flat.find(mark))) if mark else 0
    # From a little before the word holding the mark, so a long path shows whole.
    word = max(flat.rfind(c, 0, at) for c in " =;'\"")
    start = max(0, min(at - 40, word - 40))
    end = start + PROVENANCE_SNIPPET_CHARS
    return ("…" if start else "") + flat[start:end] + ("…" if end < len(flat) else "")


def _bash_inputs(record):
    """(tool_use id, [command texts]) of each Bash call in an assistant
    record: the command as stored and, when it differs, as the model sent it
    (wireToolInputs, which keeps a leading `cd`)."""
    message = record.get("message") if record.get("type") == "assistant" else None
    content = message.get("content") if isinstance(message, dict) else None
    wire = record.get("wireToolInputs") if isinstance(record.get("wireToolInputs"), dict) else {}
    for block in content if isinstance(content, list) else []:
        if not (isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "Bash"):
            continue
        inp = block.get("input") if isinstance(block.get("input"), dict) else {}
        texts = [inp.get("command")]
        sent = wire.get(block.get("id")) if isinstance(block.get("id"), str) else None
        if isinstance(sent, dict) and sent.get("command") != texts[0]:
            texts.append(sent.get("command"))
        texts = [t for t in texts if isinstance(t, str) and t]
        if texts:
            yield block.get("id"), texts


def _tail_lines(path, limit):
    """(lines of the last `limit` bytes of `path`, bytes read, whether it was cut)."""
    # non-blocking: a path swapped for a FIFO after a type check must not hang the hook
    with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as f:
        f.seek(0, os.SEEK_END)
        start = max(0, f.tell() - limit)
        f.seek(start)
        data = f.read()
    lines = data.decode("utf-8", "replace").splitlines()
    return (lines[1:] if start else lines), len(data), start > 0


def _transcript_matches(files, targets, current, skip_id, deadline,
                        inputs=_bash_inputs, named_paths=_named_paths, mark=None, later=False):
    """({target index: [match]}, whether some transcript wasn't read whole).
    A match is a dict: ts, seq (its order in the reading), snippet,
    relation, status ("ok", "error", "no result" while it has none, "result
    unknown" when a line with its id can't be read), tid. The call being
    judged is never a match: by its tool_use id when the hook input has one,
    else as a call with no result yet whose command, as stored or as sent,
    is identical to it (`current`, or a test `current(tid, texts)`). With
    the id, a call from its time or after (another agent's, in its
    transcript) isn't either, unless it comes before the judged call in the
    same record; `later` keeps those, marked "after". For another machine
    (remote_context), `inputs` and `named_paths` read its calls, a line must
    hold `mark`, and needles (lowercase) match without case.
    Raises OSError when no transcript could be read."""
    fold = (lambda text: text.lower()) if mark else (lambda text: text)
    is_current = current if callable(current) else (lambda tid, texts: current in texts)
    now = None  # when the call being judged was made, once its record is seen
    matches = {i: [] for i in range(len(targets))}
    needles = set().union(*(t["needles"] for t in targets))
    budget, cut, failed, seq = PROVENANCE_TOTAL_BYTES, False, 0, 0

    def earlier(cut):
        def before(m):
            return m.get("before") or not (now and m["ts"] and m["ts"] >= now)
        if later:
            for ms in matches.values():
                for m in ms:
                    m["after"] = not before(m)
            return matches, cut
        return {i: [m for m in ms if before(m)] for i, ms in matches.items()}, cut

    for path in files:
        if budget <= 0 or time.monotonic() > deadline:
            return earlier(True)
        try:
            lines, size, partial = _tail_lines(path, min(PROVENANCE_TAIL_BYTES, budget))
        except OSError:
            failed += 1
            continue
        budget -= size
        cut = cut or partial
        pending = {}  # tool_use id → (its command texts, its matches), until its result
        for line in lines:  # a long record can take a millisecond: the clock, every line
            if time.monotonic() > deadline:
                cut = True
                break
            # A result record holds one result, its id ahead of the output
            # (which may itself quote "tool_use").
            found = pending and '"tool_result"' in line and _TOOL_RESULT_ID_RE.search(line)
            if found and found[1] in pending:
                status = _result_status(line, found[1])
                # Unread, it stays pending: its real result may come later.
                for m in (pending.pop(found[1]) if status else pending[found[1]])[1]:
                    m["status"] = status or "result unknown"
                continue
            if '"tool_use"' not in line or mark and mark not in line \
                    or not any(needle in fold(line) for needle in needles):
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            ts = _ts_seconds(record.get("timestamp") or "")
            in_record = []  # this record's matches so far: before the judged call, if it is here
            for tid, texts in inputs(record):
                if tid and tid == skip_id:
                    now = ts
                    for m in in_record:
                        m["before"] = True
                    continue
                named = [(t, named_paths(t, needles)) for t in texts
                         if any(needle in fold(t) for needle in needles)]
                for i, target in enumerate(targets):
                    hit = next(((t, r) for t, ps in named for r in [_relation(ps, target)] if r), None)
                    if not hit:
                        continue
                    text, (relation, spot) = hit
                    seq += 1
                    m = {"ts": ts, "seq": seq,
                         "snippet": _snippet(text, os.path.basename(spot) or spot, bool(mark)),
                         "relation": relation, "status": "no result", "tid": tid}
                    matches[i].append(m)
                    in_record.append(m)
                    pending.setdefault(tid, (texts, []))[1].append(m)
        # The call under review is in the transcript before it has a result.
        for tid, (texts, ms) in pending.items():
            if not skip_id and is_current(tid, texts):
                drop = {id(m) for m in ms}
                for i in matches:
                    matches[i] = [m for m in matches[i] if id(m) not in drop]
    if files and failed == len(files):
        raise OSError("no transcript could be read")
    return earlier(cut)


def _result_status(line, tid):
    """"error" or "ok" for the tool_result with id `tid` in a raw line, or
    None when the line can't be read as one (cut, or the id only quoted)."""
    try:
        record = json.loads(line)
        content = record.get("message", {}).get("content")
        for block in content if isinstance(content, list) else []:
            if isinstance(block, dict) and block.get("tool_use_id") == tid:
                return "error" if block.get("is_error") else "ok"
    except (ValueError, AttributeError):
        pass
    return None


def session_provenance(input_data, targets, cwd, deadline):
    """(blocks for the LLM, CallState.provenance value) for the targets of
    a delete or reset: when this session's transcript starts, when each
    target folder was created, and the earliest and latest of this session's
    own earlier Bash commands that name it. Never raises; when the
    transcripts can't be read there is no block."""
    try:
        files = _session_transcripts(input_data)
        if not files:
            return [], "unavailable"
        cwd = os.path.normpath(cwd) if isinstance(cwd, str) and os.path.isabs(cwd) else ""
        start = _session_start(files[0])
        chosen, lines, seen = [], [], set()
        for kind, path, label, _ in targets:
            if path in seen:
                continue
            seen.add(path)
            if cwd and (path == cwd or cwd.startswith(path + "/")):
                lines.append(f"{path} ({label}) is the working directory or holds it: no "
                             "provenance is given for it.")
                continue
            chosen.append(_provenance_target(path, label, cwd))
            if len(chosen) >= PROVENANCE_MAX_TARGETS:
                break
        if not chosen:
            return ([_PROVENANCE_HEAD, *lines] if lines else []), "none"
        skip_id = input_data.get("tool_use_id") if isinstance(input_data.get("tool_use_id"), str) else None
        current = (input_data.get("tool_input") or {}).get("command") \
            if isinstance(input_data.get("tool_input"), dict) else None
        matches, cut = _transcript_matches(files, chosen, current, skip_id, deadline)
        found = False
        out = [_PROVENANCE_HEAD]
        if start:
            out.append(f"This session's transcript starts {_local_time(start, '%Y-%m-%d %H:%M')}.")
        for i, target in enumerate(chosen):
            line = f"{target['path']} ({target['label']}): "
            try:
                born = os.stat(target["path"], follow_symlinks=False).st_birthtime
            except AttributeError:
                born = None  # no creation time on this system
            except OSError:
                born, line = None, line + "does not exist now. "
            if born and start:
                when = "after" if born >= start else "before"
                line += f"created {_local_time(born)}, {_span(born - start)} {when} the session started. "
                found = found or born >= start
            elif born:
                line += f"created {_local_time(born, '%Y-%m-%d %H:%M')}. "
            ms = sorted(matches[i], key=lambda m: m["ts"] or 0)
            if not ms:
                line += "No earlier command of this session names it or its folder."
                out.append(line)
                continue
            found = True
            errors = sum(m["status"] == "error" for m in ms)
            line += (f"{len(ms)} earlier command{'s' if len(ms) != 1 else ''} of this session "
                     f"name{'s' if len(ms) == 1 else ''} it, a path inside it or its folder"
                     f"{f' ({errors} ended in an error)' if errors else ''}"
                     f"{'; earliest and latest' if len(ms) > PROVENANCE_SHOW_FIRST + PROVENANCE_SHOW_LAST else ''}:")
            shown = ms if len(ms) <= PROVENANCE_SHOW_FIRST + PROVENANCE_SHOW_LAST \
                else ms[:PROVENANCE_SHOW_FIRST] + [None] + ms[-PROVENANCE_SHOW_LAST:]
            for m in shown:
                if m is None:
                    line += f"\n  […{len(ms) - PROVENANCE_SHOW_FIRST - PROVENANCE_SHOW_LAST} more…]"
                    continue
                when = _local_time(m["ts"]) if m["ts"] else "?"
                line += f"\n  {when} {m['status']}, {m['relation']}: {m['snippet']}"
            out.append(line)
        out.extend(lines)
        if cut:
            out.append("(Only the newest part of the session's transcripts was read: an "
                       "older command may name these paths too.)")
        return out, "found" if found else "none"
    except Exception:
        return [], "unavailable"


_PROVENANCE_HEAD = (
    "Session provenance of the paths this call deletes or resets (evidence, not authorization). "
    "It comes from this session's own earlier Bash commands (command text only, from the main "
    "and subagent transcripts) and from the filesystem's creation times. It shows whether this "
    "session created or used a path. It cannot show that nothing else was put there since, and "
    "it is not the developer's approval.")


# ---- Provenance on another machine: an MCP tool's `command` ----
# Nothing there can be read from here, and its shell is not modelled: the
# judge gets this session's earlier calls to the same server that name a
# path the command names, and reads them itself.

# Whether remote text may delete or reset something: only whether to look.
# Its spans are bounded, so a long command can't make it backtrack for long.
_REMOTE_RESET_HINT_RE = re.compile(
    r"(?i)(?<![\w.-])rm\s+(?:[^\s;|&]{1,200}\s+){0,20}?-(?:[a-z]*r|-recursive)"
    r"|(?<![\w.-])(?:remove-item|ri|rd|rmdir|del|erase)(?:\s[^;|&\n]{0,200}?)?\s(?:-r|/s\b)"
    r"|(?<![\w.-])git\s[^;|&\n]{0,200}?(?:\bworktree\s+remove\b|\breset\s[^;|&\n]{0,100}?--hard\b"
    r"|\bclean(?:\s[^;|&\n]{0,100}?)?\s-[a-z]*f|\bcheckout(?:\s[^;|&\n]{0,100}?)?\s--(?![\w-])"
    r"|\brestore\b)")
# A path, whole: `/…`, `//…`, `~/…`, `C:\…`, `C:/…`, plain characters only
# (no glob, `$`, `=`, comma or bracket); a structured field's may hold spaces.
_REMOTE_PATH_RE = re.compile(r"(?:/|~/)[\w.~+@/-]+|[A-Za-z]:[\\/][\w.~+@\\/-]*", re.A)
_REMOTE_FIELD_RE = re.compile(r"(?:/|~/)[\w.~+@/ -]+|[A-Za-z]:[\\/][\w.~+@\\/ -]*", re.A)
REMOTE_SCAN_CHARS = 16 * 1024  # of a command's text: what is read for paths and the hint
_SPACE_RE = re.compile(r"\s")
_MCP_PATH_KEY_RE = re.compile(r"(?i)path|dir|file|dest|target|src|source")
_REMOTE_STATUS = {"ok": "the tool call returned ok", "error": "the tool call returned an error",
                  "no result": "no result yet", "result unknown": "its result could not be read"}
REMOTE_PROVENANCE_SHOW_FIRST = 2
REMOTE_PROVENANCE_SHOW_LAST = 3
_REMOTE_PROVENANCE_HEAD = (
    "This session's earlier calls to the MCP server {server} (any of its {key}* tools) that name "
    "the paths this call's command names (it may delete or reset something there). The hook "
    "cannot see that machine's files: these are only earlier calls from the main and subagent "
    "transcripts, each with what the tool call returned. Nothing here shows that a command ran "
    "or succeeded, or that nothing else was put there since. It is evidence, not authorization.")


def _remote_norm(path):
    """`path` as compared, or None for a root or a path with `..`: a drive
    path lowercase with `/`, no empty, `.` or trailing segments; a leading
    `//` (a share) kept apart from `/`."""
    if re.match(r"[A-Za-z]:[\\/]", path):
        path = path.replace("\\", "/").lower()
    parts = [s for s in path.split("/") if s not in ("", ".")]
    norm = ("//" if path.startswith("//") else "/" if path.startswith("/") else "") + "/".join(parts)
    if ".." in parts or norm in ("", "/", "//", "~") or re.fullmatch(r"[a-z]:", norm):
        return None
    return norm


def _remote_paths(text):
    """[(as written, normalized)] for the whitespace-separated words of
    `text` that are a path whole (_REMOTE_PATH_RE), bare or in one pair of
    quotes, a `;` after it allowed. A quoted span holding whitespace makes
    its word name nothing; so does a quote left open, for the rest of the
    text, and the last word of a text cut at REMOTE_SCAN_CHARS."""
    if len(text) > REMOTE_SCAN_CHARS:
        text = text[:REMOTE_SCAN_CHARS].rsplit(None, 1)[0] if text[:REMOTE_SCAN_CHARS].split() else ""
    kept, last, quote, at = [], 0, None, 0
    for m in re.finditer(r"['\"]", text):  # quotes paired left to right, as a shell reads them
        if quote is None:
            quote, at = m[0], m.start()
        elif m[0] == quote:
            span = text[at:m.end()]
            kept += [text[last:at], "\x00" if _SPACE_RE.search(span) else span]
            last, quote = m.end(), None
    kept.append(text[last:at] if quote else text[last:])
    found = []
    for word in "".join(kept).split():
        word = word[:-1] if word.endswith(";") else word
        if len(word) > 2 and word[0] in "'\"" and word[-1] == word[0]:
            word = word[1:-1]
        norm = _REMOTE_PATH_RE.fullmatch(word) and _remote_norm(word)
        if norm:
            found.append((word, norm))
    return found


def _mcp_fields(tool_input):
    """[(name, value)] of an MCP input's cwd and path-like string fields."""
    if not isinstance(tool_input, dict):
        return []
    return [(k, v) for k, v in tool_input.items() if isinstance(k, str) and isinstance(v, str) and v
            and k != "command" and (k == "cwd" or _MCP_PATH_KEY_RE.search(k))]


def _mcp_named(tool_input, fields):
    """[(as written, normalized)] for the paths an MCP input names: those in
    its command's text, and each absolute path field (`fields`) whole."""
    command = tool_input.get("command")
    named = _remote_paths(command) if isinstance(command, str) else []
    return named + [(v, _remote_norm(v)) for _, v in fields if _REMOTE_FIELD_RE.fullmatch(v) and _remote_norm(v)]


def _remote_targets(tool, tool_input):
    """(key, [(path, norm)]) for an MCP call whose `command` may delete or
    reset something on another machine (key: its `mcp__<server>__`), up to
    PROVENANCE_MAX_TARGETS paths, the most specific first; else None."""
    command = tool_input.get("command")
    if not (isinstance(command, str) and tool.startswith("mcp__") and tool.count("__") >= 2
            and _REMOTE_RESET_HINT_RE.search(command[:REMOTE_SCAN_CHARS])):
        return None
    cwd = tool_input.get("cwd")
    written = _mcp_named(tool_input, [("cwd", cwd)] if isinstance(cwd, str) else [])
    paths = dict((norm, raw) for raw, norm in reversed(written))
    ranked = sorted(paths, key=lambda n: (-n.count("/"), -len(n)))[:PROVENANCE_MAX_TARGETS]
    return (tool.rsplit("__", 1)[0] + "__", [(paths[n], n) for n in ranked]) if ranked else None


def _remote_reader(key, tool, tool_input):
    """_transcript_matches' readers for the earlier calls to the same MCP
    server (any of its tools): their texts, the paths they name, and whether
    a pending one is this call (the same input); `calls` maps an id to the
    tool name and input."""
    named, calls = {}, {}

    def inputs(record):
        message = record.get("message") if record.get("type") == "assistant" else None
        content = message.get("content") if isinstance(message, dict) else None
        for block in content if isinstance(content, list) else []:
            name = block.get("name") if isinstance(block, dict) and block.get("type") == "tool_use" else None
            if not (isinstance(name, str) and name.startswith(key) and "__" not in name[len(key):]):
                continue
            inp = block.get("input") if isinstance(block.get("input"), dict) else {}
            shown = _redact_values(inp)  # shown to the judge: field by field, as the log
            command = shown.get("command") if isinstance(shown.get("command"), str) else ""
            text = command + "".join(f"  ({'; '.join(f'{k}: {v}' for k, v in fields)})"
                                     for fields in [_mcp_fields(shown)] if fields)
            named[text] = {n for _, n in _mcp_named(inp, _mcp_fields(inp))}
            calls[block.get("id")] = (name, inp)
            yield block.get("id"), [text]

    return {"inputs": inputs, "named_paths": lambda text, _needles: named.get(text, set()),
            "current": lambda tid, _texts: calls.get(tid) == (tool, tool_input), "calls": calls}


def remote_provenance(input_data, tool, tool_input, deadline):
    """(blocks for the LLM, CallState.provenance value) for an MCP call
    that may delete or reset something on another machine (_remote_targets):
    remote_context's provenance part. ([], None) when it is no such call."""
    return remote_context(input_data, tool, tool_input, deadline)[:2]


def remote_context(input_data, tool, tool_input, deadline, shown_texts=None):
    """(provenance blocks, CallState.provenance value, script blocks,
    CallState.remote_scripts value) for an MCP call that runs a `command`
    on another machine, from one reading of this session's transcripts:
    - when it may delete or reset something there (_remote_targets), per
      path its command names, the first and last of this session's earlier
      calls to that server that name it or a path inside it, with what each
      tool call returned;
    - when it names script files there (_remote_scripts), the text this
      session wrote to each through that server's write tool
      (_remote_script_blocks; `shown_texts`, a list, gets each text shown).
    A part is ([], None) when the call is not its kind. Never raises."""
    none = ([], None, [], None)
    try:
        if time.monotonic() > deadline or not isinstance(tool, str) or not isinstance(tool_input, dict):
            return none
        found, scripts = _remote_targets(tool, tool_input), _remote_scripts(tool, tool_input)
        if not found and not scripts:
            return none
    except Exception:
        return none
    unavailable = ([], "unavailable" if found else None, [], "unavailable" if scripts else None)
    try:
        files = _session_transcripts(input_data)
        if not files or time.monotonic() > deadline:
            return unavailable
        key = tool.rsplit("__", 1)[0] + "__"
        paths = found[1] if found else []
        targets = [{"path": raw, "keys": {norm}, "parents": set(),
                    "needles": {norm.rsplit("/", 1)[-1].lower()}} for raw, norm in paths]
        for raw, norm in scripts:  # a call naming its folder may have replaced it too
            folder = norm.rsplit("/", 1)[0]
            parents = {folder} if folder.count("/") >= 3 else set()
            targets.append({"path": raw, "keys": {norm}, "parents": parents,
                            "needles": {p.rsplit("/", 1)[-1].lower() for p in parents | {norm}}})
        skip_id = input_data.get("tool_use_id") if isinstance(input_data.get("tool_use_id"), str) else None
        reader = _remote_reader(key, tool, tool_input)
        matches, cut = _transcript_matches(
            files, targets, reader["current"], skip_id, deadline, inputs=reader["inputs"],
            named_paths=reader["named_paths"], mark=f'"{key}', later=True)
    except Exception:
        return unavailable
    prov, prov_status, script, script_status = none
    n = len(paths)
    if found:
        try:
            prov, prov_status = _remote_provenance_blocks(
                key, targets[:n], [[m for m in matches[i] if not m["after"]] for i in range(n)],
                reader["calls"], cut)
        except Exception:
            prov, prov_status = [], "unavailable"
    if scripts:
        try:
            script, script_status = _remote_script_blocks(
                key, tool_input, targets[n:], [matches[i] for i in range(n, len(targets))],
                reader["calls"], cut, shown_texts)
        except Exception:
            script, script_status = [], "unavailable"
    return prov, prov_status, script, script_status


def _remote_provenance_blocks(key, targets, matches, calls, cut):
    """remote_context's provenance part, from the earlier calls matched to
    each of its targets."""
    out, found = [_REMOTE_PROVENANCE_HEAD.format(server=key[5:-2], key=key)], False
    show = REMOTE_PROVENANCE_SHOW_FIRST + REMOTE_PROVENANCE_SHOW_LAST
    for target, ms in zip(targets, matches):
        ms = sorted(ms, key=lambda m: m["ts"] or 0)
        if not ms:
            out.append(f"{target['path']}: no earlier call of this session there names it "
                       "or a path inside it.")
            continue
        found = True
        line = (f"{target['path']}: {len(ms)} earlier call{'s' if len(ms) != 1 else ''} "
                f"name{'s' if len(ms) == 1 else ''} it or a path inside it"
                f"{'; the first and last' if len(ms) > show else ''}:")
        shown = ms if len(ms) <= show else \
            ms[:REMOTE_PROVENANCE_SHOW_FIRST] + [None] + ms[-REMOTE_PROVENANCE_SHOW_LAST:]
        for m in shown:
            line += f"\n  […{len(ms) - show} more…]" if m is None else "\n  " + _remote_call_line(m, key, calls)
        out.append(line)
    if cut:
        out.append("(Only the newest part of the session's transcripts was read: an "
                   "older call may name these paths too.)")
    return out, "found" if found else "none"


def _remote_call_line(m, key, calls):
    """One call to the server: when, what the tool call returned, how it
    names the path, the tool and its redacted text."""
    when = _local_time(m["ts"]) if m["ts"] else "?"
    return (f"{when} {_REMOTE_STATUS.get(m['status'], m['status'])}, {m['relation']}, "
            f"{_tool_suffix(m, key, calls)}: {m['snippet']}")


def _tool_suffix(m, key, calls):
    """The name of a matched call's tool after the server's `mcp__<server>__`."""
    return calls.get(m["tid"], (key,))[0][len(key):]


# ---- Scripts on another machine: what this session wrote there ----
# An MCP command that runs a script file there (`powershell -File C:\…\x.ps1`)
# gets the text this session wrote to that exact path through the same
# server's write tool: the write call's input, never the file read back or a
# tool's output. A later call there that names the path or its folder may
# have changed the file: the judge is told which, and reads them.

_REMOTE_SCRIPT_RE = re.compile(r"\.%s$" % _SCRIPT_EXT, re.I)
# A server's tool that writes a file whole, or appends to it with `append`:
# its name after `mcp__<server>__`, and the input fields with the path and text.
_REMOTE_WRITE_TOOL_RE = re.compile(r"(?i)(?:write|create|put|save)(?:_?file)?")
_REMOTE_WRITE_PATH_KEYS = ("path", "file_path", "filepath", "file", "filename")
_REMOTE_WRITE_TEXT_KEYS = ("content", "contents")
# A later call to a tool that only reads can't have changed the file.
_REMOTE_READ_TOOL_RE = re.compile(r"(?i)(?:read|list|stat)(?:_\w*)?")
REMOTE_SCRIPT_SHOW_LATER = 3
_REMOTE_SCRIPT_HEAD = (
    "Script files this call's command names on the machine behind the MCP server {server}, as this "
    "session wrote them there through its {key}* write tool. Each text is the write calls' input "
    "from the main and subagent transcripts (redacted like the decision log), not the file read "
    "back: the hook cannot see that machine. It is what the call runs if nothing changed the file "
    "since: the note under each says whether a later call of this session there may have, and "
    "something outside this session still could have. Judge it as part of the call. A script the "
    "command names that is not shown here is unseen.")


def _remote_scripts(tool, tool_input):
    """[(as written, normalized)] for the script files (_SCRIPT_EXT) that an
    MCP call with a `command` names in its command's text or its path fields
    (_mcp_named), at most SCRIPT_CONTEXT_MAX_FILES; [] for any other call."""
    if not (isinstance(tool_input.get("command"), str) and tool.startswith("mcp__")
            and tool.count("__") >= 2):
        return []
    found = []
    for raw, norm in _mcp_named(tool_input, _mcp_fields(tool_input)):
        if _REMOTE_SCRIPT_RE.search(norm) and norm not in (n for _, n in found):
            found.append((raw, norm))
    return found[:SCRIPT_CONTEXT_MAX_FILES]


def _remote_write(name, inp, norm):
    """(text, appended) when a call to the tool `name` (its name after the
    server's prefix) with input `inp` writes the file `norm`, else None."""
    if not (isinstance(inp, dict) and _REMOTE_WRITE_TOOL_RE.fullmatch(name)):
        return None
    path = next((inp[k] for k in _REMOTE_WRITE_PATH_KEYS if isinstance(inp.get(k), str)), None)
    text = next((inp[k] for k in _REMOTE_WRITE_TEXT_KEYS if isinstance(inp.get(k), str)), None)
    if path is None or text is None or _remote_norm(path) != norm:
        return None
    return text, inp.get("append") in (True, "true")


def _remote_script_blocks(key, tool_input, targets, matches, calls, cut, shown_texts):
    """(blocks, CallState.remote_scripts value) for remote_context's script
    files: per file, the text of this session's latest whole write to it
    before this call with the appends after that, bounded and redacted like
    script_context, and which later calls there name it or its folder. No
    block when this session wrote none of them ("none"); "found" when it
    wrote one but no text could be shown, else "shown"."""
    server, command = key[5:-2], tool_input.get("command")
    out = [_REMOTE_SCRIPT_HEAD.format(server=server, key=key)]
    budget, written_any, shown = SCRIPT_CONTEXT_TOTAL_BYTES, False, 0
    for target, ms in zip(targets, matches):
        norm = next(iter(target["keys"]))
        ms = sorted(ms, key=lambda m: (m["ts"] or 0, m["seq"]))
        writes = [(m, *w) for m in ms if not m["after"]
                  for w in [_remote_write(_tool_suffix(m, key, calls), calls.get(m["tid"], ("", None))[1], norm)]
                  if w]
        if not writes:
            out.append(f"--- {target['path']}: this session wrote nothing to it through {server}: "
                       "not shown ---")
            continue
        written_any = True
        full = [i for i, (_, _, appended) in enumerate(writes) if not appended]
        chain = writes[full[-1]:] if full else writes
        in_chain = {id(m) for m, _, _ in chain}
        later = [m for m in ms if m["seq"] > chain[0][0]["seq"] and id(m) not in in_chain
                 and not _REMOTE_READ_TOOL_RE.fullmatch(_tool_suffix(m, key, calls))
                 # an earlier try of this same command runs the text shown
                 and not (isinstance(command, str)
                          and (calls.get(m["tid"], ("", {}))[1] or {}).get("command") == command)]
        first, last = chain[0][0], chain[-1][0]
        appends, writer = len(chain) - (1 if full else 0), _tool_suffix(first, key, calls)
        times = f"{appends} time{'s' if appends != 1 else ''}" + (
            f", the last {_local_time(last['ts'])}" if last["ts"] else "")
        if full:
            how = f"written {_local_time(first['ts']) if first['ts'] else '?'} by {writer}" \
                  + (f", then appended to {times}" if appends else "")
        else:
            how = (f"appended to {times} by {writer}; never written whole in this session: "
                   "what it held before is not known")
        odd = sorted({m["status"] for m, _, _ in chain} - {"ok"})
        if odd:
            how += "; " + ", ".join(f"a write: {_REMOTE_STATUS.get(s, s)}" for s in odd) \
                   + ", so the file may not hold this text"
        text = _redact_secrets("".join(t for _, t, _ in chain))[0]
        data = text.encode("utf-8", "replace")
        limit = min(SCRIPT_CONTEXT_MAX_BYTES, max(budget, 0))
        base = re.split(r"[\\/]", target["path"])[-1]
        if "\0" in text:
            out.append(f"--- {target['path']} ({how}): binary text, not shown ---")
        elif limit <= 0:
            out.append(f"--- {target['path']} ({how}): not shown: the script text budget is used up ---")
        else:
            note = f"{len(data)} bytes"
            if len(data) > limit:
                data, note = data[:limit], note + f"; TRUNCATED: only the first {limit} bytes are shown"
            body = data.decode("utf-8", "ignore")
            budget -= len(data)
            shown += 1
            if shown_texts is not None:
                shown_texts.append(body)
            out.append(f"--- {target['path']} ({how}; {note}) ---\n{body.rstrip()}\n--- end of {base} ---")
        if not later:
            out.append(f"{base}: no later call of this session to {server} names this path or its folder.")
            continue
        more = len(later) > REMOTE_SCRIPT_SHOW_LATER
        out.append(f"{base}: {len(later)} later call{'s' if len(later) != 1 else ''} of this session to "
                   f"{server} name{'s' if len(later) == 1 else ''} this path or its folder, so the file "
                   "may not hold what is shown (the hook can't tell: read "
                   f"{'the last ' + str(REMOTE_SCRIPT_SHOW_LATER) if more else 'them'}):"
                   + "".join("\n  " + _remote_call_line(m, key, calls)
                             + (" (made after this call)" if m["after"] else "")
                             for m in later[-REMOTE_SCRIPT_SHOW_LATER:]))
    if not written_any:
        return [], "none"
    if cut:
        out.append("(Only the newest part of the session's transcripts was read: an older call may "
                   "have written these files too.)")
    return ["\n".join(out)], "shown" if shown else "found"


# `git stash drop/clear/pop`: the stashes, when each was made against this
# session's start, and whether this session's own commands made one there.
_STASH_DISCARD_RE = re.compile(r"\bgit\b[^\n;&|]*?\bstash(?:\s+-\S+)*\s+(?:drop|clear|pop)\b")
STASH_CONTEXT_MAX = 10


def _makes_stash(text):
    """True when a command of `text` is `git … stash` that makes one: no
    subcommand, `push` or `save` (not `echo git stash`, not `stash list`)."""
    for words in _commands_words(text):
        if os.path.basename(words[0]) != "git":
            continue
        i = 1
        while i < len(words) and words[i].startswith("-"):
            i += 2 if words[i] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
        if words[i:i + 1] != ["stash"]:
            continue  # stash is git's subcommand, not a word after it (`git commit -m stash`)
        rest = words[i + 1:]
        sub = next((w for w in rest if not w.startswith("-")), None)
        if sub in (None, "push", "save") or sub is not None and rest and rest[0].startswith("-") \
                and sub not in _STASH_SUBCOMMANDS:
            return True
    return False


_STASH_SUBCOMMANDS = frozenset({"list", "show", "drop", "clear", "pop", "apply", "branch",
                                "create", "store", "push", "save"})


def _stash_made_in(text, where, top):
    """True when a stash-making `git stash` in Bash command `text` (run from
    `where`) runs in repository `top`: where git runs is the last place the
    command moved to by then (`cd X`, `git -C X`), named with certainty;
    every directory named up to it must be in `top`."""
    if not _makes_stash(text):
        return False
    # each command as the shell splits it, so a separator inside quotes
    # (`echo "a; git stash"`) starts nothing; unsure is no credit
    segments, uncertain = split_compound_command(text)
    if uncertain:
        return False
    view, pos = _comment_lines_dropped(text).replace("\\\n", ""), 0  # the splitter's view
    for segment in segments:
        start = view.find(segment, pos)
        if start < 0:
            return False
        pos = start + len(segment)
        if not _makes_stash(segment):
            continue
        dirs, certain = _git_command_dirs(view[:pos], where)
        # every place named up to it (`cd`, any `git -C`): which one this git
        # runs in is not tracked, so all must be in the repository
        if certain and dirs and all(_in_repo(os.path.realpath(d), top) for d in dirs):
            return True
    return False


def _in_repo(path, top):
    """True when folder `path` is `top` or inside it, with no nested
    repository between them."""
    if path == top:
        return True
    if not path.startswith(top + os.sep):
        return False
    while path != top:
        if os.path.exists(os.path.join(path, ".git")):
            return False
        path = os.path.dirname(path)
    return True


def _session_stash_commands(input_data, repo, deadline):
    """([(timestamp, command, outcome)] of this session's Bash calls that
    run a stash-making `git stash` in `repo` (outcome: ok, failed, or no
    result yet), whether every transcript was read whole)."""
    top = os.path.realpath(repo)
    current = input_data.get("tool_use_id")
    hits, results, whole, read = [], {}, True, 0
    for path in _session_transcripts(input_data):
        if time.monotonic() > deadline or read > PROVENANCE_TOTAL_BYTES:
            whole = False
            break
        try:
            lines, size, cut = _tail_lines(path, PROVENANCE_TAIL_BYTES)
        except OSError:
            whole = False
            continue
        read += size
        whole = whole and not cut
        for line in lines:
            result = '"tool_result"' in line
            if not result and ("stash" not in line or '"Bash"' not in line):
                continue
            if time.monotonic() > deadline:
                whole = False
                break
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            if result:
                content = (record.get("message") or {}).get("content") \
                    if isinstance(record.get("message"), dict) else None
                for block in content if isinstance(content, list) else []:
                    if isinstance(block, dict) and block.get("type") == "tool_result" \
                            and isinstance(block.get("tool_use_id"), str):
                        results[block["tool_use_id"]] = "failed" if block.get("is_error") else "ok"
                continue
            where = record.get("cwd") if isinstance(record.get("cwd"), str) else None
            for use_id, texts in _bash_inputs(record):
                if use_id == current:
                    continue
                if where and any(_stash_made_in(text, where, top) for text in texts):
                    hits.append((_ts_seconds(record.get("timestamp", "")), texts[0], use_id))
    return [(ts, text, results.get(use_id, "no result yet") if isinstance(use_id, str)
             else "no result yet") for ts, text, use_id in hits], whole


def stash_context(command, cwd, input_data, deadline):
    """Blocks on the stashes a `git stash drop/clear/pop` in `command` acts on."""
    if not (isinstance(command, str) and _STASH_DISCARD_RE.search(command)):
        return []
    scan = min(deadline, time.monotonic() + PROVENANCE_BUDGET_S)  # transcripts: one slice in all
    starts = [s for s in (_session_start(p) for p in _session_transcripts(input_data)[:2]
                          if time.monotonic() <= scan) if s]
    start = min(starts) if starts else None
    parts = []
    for repo in _git_context_dirs(command, cwd)[:2]:
        top = (_git_probe(repo, ["rev-parse", "--show-toplevel"], deadline) or "").strip() or repo
        listing = _git_probe(top, ["stash", "list", "--format=%gd%x09%ct%x09%gs"], deadline)
        if listing is None:
            continue
        lines = listing.splitlines()
        out = [f"Stashes in {top} (`git stash list`, newest first): {len(lines) or 'none'}"]
        for line in lines[:STASH_CONTEXT_MAX]:
            ref, _, rest = line.partition("\t")
            ct, _, subject = rest.partition("\t")
            when = ""
            if ct.isdigit():
                when = _local_time(int(ct), "%Y-%m-%d %H:%M")
                if start:
                    when += " (after this session started)" if int(ct) >= start \
                        else " (before this session started)"
            out.append(f"- {ref} {when}: {subject[:120]}")
        if len(lines) > STASH_CONTEXT_MAX:
            out.append(f"- … {len(lines) - STASH_CONTEXT_MAX} more")
        if start:
            out.append(f"This session started {_local_time(start, '%Y-%m-%d %H:%M')}.")
        hits, whole = _session_stash_commands(input_data, top, scan)
        if hits:
            ts, text, outcome = hits[-1]
            failed = sum(1 for h in hits if h[2] == "failed")
            out.append(f"This session's own Bash calls ran a stash-making `git stash` there {len(hits)} "
                       f"time(s)" + (f", {failed} of them failed" if failed else "") + "; the latest"
                       + (f" at {_local_time(ts, '%m-%d %H:%M')}" if ts else "")
                       + f" ({outcome}): `{' '.join(text.split())[:PROVENANCE_SNIPPET_CHARS]}`."
                       " From the command text: a call that found nothing to stash made none.")
        elif _session_transcripts(input_data):
            out.append("This session's transcripts show no Bash call that ran a stash-making "
                       "`git stash` there" + ("." if whole else " (not every transcript was read whole)."))
        parts.append("\n".join(out))
    return parts
