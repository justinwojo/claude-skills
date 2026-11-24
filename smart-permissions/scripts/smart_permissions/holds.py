"""The holds store: one small file per held call under HOLD_DIR, written whole
and claimed with exclusive markers, its TTL, per-session cap and pruning, the
hold key of a call, the acting agent's transcript, and the retry note for the
judge. Creating a hold and judging its retry are in holdflow (_hold_new,
_hold_retry) and judge (llm_evaluate_retry); reading the agent's answer is in
transcript (agent_answer_since)."""
import hashlib
import itertools
import json
import os
import re
import time

from .config import HOLD_DIR


# ============================================================
# HOLDS: an agent-resolvable flag becomes a question (Phase 2)
# ============================================================
# When both judge passes flag a call the agent could settle with facts it can
# check (who made a folder, whether its commits exist elsewhere, what a script
# does), PreToolUse denies it with a question instead of prompting the
# developer. The agent answers in its reply and retries the identical call.
# The retry gets one more judge pass with the hold, the agent's answer (the
# text the acting agent wrote to its own transcript since the hold) and
# freshly gathered evidence. Cleared: the call runs. Flagged again, or no
# answer: the developer decides, shown the hold reason in the hook's words and
# the answer labelled as the agent's claim. A second flag is terminal: one
# hold per call.
#
# Never held, straight to the developer: categories 2 and 5, deleting cloud,
# production or remote resources, sending secrets off the machine, a refused
# or malformed verdict, remote or production execution (see remote_exec), and
# a call with no session or transcript to bind the hold to. Hard denies and
# the C9 config guard come first, as before.

HOLD_TTL_S = 15 * 60          # a retry must come within this
HOLD_SESSION_CAP = 4          # holds one session may make within
HOLD_CAP_WINDOW_S = 15 * 60   # this window; past it, flags go to the developer
HOLD_PRUNE_S = 24 * 3600      # hold files older than this are removed
HOLD_ANSWER_CHARS = 3000      # the end of the agent's answer the judge sees
HOLD_CLAIM_CHARS = 600        # …and the developer sees, if it comes to that
HOLD_QUESTION_CHARS = 300
_HOLD_DEFAULT_QUESTION = ("What did you check that shows this call loses or exposes nothing the "
                          "developer wants kept, and that it is part of your task?")

# Appended to the user message for the retry of a held call.
LLM_HOLD_RETRY_NOTE = """

This exact call was held earlier in this session instead of being run. The \
flag then: {reason}
The hook asked the agent: {question}
The agent's answer, written since the hold (its own claim, not the developer's \
words or approval):
--- agent's answer ---
{answer}
--- end of agent's answer ---
The evidence above was gathered again for this retry. The hold exists because \
the evidence alone could not settle the flag, so the answer is expected to add \
facts the hook could not gather (what a commit or a file holds, what an \
earlier run produced, where else a copy lives). Weigh it as a claim to check, \
not as proof to demand. Clear the call ({{"safe": true}}) when all of these \
hold: the answer is specific (what the agent checked and what it showed), it \
is about this call's own targets and payload, nothing in the evidence or the \
developer's messages or the brief contradicts it, and, taken as true, it \
settles the flag: the operation is then one the developer's messages or the \
brief cover. Flag it again when the answer is vague, is about a different \
target or payload than this call, is contradicted by the evidence (times, \
provenance, git state, file contents, what the developer said), or would not \
settle the flag even if true; the developer then decides. Category 2 and 5 \
harms, destroying cloud, production or remote resources or data, and sending \
secrets off the machine are the developer's call whatever the answer says: \
flag those again. A scratch checkout or worktree this session made from a \
pushed branch or commit, on a development, build or test machine it drives, \
is not such a remote resource when the earlier calls and its git state \
(uncommitted changes, commits no remote holds, ignored files) show it holds \
nothing found nowhere else; a shared one, or one holding deliverables, is."""


def hold_key(input_data, tool, tool_input):
    """The hold key of a call: sha256 over the session, the acting agent, the
    working directory, the tool and its execution-relevant input (a Bash
    `description` is left out, so a cosmetic edit keeps the hold). None
    without a session id: a hold is always bound to one."""
    session = input_data.get("session_id") if isinstance(input_data, dict) else None
    if not isinstance(session, str) or not session:
        return None
    relevant = dict(tool_input) if isinstance(tool_input, dict) else {}
    if tool == "Bash":
        relevant.pop("description", None)
    agent = input_data.get("agent_id") or input_data.get("agent_transcript_path") or ""
    try:
        canonical = json.dumps([session, str(agent), str(input_data.get("cwd") or ""), tool, relevant],
                               sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()


def acting_transcript(input_data):
    """The transcript of the agent making the call: a subagent's own (never
    the lead's in its place), else the session's. None when unreadable.
    PreToolUse in a subagent may carry only `agent_id` beside the lead's
    `transcript_path`: the subagent's is then <session>/subagents/agent-<id>.jsonl."""
    main = input_data.get("transcript_path")
    agent = input_data.get("agent_transcript_path")
    agent_id = input_data.get("agent_id")
    if isinstance(agent, str) and agent and agent != main:
        path = agent
    elif isinstance(agent_id, str) and agent_id:
        if not isinstance(main, str) or not re.fullmatch(r"[\w-]+", agent_id):
            return None
        path = os.path.join(os.path.splitext(main)[0], "subagents", f"agent-{agent_id}.jsonl")
    else:
        path = main
    if isinstance(path, str) and os.path.isabs(path) and os.path.isfile(path):
        return path
    return None


def _hold_path(key, suffix=".json"):
    return os.path.join(HOLD_DIR, key + suffix)


def hold_get(key):
    """The live hold record of `key`, or None (none, expired, unreadable)."""
    try:
        with open(_hold_path(key)) as f:
            rec = json.load(f)
    except (OSError, ValueError):
        return None
    ts = rec.get("ts") if isinstance(rec, dict) else None
    if not isinstance(ts, (int, float)) or isinstance(ts, bool) \
            or not 0 <= time.time() - ts < HOLD_TTL_S \
            or not isinstance(rec.get("reason"), str) or not isinstance(rec.get("question"), str):
        return None
    return rec


def _hold_write(path, rec, exclusive):
    """Write `rec` to `path` whole, through a uniquely named temporary file:
    linked in when `exclusive` (FileExistsError if `path` exists), else
    renamed over it. A reader never sees half a record."""
    import tempfile
    os.makedirs(HOLD_DIR, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=HOLD_DIR, prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f)
        if not exclusive:
            os.replace(tmp, path)
            return
        try:
            os.link(tmp, path)
        except FileExistsError:
            raise
        except (OSError, AttributeError, NotImplementedError):  # no hard links here
            out = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(out, "w") as f:
                json.dump(rec, f)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def hold_create(key, rec):
    """Record hold `rec` for `key` unless a live one exists. Returns the hold
    in force: `rec` when this call made it, else the one another call made
    (two identical concurrent calls record one hold). None when it can't be
    written."""
    path = _hold_path(key)
    for _ in range(2):
        try:
            _hold_write(path, rec, exclusive=True)
            return rec
        except FileExistsError:
            live = hold_get(key)
            if live is not None:
                return live
            for stale in (path, _hold_path(key, ".retry")):  # expired or broken
                try:
                    os.unlink(stale)
                except OSError:
                    pass
        except OSError:
            return None
    return None


def hold_claim(key):
    """True for the one retry that may judge a held call (an exclusive
    marker); False when another retry has claimed it."""
    try:
        os.close(os.open(_hold_path(key, ".retry"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return True
    except OSError:
        return False


def hold_finish(key, rec, state):
    """Mark the hold of `key` spent ("cleared" or "asked"): a flag of the
    same call within HOLD_TTL_S then goes to the developer."""
    try:
        _hold_write(_hold_path(key), dict(rec, state=state, done=time.time()), exclusive=False)
    except OSError:
        pass


def hold_count(session):
    """How many holds `session` made within HOLD_CAP_WINDOW_S. Removes hold
    files older than HOLD_PRUNE_S on the way."""
    now, count = time.time(), 0
    try:
        with os.scandir(HOLD_DIR) as it:
            entries = list(itertools.islice(it, 4000))
    except OSError:
        return 0
    for entry in entries:
        try:
            st = entry.stat(follow_symlinks=False)
            if now - st.st_mtime > HOLD_PRUNE_S:
                os.unlink(entry.path)
                continue
            # a file is written at its hold's time or later: an older one can't count
            if not entry.name.endswith(".json") or now - st.st_mtime > HOLD_CAP_WINDOW_S:
                continue
            with open(entry.path) as f:
                rec = json.load(f)
            ts = rec.get("ts") if isinstance(rec, dict) else None
            if rec.get("session") == session and isinstance(ts, (int, float)) \
                    and 0 <= now - ts < HOLD_CAP_WINDOW_S:
                count += 1
        except (OSError, ValueError, AttributeError):
            continue
    return count
