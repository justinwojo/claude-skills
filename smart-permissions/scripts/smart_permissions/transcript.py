"""Reading session transcripts (JSONL, read from the tail): the developer's
recent messages for the judge, transcript timestamps, and what an agent
wrote after a hold. Only the developer's messages (or the agent's own text,
for a hold) come back; tool results and system reminders never do."""
import json
import os
import re
from datetime import datetime

from .holds import HOLD_ANSWER_CHARS


# Recent-message context sent with each LLM evaluation.
CONTEXT_MAX_MESSAGES = 4
CONTEXT_MAX_MESSAGE_CHARS = 1500
CONTEXT_TRANSCRIPT_TAIL_BYTES = 2 * 1024 * 1024


_SYSTEM_REMINDER_RE = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)


def _message_text(record):
    """The human-written text of a transcript record, or None.

    Keeps user turns the developer typed (or, in headless runs, the task
    prompt). Drops tool results — hostile file or web content must never
    reach the judge as trusted context — plus meta records and harness
    injections such as task notifications and slash-command output.
    """
    if not isinstance(record, dict) or record.get("type") != "user":
        return None
    if record.get("isMeta") or record.get("isCompactSummary"):
        return None
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
            return None
        text = "\n".join(b.get("text", "") for b in content
                         if isinstance(b, dict) and b.get("type") == "text")
    else:
        return None
    text = _SYSTEM_REMINDER_RE.sub("", text).strip()
    if not text:
        return None
    origin = record.get("origin")
    kind = origin.get("kind") if isinstance(origin, dict) else None
    if kind != "human" and text.startswith("<"):
        return None
    return text


def recent_user_messages(transcript_path, limit=CONTEXT_MAX_MESSAGES):
    """The last `limit` human messages from a transcript, oldest first.

    Reads only the file's tail. Never raises — context is a nice-to-have.
    """
    if not isinstance(transcript_path, str) or not transcript_path:
        return []
    try:
        with open(transcript_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - CONTEXT_TRANSCRIPT_TAIL_BYTES)
            f.seek(start)
            lines = f.read().decode("utf-8", "replace").splitlines()
        if start > 0 and lines:
            lines = lines[1:]  # first line is partial
    except OSError:
        return []
    messages = []
    for line in reversed(lines):
        try:
            text = _message_text(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
        if text:
            if len(text) > CONTEXT_MAX_MESSAGE_CHARS:
                text = text[:CONTEXT_MAX_MESSAGE_CHARS] + " […]"
            messages.append(text)
            if len(messages) >= limit:
                break
    return list(reversed(messages))


def _ts_seconds(text):
    """Epoch seconds of an ISO timestamp from a transcript, or None."""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError, OverflowError, OSError):
        return None


def agent_answer_since(path, since, limit=HOLD_ANSWER_CHARS):
    """What the agent wrote in its transcript at `path` after epoch `since`:
    its assistant text and the thinking the transcript keeps, oldest first,
    system reminders removed, the last `limit` characters kept. '' when there
    is none. Thinking counts because agents often settle the question there
    and retry with no visible message (seen in the live trial); it is the
    same agent's claim either way. Reads the file's tail only; never raises."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - CONTEXT_TRANSCRIPT_TAIL_BYTES)
            f.seek(start)
            lines = f.read().decode("utf-8", "replace").splitlines()
        if start > 0 and lines:
            lines = lines[1:]  # first line is partial
    except (OSError, TypeError, ValueError):
        return ""
    texts = []
    for line in lines:
        if '"assistant"' not in line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "assistant" or rec.get("isApiErrorMessage"):
            continue
        ts = _ts_seconds(rec.get("timestamp"))
        if ts is None or ts <= since:
            continue
        message = rec.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if isinstance(content, str):
            blocks = [content]
        elif isinstance(content, list):
            blocks = [b.get(b.get("type")) for b in content
                      if isinstance(b, dict) and b.get("type") in ("text", "thinking")
                      and isinstance(b.get(b.get("type")), str)]
        else:
            continue
        for text in blocks:
            text = _SYSTEM_REMINDER_RE.sub("", text).strip()
            if text:
                texts.append(text)
    text = "\n\n".join(texts)
    if len(text) > limit:
        text = "[… earlier text left out …]\n" + text[-limit:]
    return text
