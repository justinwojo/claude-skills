"""The flag store: calls PreToolUse put to the developer, keyed by the exact
call, so the PermissionRequest hook that follows does not overrule that ask.
One small JSON file, written whole under a lock, entries kept for
LLM_FLAG_TTL_S."""
import hashlib
import json
import os
import time

from .config import LLM_FLAG_PATH, LLM_FLAG_TTL_S
from .log import _loggable_reason


def _call_key(tool, tool_input):
    """sha256 over the tool name + canonical JSON of the full tool input."""
    try:
        canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        canonical = str(tool_input)
    raw = tool + "\0" + canonical
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()


def _flag_put(tool, tool_input, reason, script_texts):
    """Record a call PreToolUse put to the developer (`script_texts`: what the
    judge was shown, see _loggable_reason). Best-effort, never raises.
    Concurrent hooks (parallel tool calls) take turns on a lock, so one entry
    never overwrites another; past 0.3s of waiting it writes anyway."""
    import tempfile
    lock = None
    try:
        os.makedirs(os.path.dirname(LLM_FLAG_PATH), exist_ok=True)
        try:
            import fcntl
            lock = os.open(LLM_FLAG_PATH + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
            for _ in range(30):  # a holder keeps it for milliseconds
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(0.01)
        except (ImportError, OSError):
            pass
        now = time.time()
        flags = {k: v for k, v in _read_json_dict(LLM_FLAG_PATH).items()
                 if isinstance(v, dict) and now - v.get("ts", 0) < LLM_FLAG_TTL_S}
        # stored, then logged by the learner: never the judge's words about a script
        flags[_call_key(tool, tool_input)] = {"reason": _loggable_reason(reason, script_texts), "ts": now}
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(LLM_FLAG_PATH), prefix=".flags-")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(flags, f)
            os.replace(tmp_path, LLM_FLAG_PATH)
        except OSError:
            os.unlink(tmp_path)
            raise
    except Exception:
        pass
    finally:
        if lock is not None:
            os.close(lock)


def _flag_get(tool, tool_input):
    """Reason string if this exact call was recently flagged, else None.

    A planted entry can only turn an LLM consult into a human prompt, so the
    file needs no integrity check.
    """
    try:
        entry = _read_json_dict(LLM_FLAG_PATH).get(_call_key(tool, tool_input))
        if isinstance(entry, dict) and time.time() - entry.get("ts", 0) < LLM_FLAG_TTL_S:
            return entry.get("reason") or "Flagged by both LLM passes"
    except Exception:
        pass
    return None


def _read_json_dict(path):
    """Load a JSON object from path; missing/corrupt/non-dict → {}."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
