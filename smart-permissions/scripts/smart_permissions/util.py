"""Small helpers with no state of their own: elapsed milliseconds, running a
context block so an exception never fails the hook, the per-process memo
for readers whose answer depends only on their arguments and the loaded
config, the marked lines around a text shown to the judge, and the one
line a value from the payload, a transcript or a repository is shown on
outside them."""
import functools
import re
import secrets
import time


def text_marker(texts):
    """A random token, new for each block, that none of `texts` holds."""
    while True:
        token = "sp-" + secrets.token_hex(6)
        if not any(token in text for text in texts):
            return token


def fenced(opening, text, end, marker):
    """`text` as the judge is shown it: between an opening and an end line
    both marked with `marker` (text_marker over every text of its block), so
    nothing inside can fake its end. Every text an agent wrote, or that is
    read from a transcript, is shown this way; the block's header names the
    marker and says the text is data."""
    return f"--- {one_line(opening)} [{marker}] ---\n{text.rstrip()}\n--- {one_line(end)} [{marker}] ---"


# Every character that can end a line, and every other control character but tab
_LINE_BREAK_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f\u2028\u2029]")
_ESCAPES = {"\n": "\\n", "\r": "\\r", "\x0b": "\\v", "\x0c": "\\f"}


def one_line(text):
    """`text` on one line, so a value from the payload, a transcript or a
    repository that the judge is shown outside a fenced block (a path, a
    tool name, a commit subject) can't start a line of its own: each line
    break or other control character is written as its escape (`\\n`,
    `\\x85`, `\\u2028`), so it shows and two values stay apart. Spaces and
    tabs are left as they are."""
    return _LINE_BREAK_RE.sub(lambda m: _ESCAPES.get(m[0]) or (
        f"\\x{ord(m[0]):02x}" if ord(m[0]) < 0x100 else f"\\u{ord(m[0]):04x}"), text)


def _elapsed_ms(start):
    """Milliseconds since a time.monotonic() start marker (None on error)."""
    try:
        return int((time.monotonic() - start) * 1000)
    except Exception:
        return None


def _quietly(block, *args):
    """block(*args), or None when it raises: a context block is evidence,
    never a reason for the hook to fail."""
    try:
        return block(*args)
    except Exception:
        return None


def _memo(fn):
    """Cache a reader whose answer depends only on its arguments and the
    loaded config: one command is read many times over (rules, guards, C9,
    the code it runs). Callers get their own copy of a list or dict in the
    answer. A call with an unhashable argument (a list to fill) is not cached."""
    cached = functools.lru_cache(maxsize=4096)(fn)

    @functools.wraps(fn)
    def read(*args, **kwargs):
        try:
            out = cached(*args, **kwargs)
        except TypeError:
            return fn(*args, **kwargs)
        if isinstance(out, tuple):
            return tuple(v.copy() if isinstance(v, (list, dict)) else v for v in out)
        return out.copy() if isinstance(out, (list, dict)) else out
    read.cache_clear = cached.cache_clear
    return read
