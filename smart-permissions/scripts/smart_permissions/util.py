"""Small helpers with no state of their own: elapsed milliseconds, running a
context block so an exception never fails the hook, and the per-process memo
for readers whose answer depends only on their arguments and the loaded config."""
import functools
import time


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
