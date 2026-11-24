"""The per-call state of one hook invocation.

Each hook entry (core.main, learner.main) creates one CallState, fills it from
the payload and makes it the active state with `using_state` for the whole
call: that is the only place a hook sets it, and leaving the block restores
the one before. The hook's own flow passes the state explicitly (to
build_llm_context, log_decision, the hold steps and the judge's scrubbing).
The rule engine, whose readers sit many calls deep under evaluate_bash, reads
it with current_state(). Outside a hook (a test, the eval harness) the active
state is an idle one that knows no directory, unless the caller builds its
own and activates it.

Nothing cached may read it: a memoized reader's answer depends on its
arguments and the loaded config only (test_package_modules checks that no
@_memo function in core reaches current_state)."""
import contextlib


class CallState:
    """What one hook call knows beyond its tool input, and what it learns.

    From the payload: `cwd`, the session's working directory (absolute, or
    None); `scratchpad`, this session's scratchpad folder (see core's
    session_dirs), or None; `client_tool`, the client's own tool name when
    parse_hook_payload mapped it, so the decision log keeps it.
    Set while the call is decided: `top_command`, the command evaluate_bash
    was last called with at depth 0 (code a command runs is read one level
    deeper on its own, but an import path the whole command sets
    (`export PYTHONPATH=…; trap "python3 -c …" EXIT`) still applies to it);
    from build_llm_context, for the decision log, `provenance`: "found" (an
    earlier command of this session names a target, or the target was
    created after the session started; on another machine, an earlier call
    there names it), "none", "unavailable" (no transcript to read), or None
    when the call deletes or resets nothing it can name; and `script_texts`,
    the local script text the judge was shown, so a reason quoting it is
    scrubbed before it is logged or stored (see scrub_script_text);
    `reading_words`, True while _commands_words runs (reading a command can
    evaluate code inside it, which comes back there)."""
    __slots__ = ("cwd", "scratchpad", "client_tool", "top_command", "provenance",
                 "script_texts", "reading_words")

    def __init__(self, cwd=None, scratchpad=None, client_tool=None):
        self.cwd = cwd
        self.scratchpad = scratchpad
        self.client_tool = client_tool
        self.top_command = ""
        self.provenance = None
        self.script_texts = []
        self.reading_words = False


_active = CallState()  # idle: no hook call is being decided


def current_state():
    """The state of the call being decided (an idle one outside a hook)."""
    return _active


@contextlib.contextmanager
def using_state(state):
    """Make `state` the active one for the block; the previous one after it."""
    global _active
    saved, _active = _active, state
    try:
        yield state
    finally:
        _active = saved
