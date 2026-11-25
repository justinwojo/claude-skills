"""Judge context from the repository the command runs in: a `git status`
snapshot before a discard, a linked-worktree note, and whose remotes a push
or remote change reaches. The probes and command-reading helpers are core's
(the rules use them too)."""
import os
import re
import time

from ..util import one_line
from ..core import (
    GIT_CONTEXT_BUDGET_S, _commands_words, _developer_owners, _git_command_dirs, _git_probe,
    _git_remotes, _remote_owner,
)


# A git subcommand that can discard uncommitted work (see _git_risk). A loose
# match: it only decides whether the LLM also gets a `git status` snapshot.
_GIT_DISCARD_HINT_RE = re.compile(r"\bgit\b[^\n;&|]*?\b(?:checkout|restore|reset|clean|switch|stash)\b")


GIT_STATUS_MAX_LINES = 40


GIT_CONTEXT_MAX_DIRS = 3


def git_status_snapshot(cwd, deadline):
    """`git status --short` of the repository at `cwd`, labelled for the LLM,
    or '' when git can't say. It lets the LLM see whether the paths a `git
    checkout --` / `reset --hard` / `clean` would overwrite hold uncommitted
    or untracked work. Dirty submodules are listed; ignored files are not
    (named in the label)."""
    stdout = _git_probe(cwd, ["status", "--porcelain=v1", "--untracked-files=all",
                              "--ignore-submodules=none"], deadline)
    if stdout is None:
        return ""
    lines = [one_line(ln) for ln in stdout.split("\n") if ln]  # line feeds only: a name may hold U+2028
    head = (f"`git status --short` in {one_line(cwd)}, taken before the command runs (it does not "
            "cover a directory the command moves to that isn't shown here, and the "
            "command's own earlier steps can make it not apply; ignored files are not listed):")
    if not lines:
        return f"{head}\n(clean: no uncommitted changes and no untracked files; ignored files unknown)"
    body = "\n".join(lines[:GIT_STATUS_MAX_LINES])
    if len(lines) > GIT_STATUS_MAX_LINES:
        body += f"\n[… {len(lines) - GIT_STATUS_MAX_LINES} more entries not shown]"
    return f"{head}\n{body}"


def git_linked_worktree_note(path, deadline):
    """A sentence for the LLM when `path` is in a linked worktree of a repository
    with a main checkout, else ''. Asks git, not the path's name, so any layout
    counts. A bare repository gets no note: there every checkout is linked, the
    developer's own included. Nor does an inherited GIT_DIR or GIT_WORK_TREE: the
    metadata and the files changed may then belong to different checkouts."""
    if os.environ.get("GIT_DIR") or os.environ.get("GIT_WORK_TREE"):
        return ""
    stdout = _git_probe(path, ["rev-parse", "--path-format=absolute", "--git-dir",
                               "--git-common-dir", "--show-toplevel"], deadline)
    lines = stdout.splitlines() if stdout else []
    if len(lines) != 3 or os.path.realpath(lines[0]) == os.path.realpath(lines[1]):
        return ""
    # `worktree list` always starts with the main worktree.
    listing = _git_probe(path, ["worktree", "list", "--porcelain"], deadline) or ""
    main = listing.split("\n\n", 1)[0].splitlines()
    if not main or not main[0].startswith("worktree ") or "bare" in main:
        return ""
    return (f"{one_line(lines[2])} is a linked git worktree of the repository at "
            f"{one_line(main[0][len('worktree '):])}, not its main checkout.")


def _git_context_dirs(command, cwd):
    """The directories the LLM should know about for this command."""
    return _git_command_dirs(command, cwd)[0]


def git_discard_context(command, cwd, deadline=None):
    """Blocks for the LLM on a command that can discard work: for each directory
    involved, whether it is a linked worktree and its `git status`."""
    deadline = deadline or time.monotonic() + GIT_CONTEXT_BUDGET_S
    parts = []
    for path in _git_context_dirs(command, cwd)[:GIT_CONTEXT_MAX_DIRS]:
        note = git_linked_worktree_note(path, deadline)
        snapshot = git_status_snapshot(path, deadline)
        parts.extend(p for p in (note, snapshot) if p)
    return parts


_GIT_REMOTE_HINT_RE = re.compile(r"\bgit\b[^\n;&|]*?\b(?:remote|push)\b")


def git_remote_context(command, cwd, deadline):
    """Blocks for the LLM on a command that adds, repoints or pushes to a remote:
    whose are the remotes and the URLs it names. The judge can't otherwise tell a
    stranger's account from the developer's own."""
    parts = []
    named = [w for words in _commands_words(command) for w in words
             if _remote_owner(w) and ("://" in w or "@" in w.split(":", 1)[0])]
    for path in _git_context_dirs(command, cwd)[:GIT_CONTEXT_MAX_DIRS]:
        remotes = _git_remotes(path, deadline)
        if remotes is None:
            continue
        mine = _developer_owners(remotes, path, deadline)

        def verdict(label, owner):  # a remote's name and a URL's host are the repository's or the command's
            if not mine:
                return one_line(f"{label} {owner}.")
            whose = "is the developer's" if owner in mine else "matches none of the developer's owners"
            return one_line(f"{label} {owner} {whose}.")

        checks = [verdict(f"Remote {name}", _remote_owner(url))
                  for name, urls in list(remotes.items())[:GIT_CONTEXT_MAX_DIRS * 4]
                  for url in urls["push"] if _remote_owner(url)]
        checks += [verdict("URL in the command:", _remote_owner(w)) for w in named]
        # Local paths and unknown hosts have no owner; say so rather than
        # leave the judge an empty block.
        checks = checks or ["No remote here or URL in the command has an owner to check "
                            "(local paths or hosts not known here)."]
        known = f"({one_line(', '.join(sorted(mine)))})" if mine else "(neither is known here)"
        parts.append(f"Owner check in {one_line(path)}, against origin's fetch URL and the gh login {known}:\n"
                     + "\n".join(checks))
    return parts
