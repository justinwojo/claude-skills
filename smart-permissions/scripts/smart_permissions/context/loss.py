"""Judge context on what a delete or reset would lose: the targets it names
(destructive_targets), the repositories inside a deleted folder, a clone's
unpushed work, a deleted branch's own commits."""
import os
import re
import time
import glob
import itertools

from ..config import HOME_DIR
from ..core import (
    _CD_NAMES, _GIT_SHORT_VALUES, _GIT_VALUE_OPTS, _LITERAL_CHARS, _PLAIN_BRANCH_RE, _cd_in_scope,
    _commands_words, _evidence_cd, _evidence_path, _git_flags, _git_probe, _git_remotes, _git_risk,
    _literal_paths, _long_option_is, _spell_names, _tilde_masked,
)
from .git import git_linked_worktree_note, git_status_snapshot
from .provenance import _local_time


# Loss evidence: folders looked at, how deep a deleted folder is searched
# for repositories, and how much of each is shown.
LOSS_MAX_TARGETS = 3
LOSS_REPO_DEPTH = 3
LOSS_MAX_REPOS = 5
LOSS_MAX_DIRS = 2000
LOSS_STATUS_LINES = 12
LOSS_MAX_BRANCHES = 4
# Folders no repository worth reporting lives in, and that can hold many
# thousands of entries.
_LOSS_SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", "__pycache__", ".tox", ".angular",
                             ".next", ".gradle", "Pods", ".cache", ".git"})
_GIT_DISCARD_SUBS = frozenset({"checkout", "restore", "reset", "clean", "switch", "stash"})


def _glob_now(word, base, limit=4):
    """What a glob operand matches right now, when that is 1 to `limit`
    entries; None when it matches nothing, too much, or is built at run time."""
    word = os.path.expanduser(word)
    if re.search(r"[$`{\x00-\x1f]", word) or not (os.path.isabs(word) or base):
        return None
    try:
        found = list(itertools.islice(glob.iglob(os.path.join(base or "/", word)), limit + 1))
    except (OSError, ValueError, re.error):
        return None
    found = [os.path.normpath(p) for p in found]
    return found if 0 < len(found) <= limit and "/" not in found and HOME_DIR not in found else None


def destructive_targets(command, cwd):
    """[(kind, path, label, branches)] for each delete or reset in `command`
    whose target can be named: `rm -r`, and `rm` of a glob ("delete"); a git
    discard (see _git_risk) in the folder git runs in ("discard"); `git branch
    -D` with its names ("branch"); `git worktree remove --force` ("worktree").
    Follows `cd` and `git -C` in order and writes out names set to one literal
    path. After a `cd` that may not move what follows (`(cd x); rm -r y`, see
    _cd_in_scope) a relative target isn't named. A target it can't name is
    left out; this only picks what to gather evidence about. A `~` that may
    not be $HOME names nothing (see _tilde_masked)."""
    try:
        commands = _commands_words(_tilde_masked(command))
    except Exception:
        return []
    names = _literal_paths(command)
    base = cwd if isinstance(cwd, str) and os.path.isabs(cwd) else None
    scoped = None
    found = []
    for words in commands:
        words = [_spell_names(w, names) for w in words]
        name = os.path.basename(words[0])
        if name in _CD_NAMES:
            if scoped is None:
                scoped = _cd_in_scope(command)
            base = None if scoped else _evidence_cd(name, words, base, command)
        elif name == "rm":
            opts, operands, ended = [], [], False
            for w in words[1:]:
                if not ended and w == "--":
                    ended = True
                elif not ended and w.startswith("-") and w != "-":
                    opts.append(w)
                else:
                    operands.append(w)
            recursive = any(_long_option_is(o, "--recursive") or not o.startswith("--") and re.search("[rR]", o)
                            for o in opts)
            for w in operands:
                path = _evidence_path(w, base, True) if recursive or re.search(r"[*?\[]", w) else None
                if path and path not in ("/", HOME_DIR):
                    # The path is shown beside the label: name only what a glob adds.
                    pattern = w[len(w.rstrip("/").rsplit("/", 1)[0]) + 1:] if re.search(r"[*?\[]", w) else ""
                    label = " ".join(["rm", *opts, pattern]).strip()[:80]
                    # A glob that matches a few entries now names those; the
                    # whole folder would show repos the glob never touches.
                    matches = _glob_now(w, base) if pattern else None
                    for p in matches or [path]:
                        found.append(("delete", p, label, ()))
        elif name == "git":
            i, here = 1, base
            while i < len(words) and words[i].startswith("-"):
                if words[i] == "-C" and i + 1 < len(words):
                    here = _evidence_path(words[i + 1], here, True)
                i += 2 if words[i] in _GIT_VALUE_OPTS else 1
            if i >= len(words) or not here:
                continue
            sub, rest = words[i], words[i + 1:]
            label = " ".join(["git", sub, *rest])[:80]
            if sub in _GIT_DISCARD_SUBS and isinstance(_git_risk(words[1:]), str):
                found.append(("discard", here, label, ()))
            elif sub == "branch":
                letters = "".join(f for f in _git_flags(rest, _GIT_SHORT_VALUES["branch"]) if len(f) == 1)
                if "D" in letters or ("d" in letters or "--delete" in rest) \
                        and ("f" in letters or "--force" in rest):
                    branches = tuple(b for b in rest if not b.startswith("-")
                                     and _PLAIN_BRANCH_RE.fullmatch(b))
                    found.append(("branch", here, label, branches))
            elif sub == "worktree" and rest[:1] == ["remove"] \
                    and any(f in ("-f", "--force") for f in rest):
                target = next((w for w in rest[1:] if not w.startswith("-")), None)
                path = _evidence_path(target, here, True)
                if path:
                    # The path is shown beside the label.
                    label = " ".join(["git", "worktree", *[w for w in rest if w != target]])[:80]
                    found.append(("worktree", path, label, ()))
    unique, seen = [], set()
    for t in found:
        if (t[0], t[1], t[3]) not in seen:
            seen.add((t[0], t[1], t[3]))
            unique.append((t[0], t[1], t[2].replace(_LITERAL_CHARS["~"], "~"), t[3]))
    return unique


def _clean_url(url):
    """A remote URL without credentials."""
    return re.sub(r"//[^/@\s]*@", "//", url)


def _indent(text, limit=LOSS_STATUS_LINES):
    lines = text.splitlines()
    shown = "\n".join("    " + x for x in lines[:limit])
    if len(lines) > limit:
        shown += f"\n    [… {len(lines) - limit} more entries not shown]"
    return shown


def _repos_inside(path, deadline):
    """(git checkouts and bare repositories at or under `path`, as (folder,
    bare), LOSS_REPO_DEPTH levels deep at most, whether the search finished).
    Links aren't followed, and a repository's own folders aren't searched:
    its status covers them."""
    repos, level, looked = [], [path], 0
    for depth in range(LOSS_REPO_DEPTH + 1):
        deeper = []
        for d in level:
            bare = os.path.isfile(os.path.join(d, "HEAD")) and all(
                os.path.isdir(os.path.join(d, x)) for x in ("objects", "refs"))
            if bare or os.path.lexists(os.path.join(d, ".git")):
                repos.append((d, bare))
                if len(repos) >= LOSS_MAX_REPOS:
                    return repos, False
                continue
            looked += 1
            if looked > LOSS_MAX_DIRS or time.monotonic() > deadline:
                return repos, False
            if depth == LOSS_REPO_DEPTH:
                continue
            try:
                with os.scandir(d) as it:
                    deeper.extend(e.path for e in it if e.name not in _LOSS_SKIP_DIRS
                                  and e.is_dir(follow_symlinks=False))
            except OSError:
                continue
        level = sorted(deeper)
    return repos, True


def _repo_loss(repo, deadline, bare=False):
    """What deleting the checkout (or `bare` repository) at `repo` would
    lose, as git sees it."""
    if bare:
        text = "  A bare repository (no work tree): its branches are all it holds."
    else:
        status = _git_probe(repo, ["status", "--porcelain=v1", "--branch", "--untracked-files=normal",
                                   "--ignored=matching", "--ignore-submodules=none"], deadline)
        if status is None:
            return "  git could not read it in time."
        text = "  `git status --short --branch --ignored`:\n" + _indent(status)
    remotes = _git_remotes(repo, deadline)
    # a clone of a configured remote that kept no remote-tracking refs
    clone = _clone_observations(repo, bare, deadline) if remotes else None
    unique = (_git_probe(repo, ["rev-list", "--count", "--branches", "--not", "--remotes"],
                         deadline) or "").strip()
    if unique.isdigit() and clone:
        # with no remote-tracking ref to compare against, git counts every commit
        text += (f"\n  Commits on local branches: {unique}. There are no remote-tracking refs, "
                 "so git cannot say which of them its remote also holds.")
    elif unique.isdigit():
        text += f"\n  Commits on local branches that no remote-tracking ref holds: {unique}"
        if unique != "0":
            latest = (_git_probe(repo, ["log", "-1", "--format=%h %cd %s", "--date=format-local:%Y-%m-%d %H:%M",
                                        "--branches", "--not", "--remotes"], deadline) or "").strip()
            text += f" (newest: {latest[:100]})" if latest else ""
        text += "."
    if _git_probe(repo, ["symbolic-ref", "-q", "HEAD"], deadline) is None:
        detached = (_git_probe(repo, ["rev-list", "--count", "HEAD", "--not", "--branches", "--remotes", "--"],
                               deadline) or "").strip()
        if detached.isdigit() and detached != "0":
            text += (f" HEAD is detached, with {detached} commit{'s' if detached != '1' else ''}"
                     " no branch or remote-tracking ref holds.")
    if remotes is not None:
        named = [f"{n} {_clean_url(r.get('fetch', ''))[:100]}" for n, r in list(remotes.items())[:4]]
        text += f" Remotes: {', '.join(named) if named else 'none'}."
    stashes = _git_probe(repo, ["stash", "list", "--format=%gd"], deadline)
    if stashes is not None:
        text += f" Stashes: {len(stashes.splitlines())}."
    if clone:
        text += "\n  " + clone
    return text


_CACHE_ROOTS = tuple(os.path.join(HOME_DIR, d) for d in (".cache", "Library/Caches"))


def _clone_observations(repo, bare, deadline):
    """What a repository with a remote but no remote-tracking refs shows about where its
    branches came from, said literally (a `git clone --bare`/`--mirror` keeps
    none): a mirror setting, its branch count, its loose refs and reflogs
    and those newer than packed-refs (and when that was written),
    and a path under a cache folder. None when it has remote-tracking refs or
    git can't say. Whether its commits exist elsewhere is left to the judge."""
    tracking = _git_probe(repo, ["for-each-ref", "--count=1", "--format=%(refname)", "refs/remotes"],
                          deadline)
    if tracking is None or tracking.strip():
        return None
    out = []
    mirror = _git_probe(repo, ["config", "--get-regexp", r"^remote\..*\.mirror$"], deadline) or ""
    if re.search(r"\strue\s*$", mirror, re.M | re.I):
        out.append("Its remote is set up as a mirror (remote.<name>.mirror true).")
    heads = _git_probe(repo, ["for-each-ref", "--format=%(refname)", "refs/heads"], deadline)
    gitdir = repo if bare else (_git_probe(repo, ["rev-parse", "--absolute-git-dir"], deadline)
                                or "").strip()
    if heads is not None:
        line = f"Local branches: {len(heads.splitlines())}"
        if gitdir and os.path.isdir(gitdir):
            loose, logs, cut = [], [], False
            head_log = os.path.join(gitdir, "logs", "HEAD")
            logs += [head_log] if os.path.isfile(head_log) else []
            # every local ref (branches, tags, notes…) and its log: any of them may be newer
            for sub, into in (("refs", loose), ("logs/refs", logs)):
                for root, _dirs, files in os.walk(os.path.join(gitdir, sub)):
                    into.extend(os.path.join(root, f) for f in files)
                    if len(into) > 1000 or time.monotonic() > deadline:
                        cut = True
                        break
            packed = os.path.join(gitdir, "packed-refs")
            try:
                packed_at = os.stat(packed).st_mtime
            except OSError:
                packed_at = None
            line += f"; {len(loose)} loose ref{'s' if len(loose) != 1 else ''} (branches, tags, …)"
            line += f", {len(logs)} reflog{'s' if len(logs) != 1 else ''} (refs and HEAD)"
            if packed_at is None:
                line += "; no packed-refs file"
            else:
                newer = []
                for f in loose + logs:
                    if time.monotonic() > deadline:
                        cut = True
                        break
                    try:
                        mtime = os.stat(f).st_mtime
                    except OSError:
                        continue
                    if mtime > packed_at:
                        newer.append(mtime)
                line += f"; packed-refs written {_local_time(packed_at, '%Y-%m-%d %H:%M')}"
                line += (f"; {len(newer)} loose ref or reflog file{'s' if len(newer) != 1 else ''}"
                         f" newer than packed-refs (newest {_local_time(max(newer), '%Y-%m-%d %H:%M')})"
                         if newer else "" if cut else
                         "; no loose ref or reflog is newer than packed-refs")
            line += "; the scan stopped early, there may be more." if cut else "."
        out.append(line if line.endswith(".") else line + ".")
    real = os.path.realpath(repo)
    cache = next((c for c in _CACHE_ROOTS if real == c or real.startswith(c + os.sep)
                  or repo.startswith(c + os.sep)), None)
    if cache:
        out.append(f"It is under the cache folder {cache}.")
    return " ".join(out) or None


def _delete_loss(path, label, deadline):
    """A block on what deleting the folder `path` would lose: the git
    checkouts inside it, or, inside a checkout, git's view of that path (of
    a file too, as a glob names them)."""
    if os.path.islink(path) or not os.path.exists(path):
        return ""
    folder = os.path.isdir(path)
    if not folder and not os.path.isfile(path):
        return ""
    repos, complete = _repos_inside(path, deadline) if folder else ([], True)
    if repos:
        out = [f"Git repositories inside {path} ({label}), up to {LOSS_REPO_DEPTH} levels deep"
               + ("" if complete else "; the search stopped early, there may be more") + ":"]
        for repo, bare in repos:
            out.append(f"- {os.path.relpath(repo, path) if repo != path else path}:")
            out.append(_repo_loss(repo, deadline, bare))
        return "\n".join(out)
    top = (_git_probe(path if folder else os.path.dirname(path), ["rev-parse", "--show-toplevel"],
                      deadline) or "").strip()
    if top:
        status = _git_probe(top, ["status", "--porcelain=v1", "--untracked-files=normal",
                                  "--ignored=matching", "--", os.path.realpath(path)], deadline)
        if status is not None:
            body = _indent(status) if status.strip() else \
                "    (nothing: every file there is committed and unchanged)"
            where = ""
            if re.match(r"(?:/private)?/tmp/", top):
                remotes = _git_remotes(top, deadline)
                named = [f"{n} {_clean_url(r.get('fetch', ''))[:100]}"
                         for n, r in list((remotes or {}).items())[:3]]
                where = (f" The repository's root is under /tmp" + (
                    f"; its remotes: {', '.join(named)}." if named else
                    "; it has no remotes." if remotes is not None else "."))
            return (f"{path} ({label}) is inside the git repository {top}.{where} Uncommitted, "
                    f"untracked and ignored files there (`git status --short --ignored`):\n{body}")
    if not folder:
        return ""
    return (f"No git repository inside {path} ({label}), up to {LOSS_REPO_DEPTH} levels deep"
            + ("" if complete else " (the search stopped early)") + ", and it is not inside one.")


def _branch_loss(path, branches, label, deadline):
    """Blocks on what `git branch -D` of `branches` in `path` would lose."""
    out = []
    for b in branches[:LOSS_MAX_BRANCHES]:
        ref = "refs/heads/" + b
        tip = (_git_probe(path, ["log", "-1", "--format=%h %cd %s", "--date=format-local:%Y-%m-%d %H:%M",
                                 ref, "--"], deadline) or "").strip()
        if not tip:
            continue
        line = f"Branch {b} in {path} ({label}): tip {tip[:100]}."
        unique = (_git_probe(path, ["rev-list", "--count", ref, "--not", f"--exclude={b}",
                                    "--branches", "--remotes", "--"], deadline) or "").strip()
        if unique.isdigit():
            line += f" Commits only this branch holds (no other branch or remote-tracking ref): {unique}."
        head = (_git_probe(path, ["symbolic-ref", "-q", "HEAD"], deadline) or "").strip()
        if head == ref:
            line += " It is the checked-out branch now (the command may switch away first)."
        elif _git_probe(path, ["merge-base", "--is-ancestor", ref, "HEAD"], deadline) is not None:
            line += " Merged into HEAD."
        else:
            line += " Not merged into HEAD."
        out.append(line)
    return out


def loss_context(targets, covered, deadline):
    """Blocks for the LLM on what each delete, branch deletion or forced
    worktree removal in `targets` would lose (discards get their `git
    status` from git_discard_context; `covered` are the folders it did)."""
    parts, done = [], 0
    for kind, path, label, branches in targets:
        if done >= LOSS_MAX_TARGETS or time.monotonic() > deadline:
            break
        if kind == "delete":
            block = _delete_loss(path, label, deadline)
            parts.extend([block] if block else [])
        elif kind == "branch":
            parts.extend(_branch_loss(path, branches, label, deadline))
        elif kind == "worktree" and os.path.realpath(path) not in covered:
            note = git_linked_worktree_note(path, deadline)
            snapshot = git_status_snapshot(path, deadline)
            parts.extend(p for p in (note, snapshot) if p)
        else:
            continue
        done += 1
    return parts
