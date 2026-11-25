# Smart Permissions

A hook plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that replaces the built-in permission system with smarter, configurable auto-approval. It lets Claude work autonomously on safe operations while still blocking genuinely dangerous commands.

Out of the box, Claude Code prompts you for every file write, every bash command, and every web fetch. With this plugin, common development operations are auto-approved based on rules you control.

The plugin evaluates in a strict **trust order — rules → LLM → human**. Local rules decide first. Anything they can't classify is handed to an optional LLM (if you've configured one). Only what neither can vouch for reaches you as a standard permission prompt with full "Always allow" support. The plugin never edits its own config: an LLM approval covers that one call, and only you add entries to the allowlists.

> **Upgrading from an earlier version — auto-learning is gone.** Earlier versions wrote approved commands, write folders, web domains and MCP tool names into your config. That has been removed, and two behaviors change:
>
> - **Without an LLM configured**, calls the rules can't settle now show the normal Claude prompt. They used to be approved silently and learned: unknown Bash commands, writes under your home or temp folders, and WebFetch to new domains. To keep things quiet, configure an LLM (`SAFETY_HOOK_MODEL=claude-haiku-5-5` plus a key, see [LLM environment variables](#llm-environment-variables)), add your own entries to the config, or use the prompt's "Always allow".
> - **With an LLM**, nothing it approves is saved to your config. Every call gets a fresh, context-aware judgment; nothing is cached. A `smart-permissions-llm-cache.json` left in `~/.claude/hooks/` by an earlier version is ignored and can be deleted.
>
> `SAFETY_HOOK_AUTO_LEARN` and the config keys `auto_learn_mcp_tools` and `never_learn_commands` are retired and ignored; you can delete them. Entries earlier versions learned stay in your config as ordinary entries. Look through `safe_commands`, `safe_write_paths`, `allowed_web_domains` and `safe_mcp_tools` and prune anything you don't want trusted permanently. `/smart-permissions:setup` can walk you through it.

## Installation

```
/plugin marketplace add justinwojo/claude-skills
/plugin install smart-permissions@justinwojo-claude-skills
```

Then run the setup wizard to configure it:

```
/smart-permissions:setup
```

The wizard walks you through LLM evaluation, safe commands, write paths, and MCP tool permissions.

## How it works

Every tool call passes through **two** hooks. The PreToolUse hook runs first;
if it can't decide, the PermissionRequest hook (`permission_learner.py`, logged
as source `learner`; the name predates the removal of learning) gets a second,
LLM-consulting pass before Claude ever shows you a prompt:

```
Tool call
  ┌─ PreToolUse ─────────────────────────────────────────────────────┐
  │  Dangerous pattern in code? (sudo, curl|sh)     ──→  DENY          │
  │  …only in data (echo, commit message)           ──→  LLM           │
  │  Recursive delete of a protected folder (~/Dev) ──→  DENY          │
  │  rm -r target on a possibly-empty $VAR          ──→  DENY + rewrite│
  │  Permission-config write? (settings, this cfg)  ──→  ASK (human)   │
  │  Plain force push (not main)                    ──→  DENY + rewrite│
  │  rm -r of /tmp/x, or __pycache__ under cwd      ──→  ALLOW         │
  │  Other recursive delete (rm -r, find -delete)   ──→  LLM           │
  │  Risky pattern? (rm *, find / -delete)          ──→  LLM           │
  │  Known-safe command/subcommand?                 ──→  ALLOW         │
  │  MCP tool in safe list? (glob patterns)         ──→  ALLOW         │
  │  Otherwise (unknown)                            ──→  LLM eval      │
  │  Remote/prod exec (kubectl exec, az … exec)     ──→  LLM, strict   │
  │  LLM flagged it and the recheck confirmed:                         │
  │    the agent can settle it                      ──→  HOLD (deny +  │
  │                                                      a question)   │
  │    retried with an answer the judge accepts     ──→  ALLOW         │
  │    the developer's call, or flagged again       ──→  ASK (human)   │
  └───────────────────────────────────────────────────────────────────┘
                          │ still undecided ("ask")
                          ▼
  ┌─ PermissionRequest (learner) ────────────────────────────────────┐
  │  Re-run PreToolUse's rules: what they deny      ──→  DENY          │
  │  Permission-config write, unreadable command    ──→  ASK           │
  │  LLM configured?  ── yes ─→ LLM eval            ──→  ALLOW / ASK   │
  │                   └─ no                         ──→  ASK           │
  └───────────────────────────────────────────────────────────────────┘
                          │ still "ask"
                          ▼
              Standard Claude permission prompt
              (with "Always allow" option)
```

Every decision from both hooks is appended to a structured **decision log**
(see [Decision log](#decision-log) below).

### How the LLM judges a call

The LLM approves by default and flags a call only with concrete evidence of
one of five harms: irreversible destruction the task doesn't cover, making
private things public, leaking secrets, running untrusted remote code, or
lasting security weakening. The prompt borrows its risk categories from
Codex's auto-review policy, without Codex's rule that any possibly-sensitive
upload needs explicit authorization.

- **Context.** Along with the tool call, the LLM sees the working directory and
  the developer's last few messages from the session transcript. The messages
  tell it what task is underway, so a raw socket to a projector during a
  calibration session reads as normal work. Tool results, assistant text and
  harness notices are never sent, so file or web content can't argue its way
  past the judge. For a Bash command that can discard work (`git checkout`,
  `restore`, `reset`, `clean`, `switch`, `stash`) it also gets a read-only
  `git status --short` of the working directory and of any literal `cd` or
  `git -C` target (2s cap each, 40 lines, ignored files not listed), so a
  `git checkout --` of paths that hold no uncommitted or untracked changes
  goes through, and one over real edits is still flagged. Git also says whether
  each directory is a linked worktree: a discard there passes even over edits,
  wherever the worktree lives. A checkout of a bare repository gets no such pass,
  since the developer's own checkout is linked there too. For a command that adds,
  repoints or pushes to a git remote, it gets each remote's owner and whether that
  owner is yours, judged against `origin`'s fetch URL and your `gh` login. A push to
  an owner that's neither is flagged unless your messages name it.
  For a recursive delete, a `git branch -D` or a `git worktree remove --force`
  it gets what that would lose: the git checkouts inside a deleted folder (3
  levels deep at most) with their `git status`, commits no remote-tracking ref
  holds, remotes and stash count, or, for a folder inside a checkout, that
  checkout's status of it; for a branch, its tip, the commits only it holds and
  whether HEAD has it. For any of these and the discards above it also gets the
  **session provenance** of each target: when the folder was created against
  when this session's transcript starts, and the earliest and latest of this
  session's own earlier Bash commands that name it, a path inside it or its
  folder, with whether each failed. Only command text is read (from the newest
  16 MB of the main and subagent transcripts, within 1s), never tool output,
  and the block says what it is: evidence of what this session made, not your
  approval. With it the judge approves resetting or removing a checkout the
  session evidently made for its own experiments, and still flags one you said
  to keep, one that looks like a deliverable, or one with unclear provenance.
  A cleanup on another machine through an MCP tool with a `command` that
  looks like a delete or reset (`rm -r`, `Remove-Item -Recurse`, `rd /s`,
  `git worktree remove`, `git reset --hard`, `git clean -f`, `git checkout --`,
  `git restore`) can't be looked at from here. For the absolute paths its
  command names (whole words of plain path characters, bare or in one pair of quotes; nothing after a quote left open) and its `cwd`,
  four at most, the judge gets the first two and last three of this session's
  earlier calls to the same MCP server (any of its tools: their `command`,
  `cwd` and path fields) that name the path or one inside it, each with the
  tool's name, what the tool call returned and its redacted text. A `cwd` or
  path field counts whole; drive paths (`C:\…`) compare without case or slash
  direction. The hook doesn't parse the remote shell and never says a command
  ran or created anything: the judge reads the calls. An `ssh` call goes to
  the judge as before, without this history. A scratch checkout or worktree made from a pushed branch or commit
  that holds nothing unique is a flag the agent can settle from those calls
  and the checkout's git state, so it is held for the agent rather than put to
  you; a shared checkout or one holding deliverables stays yours.
  An MCP call whose `command` names a script file there by its absolute path
  (`powershell -File C:\…\run.ps1`, `bash /srv/x/run.sh`, not `~/…`; the
  extensions local scripts use, three files at most) gets the text this
  session wrote to that exact path through the same server's write tool
  (`write_file`, `write`, `create_file`, `put_file` or `save_file`, with a
  `path` or `file_path` and a `content`; `append: true` adds to the latest
  whole write), read in the same pass as the cleanup history: the write
  call's input, never the file read back, 8 KB a file and 16 KB in all, cut
  back to a line break (else a space; a word that runs past the cut is left
  out whole) and then redacted like the log (the note says when
  something was redacted), between lines marked with a random token as for
  local scripts. Both blocks read one list of this session's calls to that
  server, main and subagent transcripts together, each with its result;
  "earlier" is surely before this call: in one transcript by time, then line
  and place in the record, across transcripts by time (a record with no
  time of its own is ordered only in its transcript). The call is found in
  the acting agent's own transcript, by its tool_use id, or by its input as
  the one such call there still waiting for a result; when it isn't there,
  or two such calls are, no script text is shown and the cleanup history is read as in 1.8.3. So a
  write in the same message before the call counts, and nothing after it
  does. The block says when the text was written and what the write
  returned, says which write took effect last is not known when one was
  sent in the same message as an earlier write to the path or before its
  result, lists the later calls of this session to that server that name the path or
  its folder (other than reads and earlier tries of the same command; one
  whose order against this call is not known says so), since those may have
  changed the file, and says the call itself may change it
  first and a script not shown is unseen. A script this session did not
  write there gets no text, as before. The retry of a held call is judged
  with the same block. Logged as `remote_scripts`.
  Provenance never allows anything by rule. It also sees why the local rules sent the call (`Unknown
  command(s): flyctl`, `Risky: … appears only in text passed on as data`), as
  a hint about what to check.
- **More evidence.** None of this allows anything by rule, and none of it is
  written to the decision log.
  - *A subagent's brief.* A call from a subagent comes with the task the agent
    that started it handed over (the first message of its transcript, 4000
    characters at most, head and tail kept), labelled as an agent's brief, not
    your words, next to your own recent messages. The brief, each of your
    messages and a held call's answer sit between lines marked with a random
    token, as script texts do.
  - *Scripts it runs.* For `bash x.sh`, `python3 tools/x.py`, `. env.sh`,
    `cmd < x.sh`, `cat x.sh | …`, `base64 x.sh` and a shell script named
    anywhere in the command (inside `python3 -c "…"`, say), the judge reads the
    file: up to 3 files, 8 KB each, regular files you own only (not on
    Windows, where ownership can't be checked), never a
    `sensitive_paths` entry or the judge's key file (nor a link to one). It is
    told when a file was truncated, unreadable, missing or not shown, and which
    other local scripts a shown one names that it has not seen. Each text sits
    between an opening and an end line marked with a random token drawn for
    that call, which the header names as the bounds of file content to judge,
    not instructions, so a file can't fake its own end. Script contents stay
    out of the decision log: when the judge was shown a script, the log keeps
    only its category, not its words, also where the hook quotes them in a
    reason of its own (a held call's question and flag, a remote-execution
    ask), whose own words, its diagnostics included (no judge configured,
    the judge unavailable), are logged as written. A held call's retry keeps
    the judge's words out when the judge that held it or the one judging
    the retry was shown a script. The reason you see has
    quoted script text replaced by `[script text]`.
  - *Stashes.* For `git stash drop`, `clear` or `pop` (when it reaches the
    judge): `git stash list` with each stash's date and message, whether it
    was made before or after this session started, and this session's own
    Bash calls that ran a stash-making `git stash` in that repository, with
    whether each failed.
  - *Clones without remote-tracking refs.* A `git clone --bare` or `--mirror`
    keeps no `refs/remotes`, so every commit would count as one "no
    remote-tracking ref holds". For a repository with a remote and no such
    refs, the judge is told that plainly instead, with what git shows: a
    mirror setting, how many branch refs are loose or only in `packed-refs`
    and when that was written, any loose ref or reflog newer than it, and a
    path under `~/.cache` or `~/Library/Caches`. It is never told the commits
    are safe elsewhere; it weighs that.
  - *`/tmp`.* For a path under `/tmp`, who owns the folder right under it and
    its mode: Claude Code's own `/private/tmp/claude-<uid>` (yours, mode 700) is
    private, not world-writable, and an import path (`PYTHONPATH=…`) into it
    says so in the rule reason. A delete inside a git clone whose root is under
    `/tmp` names that clone's remotes; a file a glob names inside a repository
    gets git's view of it, as a folder does.
  - *Your notes on an MCP tool.* See `mcp_context` under
    [MCP tool permissions](#mcp-tool-permissions).
- **Messages are a partial view.** An agent often works from earlier
  instructions, a plan or a brief the judge never sees, so a call the latest
  message doesn't mention (cleanup after "where are we at?") is no reason to
  flag it. The judge flags on what a call does, not on whether it was asked
  for. Routine git housekeeping is named as safe: fetch, merge, pushes without
  `--force` (to `main` too), deleting branches other than the default, and
  removing worktrees, agent worktrees above all. Discarding uncommitted work
  still counts, but only in your main checkout, not in a linked worktree.
- **No cache.** Every call is judged afresh, so a verdict always reflects the
  current context. A timeout or error reports the total time spent
  (`LLM unavailable (…; 6.2s in all)`) and goes to you.
- **Strict verdicts.** Only an answer whose `safe` is the boolean `true`
  approves. A string (`"true"`), a number, or a missing or malformed verdict
  goes to you. A refusal to judge (Anthropic `stop_reason: refusal`, an
  OpenAI-compatible `refusal` or `content_filter`) counts as a flag: the hook
  asks you explicitly, with no recheck, rather than leaving the call to auto
  mode.
- **Second pass.** A flagged call is judged again at
  `SAFETY_HOOK_RECHECK_REASONING_EFFORT` (default `high`), with the first
  verdict attached. If the recheck clears it, the call runs (`source:
  llm-recheck`). If the recheck confirms it, the hook
  emits an explicit `ask`, so you decide — even in auto mode, where a silent
  fall-through would go to Claude's classifier instead. The PermissionRequest
  hook that fires for that prompt leaves it to you rather than asking the LLM a
  third time. If the recheck can't run in time, errors or gives no verdict,
  the first flag stands and the hook asks you explicitly.
- **No LLM hard denies.** Only the local rules deny outright: the
  dangerous patterns and the protected-delete guard below. A hold (next
  section) is a deny in form only: a question for the agent, not a refusal.

### Holds: the agent answers first

A flag the agent can settle is put to the agent before it reaches you (on
by default; `"holds": false` turns it off). The judge's verdict says who can
settle it (`resolver`: `agent` or `developer`) and what to ask (`question`).
When both
passes flag a call and the agent can settle it, the PreToolUse hook denies
the call with a question instead of prompting you:

> Held by smart-permissions (a question, not a refusal): the judge flagged it
> (category 1: …). Are those commits pushed anywhere? Write your answer as a
> message first, with the evidence (what you checked and what it showed; only
> text written after this hold is read), then retry the identical call; if
> you can't vouch for it, ask the developer.

The agent checks, writes its answer, and retries the same call. On that retry
the judge (one pass, at the recheck effort, with the evidence gathered again)
sees the hold and the agent's answer: the assistant text the acting agent
wrote to its own transcript since the hold, and the thinking the transcript
keeps (agents often settle the question there and retry with no visible
message); a subagent's answer is read from the subagent's transcript, never
the lead's; 3000 characters at most, tool input and harness notices left
out. The answer is a claim, not your approval: the judge clears the call when
it is specific, about this call's own targets and payload, contradicted by
nothing in the evidence or your messages, and settles the flag. Otherwise the call comes to you, with the hold reason in
the hook's words and the agent's answer labelled as its claim, not verified.

- **What is never held.** Category 2 (making things public) and 5 (lasting
  security weakening), destroying cloud, production or remote resources or
  data (`az … delete`/`purge`, `kubectl delete`, `terraform destroy`, `gh api
  -X DELETE`, …), sending secrets off the machine (a category 3 flag on a call
  that sends anything out, a `git push` included), a refused or malformed
  verdict, a verdict that does not name the agent as the one who can settle it
  or gives no category, a first pass that flagged one of these even when the
  recheck called it something else, and remote execution (below). These come
  to you directly.
- **One hold per call.** A hold is bound to the session, the acting agent, the
  working directory, the tool and its input (a Bash `description` is left out,
  so a cosmetic edit keeps the hold); a changed command is judged afresh. It
  lasts 15 minutes. A retry with no answer, a second flag, or a flag on a call
  already held once comes to you. A session gets at most 4 holds in 15 minutes;
  past that, flags come to you.
- **Your prompt stays yours.** When a retry comes to you, the PermissionRequest
  hook leaves the prompt to you, as it does for every explicit ask.
- **Off.** With `"holds": false` a confirmed flag is an explicit ask, as in
  1.6.0.

The holds live in `~/.claude/hooks/smart-permissions-holds/` (one small file
per hold: the reason, the question, the time and its state; never the agent's
answer). A write to that folder is a permission-config write (C9) and prompts.
Auto mode's denial limits (3 in a row, 20 in all) count its classifier's
blocks; as far as the docs and Claude Code 2.1.328 show, a hook's deny is not
counted, so holds do not push an auto-mode session into its fallback. In `-p`
mode a call that comes to you is denied, with the reason in the tool result.

### Remote and production execution

A command that runs code on another machine (`kubectl exec`/`cp`/`debug`,
`oc rsh`, `az containerapp exec`, `az vm run-command`, `az webapp ssh`, `aws
ecs execute-command`, `aws ssm send-command`, `gcloud compute ssh`, `fly ssh
console`, `heroku run`, `docker`/`podman`/`docker-compose` on a remote host:
`-H`, `--context`, `--remote`, `DOCKER_HOST`, or a remote `docker context use`;
also inside `script -c`) is judged
strictly, even when your `safe_commands` would allow it. It runs without a
prompt only when the judge is confident (`confident: true`) that it does what
your messages or the brief ask and nothing more, and the whole payload is in
the command text itself (inline, or a heredoc). A payload read from a local
file or another command (`< diag.sh`, a pipe, `--scripts @file`, `file://…`,
`--script-uri`, `source`, a Compose `run` whose service is defined in a local
compose file), anything with a `$` or a backtick (a variable or
`$(…)` filled in when it runs), or a file copy comes to you directly, with no
judge call: its payload never goes to the judge. Quoting is not parsed for
this, so a quoted pipe (`sh -c "ps | grep x"`) or a literal `$` asks too. Anything else (a flag, an unsure
verdict, no judge, an error) is an explicit ask that the PermissionRequest
hook leaves to you.
Remote execution is never held. Plain `ssh host cmd` is not in this class.

**Local scripts.** Running a project script (`./deploy.sh`, `bash x.sh`, `sh
x.sh`, also behind `env` or `timeout`, or inside `$(…)`) is a rules allow, so
the hooks read the script before allowing it: a local shell script the call
runs, sources or feeds to a shell (up to 12 of them, 64 KB each, only regular
files you own) is scanned for the remote-execution commands above and for deleting
cloud, production or remote resources. A remote exec inside it gets the strict
policy above, judged on the script's text (a script with a `$`, a pipe or a
redirect, one the judge is not shown whole, a call with a redirect, a pipe or
a heredoc, or one the call writes first comes to you without a judge call); a cloud delete
inside it goes to the judge instead of being allowed, comes to you when the
judge gives no answer, and a flag on it is never held. A script that can't be
read or is over 64 KB keeps the rules' answer, and so does a script in another
language (`python3 x.py`) or one a script calls in turn. Ordinary project
scripts are unaffected; one whose cloud CLI line has a delete word anywhere in
it (`kubectl get pods --context delete`) gets a judge call.

### Unanswered prompts: parked, not a freeze

A call that needs you (a permission prompt) no longer stops the session
until you come back. Claude Code shows the prompt while the PermissionRequest
hook is still running, and your answer applies at once. If you haven't
answered after `prompt_timeout_minutes` (default 10; `0` turns it off; 1 to
60), the hook denies the call with a message to Claude: it needed you, why it
couldn't be auto-approved (the reason you'd have seen), not to retry it or
get around the restriction with an equivalent command, to move on to other
work, and to list the call under "Parked for the developer" in its final
reply. It is never an allow. The decision log records it with source
`prompt-timeout`. The hook waits in one sleep and checks the session
transcript before denying: if you answered in the meantime, it does nothing.
In `claude -p` and other unattended runs (`CLAUDE_CODE_SESSION_ATTENDED=0`, or
an `sdk-*` entrypoint without that variable) it never waits: Claude Code
denies a prompt there itself. The hooks.json timeout of the learner (3660 s)
is above the longest setting; with manual setup, set yours the same way.

### Recursive deletes

Deleting your home folder or anything at its top level (`~/Dev`, `~/Desktop`,
`~/Documents`, `~/Library`, `~/.ssh`, ...) is denied locally, before the LLM is
asked, so "never" doesn't depend on a model's judgment. The guard resolves the
target first: `~`, `$HOME`, variables set earlier in the command, an empty
variable (`"$X"/Users/you`), `cd` plus a relative path, `..`, globs (`~/D*`),
brace expansion (`~/{Desktop,Documents}`), trailing `/*`, and case (`~/dev` on
macOS). It looks through keywords and wrappers (`do`, `!`, `env`, `nice -n 5`,
`time -p`, `builtin`, `sudo`, `xargs`), the same way the allowlist does. It also
blocks any folder above home. Add patterns to `protected_delete_paths`; `"~/Dev/*"` protects each
project root too.

The same deny covers the other ways to delete a whole folder: `srm -r`,
`rmdir` (with `-p`, each parent too), and `find` with `-delete` or
`-exec rm` started at a protected folder with nothing narrowing what it
matches (`find ~/Documents -delete`). A `find` that filters (`-name`,
`-type f`, `-mindepth 1`, …) goes to the LLM as a bulk delete. The guard also
reads code a command runs: a shell's `-c` string, heredoc or here-string
(`bash <<'EOF'`), text echoed or printed into `| sh`, a `trap` handler, a
`find -exec` command, `eval` and awk's `system()`, with any `cd` before it.
`unlink` and `shred` remove single files, not folders, and are not covered.

A recursive `rm` whose target leans on a variable that may be empty
(`rm -rf "$T/$k"`, which is `rm -rf /` when both are empty) is denied with a
rewrite: `"${T:?}/${k:?}"` makes the shell abort instead of deleting. Claude
Code stops for manual approval on the unguarded shape, and no hook can clear
that prompt, so the rewrite is what keeps the agent moving. A name the command
sets once to a literal before the `rm`, outside any condition, loop or
subshell (`S=/tmp/x; rm -rf "$S/t5"`), can't be empty and needs no guard.

The guard follows what the shell would do to reach the target: assignments,
`cd`, `pushd`/`popd`, loops, `|| exit`, zsh and bash word splitting, and values
it can't know (checked both as some folder and as empty). A target with too
many paths to check is denied with "list the targets". Three kinds of recursive
`rm` are allowed by rule because they only clear scratch space: a folder below
`/tmp`, and a Python or Dart cache (`__pycache__`, `.dart_tool`, …) in the
working directory, each spelled out in full, and anything strictly inside this
session's own scratchpad (an `rm` target may read a name set once to a
literal, as above; a `find … -delete` must be written all literal). The full rules, with the zsh and
bash details and the known limits, are in [GUARD.md](GUARD.md).

Every other recursive or bulk delete (`rm -r`, `find -delete`, `find -exec rm`,
`xargs rm`) goes to the LLM on every call. It is never auto-allowed by rule,
and its verdict covers only that call. The LLM sees the working directory, your
recent messages, the git checkouts the delete would take with them, and this
session's own earlier commands naming the target (see
[How the LLM judges a call](#how-the-llm-judges-a-call)). It approves build
output, caches, temp files and folders this session made for its own
experiments, and flags a whole project or data the task doesn't cover. Without an LLM configured, these
fall through to the normal prompt. The guard reads only the command text: a
delete hidden in a script file or an inline interpreter (`python -c`) reaches
the LLM through the other rules, not this one.

### What gets auto-allowed

- **Read-only tools** — Read, Glob, Grep, WebSearch (except reads of `sensitive_paths`)
- **File writes** to safe directories — `~/Dev/`, `/tmp/`, `~/.claude/`
- **Bash commands** using known tools — git, dotnet, compilers, file utilities, and 100+ more
- **Safe subcommands** of restricted tools — `npm install`, `docker build`, `gh pr view`, `cargo test`, etc.
- **Relative scripts** — `./build.sh`, `scripts/test.sh` (project scripts are trusted)
- **WebFetch** to allowed domains — GitHub, StackOverflow, language docs, etc.
- **MCP tools** matching `safe_mcp_tools` patterns — configure per-server with globs
- **Global flags** before subcommands — `docker --context prod build`, `npm --prefix /tmp run dev`, etc.
- **Dart** development commands — `dart test`, `analyze`, `format`, `fix --dry-run`, `pub get`/`upgrade`/`downgrade`/`deps`/`outdated`, `run`, `compile`, `doc`, `--version`, and `dart tool/x.dart` (a script, like `python3 x.py`)
- **macOS status reads** — `vm_stat`, `pmset -g`, `memory_pressure -Q`, `ioreg`, `iostat`, `diskutil list`/`info`, `scutil --get`, `csrutil status`, `sw_vers`, `sysctl`, `code --version`/`--list-extensions`
- **Scratch deletes** — a recursive `rm` of a folder below `/tmp`, of a Python/Dart cache in the working directory, or of anything inside this session's scratchpad (see [Recursive deletes](#recursive-deletes))
- **Agent worktree branches** — `git branch -D` when every branch named is one Claude Code made for an agent worktree (`worktree-agent-<hex>`)
- **Branches already on a remote** — `git branch -D` (or `-d -f`) of branches named plainly whose tips some remote-tracking ref holds, checked with one `git rev-list` in every directory the command may run git in, and only when nothing else in the command can make a commit, move a branch or drop a remote-tracking ref: every word of the command written literally (no `$`, glob, `~` or assignment), and beside it only readers such as `ls`, `tail`, read-only git subcommands with a short list of known options (`git status --short`, `git log --oneline -3`, `git rev-parse --abbrev-ref`; an option git would read as an abbreviation of another counts as unknown), `git worktree remove [--force] PATH`, a plain `git switch NAME` or another `git branch -D`; a directory not resolved, an unknown branch, a slow probe or anything else beside it goes to the LLM

### What gets blocked

- `sudo` anything
- `rm -rf /`, and a recursive delete of anything above home, by the protected-delete guard (any flag order or spelling, inside `$(…)` too)
- Recursive deletes of home or its top-level folders (see [Recursive deletes](#recursive-deletes))
- `curl | sh`, `wget | bash`, and other remote code execution chains
- Writes to device files (`> /dev/sda`), fork bombs, `mkfs`, `dd` to devices
- Write/Edit to sensitive paths (`~/.ssh/`, `~/.aws/`, `.env`, browser profiles, keychains). Reading them goes to the LLM (see below)
- Any of these inside code another command runs: `bash -c '…'`, `sh <<'EOF'`, `echo '…' | bash`, `trap '…' EXIT`, `find -exec sh -c '…'`, `eval`, awk's `system()`
- A plain force push to a branch other than `main`/`master` (`git push --force`, `-f`, `+branch`) is denied with a rewrite: push with `--force-with-lease` instead, which git refuses if someone else pushed in the meantime. A lease push is allowed.

Each deny says what to do instead: `sudo` asks the user to run the step themselves (`! sudo …`), `curl … | sh` to download the script to a file and show it first, a device write to use a regular file. Both hooks show the same message.

A dangerous pattern counts only where it can run. When it appears only in text passed on as data, the call goes to the LLM instead of being denied: an `echo`/`printf` argument, a `git commit`/`git tag` `-m` message, a `gh` `--body`/`--title`, or a quoted heredoc copied by `cat`/`tee` (`git commit -m 'drop sudo from the setup script'`). It is never allowed by rule. Anything else is code and is denied: any match in a command with a pipe, a group or a substitution (`echo '…' | sh`, `( … )`, `<(…)`), text written to a file in a command that also does something else (`echo '…' > a.sh; sh a.sh`), `printf -v`, a word with `$…` or a backtick, an unquoted heredoc with expansions, a heredoc fed to an interpreter, `trap`, `git log --grep`, or a parse the splitter is unsure of. To write such text to a file, use the Write tool or a heredoc on its own.

### What gets prompted

- **Dangerous subcommands** — `npm publish`, `docker run`, `docker exec`, `docker push`, `gh pr create`, `gh pr merge`, `cargo publish`, `pip uninstall`, `dart`/`flutter pub publish`, `pub token` and `pub global` (also behind global options or a wrapper: `dart --verbosity=all pub publish`, `xargs flutter pub publish`), and a `dart`/`flutter` subcommand built at run time (`flutter $S publish`), or any word built at run time unless the subcommand is `test`, `analyze`, `format`, `run` or a `.dart` script (`dart compile exe x -o "$OUT"`)
- `bash -c`, `sh -c`, `fish --command`, `osascript -e` (inline interpreter execution)
- **Code run by another command** — code a shell reads from a heredoc or here-string is checked like a top-level command: `bash <<'EOF'` with `ls` in it is allowed, with an unknown command it prompts. A shell fed from a pipe or a file (`… | sh`, `bash < f`), heredoc code with `$…` expansions, a login shell, an rc file or `BASH_ENV` (also when exported earlier in the command), fish code (its `-c` and `-C` init code are still read for denies and C9), an unknown command in a `trap` handler or `find -exec`, and an awk program that runs commands (`system()`, `print | "cmd"`) prompt. An interpreter other than a shell (python, node, ruby, perl, osascript, deno) reading its code from a heredoc, here-string, pipe or stream (`python3 - <<'EOF'`, `… | node`, `python3 /dev/stdin`, `python3 < x.py`, which zsh joins to a pipe) goes to the LLM, as its `-c`/`-e` code does. Running a script file (`python3 foo.py`, also with a heredoc as its input), a module (`python3 -m …`) or `--version` is allowed when every option before it is a plain one the rules know (`python3 -I`, `-X dev`, `node --max-old-space-size=4096`); any other option might take the next word as its value
- `rm *` or `rm .*` (wildcard deletion)
- `find -delete` or `find -exec rm` with a filter (`find / -name tmp -delete`)
- **Risky operations of allowed tools** (always to the LLM; a long option counts in any prefix the tool reads as it, `git reset --har`, `rm --rec`) — a `git push` to a remote whose owner is neither `origin`'s nor your `gh` login, `git reset --hard`, `git clean -f`, `git checkout` of a file or `.` (an operand that is a glob, has a file extension or exists in the folder counts as a file), `git checkout -f`/`git switch -f`, `git restore` of the work tree, `git stash drop`/`clear`, `git branch -D`, `git filter-branch`, a force push to `main`/`master` or with no branch named, a push that deletes a remote branch, `git -c` settings that run a command (an `alias.*` that isn't `!cmd` is read as the git command it stands for; a pager or editor that is `less`, `more` or a plain allowed command, like `core.pager=cat`, is fine, and so are `core.hooksPath=/dev/null` and an empty `credential.helper=`, which switch hooks and helpers off for that run); `curl` uploads of local files (`-d @file`, `-F f=@file`, `-T`, `-K`) and `wget --post-file`; `chmod -R` that makes a tree world-writable; `docker volume rm`/`prune`, `docker system prune`, `docker compose down -v`; writes to raw disks (`/dev/disk*`, `/dev/sd*`); writes to shell startup files (`~/.zshrc`, `~/.bashrc`, …) and `~/Library/LaunchAgents`, also as a `dart`/`flutter` option's value (`dart compile js x.dart -o ~/.zshrc`); `git config` writes of a key that runs code, loads a file or sends code elsewhere (`core.hooksPath`, `core.sshCommand`, `credential.helper`, `filter.*`, any `alias.*`, `include.path`, `init.templateDir`, `safe.directory`, `url.*.insteadOf`, `remote.*.url`, the same keys `git -c` checks; reads, unsets and keys like `user.email` are fine); `git remote add`/`set-url`, `git push --all`, and a push to a URL rather than a configured remote (a plain `git push origin main` is unchanged); and `defaults write`/`delete`/`delete-all`/`import`/`rename` (reads are fine)
- **Sensitive paths read** — Read, Glob or Grep of a `sensitive_paths` entry (also a file glob that can match one, like `**/.ssh*` or `*.env`), and a Bash command naming one (`cat ~/.ssh/id_rsa`, `cat .env`, `git show HEAD:.env`, `sqlite3 ~/Library/…/Chrome/Default/Cookies`). The defaults include the Chrome, Brave, Edge, Arc, Chromium and Firefox profile folders, Safari's cookies, `~/Library/Keychains`, and the store files by name (`Login Data`, `Local State`, `key4.db`, `cookies.sqlite`, `Cookies.binarycookies`) for a copy elsewhere
- Archive extraction to system roots (`tar -C /usr/`)
- **Subcommands not on the list** — a command that ships (or is configured) only with multi-word entries, like `docker`, `npm`, `gh`, `terraform`, `kubectl`, `cargo`, `helm`, `pip`, is unknown with any other subcommand (`docker run`, `npm publish`): it is never approved by rule, and goes to the LLM or, without one, to you.
- **Words built at run time where they decide the verdict** — a `$VAR`, `$(…)`, unquoted glob or brace expansion in a word the rules read to choose a verdict: a git option or subcommand (`git $S --hard`, `git reset --h{a..a}rd`, `git -c "$K" log`), any word of a git subcommand the risky-operation checks read (`git checkout $B`, `git push origin HEAD:$R`), any word of `docker volume`/`system`/`compose`, a `chmod` mode, or a subcommand matched against a multi-word entry (`az {group,x} list`). A quoted value of `git -C`, `--git-dir` or `--work-tree` is one word whatever it holds, so `git -C "$W" status` and `git -C "$(pwd)" status` are still allowed; an unquoted `git -C $W` (or a quoted `"$@"`) can split into a subcommand and goes to the LLM. A `git -c alias.…` makes every word deciding, and so does a wrapper the rules can't line up with its words (`env -S "git $S"`). Built words elsewhere (`git log $R`, `chmod +x $F`) are fine, and so is a word built only from names the command sets once to a literal before it, outside any condition, loop or subshell (`B=main; git push origin $B` is judged as `git push origin main`).
- **Environment that runs other code** — a command that sets a variable a tool runs as a program (`GIT_SSH_COMMAND`, `GIT_PAGER`, `PAGER`, `GIT_EDITOR`, `EDITOR`, `VISUAL`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PROXY_COMMAND`, …) to anything but `less`, `more` or a plain allowed command, or sets a loader variable at all (`LD_*`, `DYLD_*`, `BASH_ENV`, `GIT_EXEC_PATH`, `GIT_CONFIG_*`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONUSERBASE`, `PERL5OPT`, `JAVA_TOOL_OPTIONS`, …), or sets an import path (`PYTHONPATH`, `NODE_PATH`, `RUBYLIB`, `PERL5LIB`, `LD_LIBRARY_PATH`) to anything but relative paths inside the working folder in a single command (`PYTHONPATH=src pytest`, `.:lib`, `src:$PYTHONPATH` are fine; `/tmp`, `../x`, `~/x` and `$PWD/src` go to the LLM). Beside other commands, a relative path is fine when each of them is a `cd` or a command that can't plant a link (`tail`, `grep`, …) and every directory the command may be in is the working folder or a linked worktree of its repository (`cd ../app-wt && PYTHONPATH=src pytest | tail`); a `cd` elsewhere, or `git`, `ln` and the like beside it, go to the LLM. So does an option that runs the program in another folder, as a `cd` would (`make -C`, `env -C`, `uv run --directory`, `npm --prefix`, `go -C`, `cargo --manifest-path`, `git -C`, …), in any spelling the program's parser may read as one (a letter in a cluster, `make -sC x`; a prefix of the long option, `make --dir=x`; go's `-C=x`), and for `npm`, `npx`, `pnpm`, `yarn`, `bun` and `gradle`, whose parsers aren't modelled, any option at all, unless the folder, links resolved, is inside the working folder or a linked worktree of its repository: `PYTHONPATH=src make -C /tmp/x test` goes to the LLM, `PYTHONPATH=src make -C sub test` is fine. `NODE_OPTIONS` and `RUBYOPT` are fine when every option loads nothing (`--max-old-space-size=8192`, `--enable-source-maps`, `-W0`). Such a word counts anywhere in a command except as an argument a plain command just passes on (`git commit -m "PAGER=x"`): a leading assignment, `env` (also `env -S '…'` and behind other wrappers), `export`, `declare`/`local`/`typeset`, also behind `builtin` or `command`. An append (`PAGER+=…`), an element (`PAGER[1]=…`), an array (`LD_PRELOAD=(…)`) and, after a wrapper or builtin, a name built at run time (`export "$K=…"`, a brace or backtick in the name) always count. `GIT_PAGER=cat git log` is allowed, `GIT_SSH_COMMAND="sh -c …" git fetch` goes to the LLM. A value set without `=` (`read`, `printf -v`) isn't read.
- **Function bodies** — every form of a function the command defines (`f() { …; }`, `f() ( … )`, `function f { … }`, zsh's `f() cmd`) is checked command by command like the top level, and so is each `case` arm.
- **Bulk push to a new remote** — a command that adds or repoints a remote (`git remote add`, `set-url`, or `git config` of its URL) and pushes every branch to it, or pushes every branch to a URL. Every branch means `--all`, `--branches`, `--mirror`, a refspec like `refs/heads/*`, or a remote added with `--mirror`; a push naming no remote counts as going to the new one. No LLM verdict can clear it
- **Permission-config writes (C9)** — Write/Edit/NotebookEdit targeting `~/.claude/settings*`, `~/.claude/hooks/`, `~/.claude/keybindings.json`, or the plugin's own config / log / LLM-flag files, and Bash commands that write to them (`tee`, `>`, `sed -i`, `mv`, `ln`, a `dart`/`flutter` command that names one (`dart compile exe x -o …`), or a `cp`/`install`/`rsync` whose destination is one; copying one of them elsewhere is a read) anywhere in the command: after `;` or `&`, inside `if`/`for` bodies, functions, groups and `$(…)`. A Bash command that names one of those paths but can't be parsed with confidence prompts too. These *always* prompt — never auto-allowed, never LLM-vouched, whatever else the command does short of a hard deny — even when their parent (`~/.claude/`) is a safe write path, so the agent can't rewrite its own permission rules. The hook emits an explicit `ask` for them rather than falling through, so neither a native allow rule (`Bash(cp:*)`, an earlier "Always allow") nor auto mode can approve one. Both hooks apply the same check. This guard is not subtractable.
- WebFetch to domains not in the allow list
- MCP tools not matching any `safe_mcp_tools` pattern
- Anything else the rules can't settle (a novel CLI tool, a write outside the safe folders), when no LLM is configured

With an LLM configured, everything in this list except permission-config writes and bulk pushes to a new remote goes to the LLM first, and you see only what it won't approve. When something *does* prompt, you get the standard Claude permission dialog with "Always allow", so it only prompts once if you choose to permanently allow it — except a permission-config write, which asks every time.

## Security model / threat boundary

**This plugin is a guardrail, not a sandbox.** It reduces friction and catches obvious mistakes: it blocks plainly-dangerous commands (`sudo`, `rm -rf /`, `curl … | sh`), routes unknown commands through the LLM or the permission prompt, and auto-approves the ones you've marked (or that are obviously) safe. That is its whole job.

It is **not** a security boundary against a determined adversarial agent that already has Bash access. A shell can write files through indirection that static command analysis cannot fully see — variables (`CFG=~/.claude/settings.json; cp x "$CFG"`), `cd` plus relative paths, hardlinks, script *files* whose contents aren't inspected (`bash /tmp/p.sh`), or archive extraction (`tar -C ~/.claude …`). Writes to the plugin's own config/log/settings via those routes cannot be reliably prevented by a hook, and none of them were preventable before this plugin either. The Bash config-path write guard is **best-effort for naive/accidental cases only** — do not treat it as airtight.

The permission-config files live in the **user trust domain** (`~/.claude/`): anything running as you can ultimately reach them. If you need a real boundary against untrusted code, use OS-level sandboxing (containers, VMs, seccomp/AppArmor) — not this plugin.

- Guardrail against mistakes and unknown commands: **yes.**
- Barrier against code actively trying to escalate its own permissions: **no** — use OS sandboxing.
- The plugin keeps no LLM decision cache, so there is no stored verdict to plant or go stale. Its one LLM state file (`smart-permissions-llm-flags.json`) can only turn an LLM call into a prompt, and it is a C9 path.

## Configuration

Your personal config lives at `~/.claude/smart-permissions-config.json`. It's generated automatically the first time the hook runs, with example values to guide you. Run `/smart-permissions:setup` to configure interactively, or edit the file directly.

**Arrays are merged** (union) with the built-in defaults, so you only need to add what's unique to your workflow.

### Config keys

| Key | Type | Description |
|-----|------|-------------|
| `safe_commands` | string array | Commands auto-allowed in Bash — supports single (`git`), multi-word (`flutter doctor`), and wildcards (`kubectl get*`) |
| `safe_write_paths` | string array | Directories where Write/Edit are auto-allowed (supports `~/`) |
| `safe_script_paths` | string array | Directories where absolute-path scripts are auto-allowed |
| `allowed_web_domains` | string array | Domains auto-allowed for WebFetch (subdomains included) |
| `safe_mcp_tools` | string array | MCP tool name patterns auto-allowed (supports glob wildcards) |
| `mcp_context` | object | `{"MCP tool glob": "sentence"}`: a note the LLM judge reads with each call to a matching MCP tool (see [MCP tool permissions](#mcp-tool-permissions)). Context only, never an allow. Empty by default. |
| `safe_internal_tools` | string array | Claude Code / harness internal tools auto-allowed (no side effects outside the harness) |
| `sensitive_paths` | string array | Write/Edit to a path containing one is denied (substring match); Read/Glob/Grep of one, and Bash commands naming one, go to the LLM (matched where a path component ends, case-insensitive: `/.env` matches `.env.local`, not `.envrc`) |
| `always_ask_write_paths` | string array | Path substrings that always prompt on Write/Edit (permission-config self-escalation guard, C9). **Not subtractable.** |
| `dangerous_patterns` | string array | Regex patterns that deny when they match code (the whole command or one of its commands); a match only in data goes to the LLM |
| `protected_delete_paths` | string array | Folders a recursive delete may never touch, nor anything above them (default `~`, `~/*`; globs expand on disk). **Not subtractable.** |
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |
| `remove_from_defaults` | object | Subtract shipped entries from allowlist keys (see [Subtracting defaults](#subtracting-defaults)) |
| `holds` | bool | Put a flag the agent can settle to the agent first, as a question, before it reaches you (default `true`; see [Holds](#holds-the-agent-answers-first)) |
| `prompt_timeout_minutes` | number | Deny a permission prompt you leave unanswered this long, with a message that parks the call for you (default `10`, `0` off, 1 to 60; see [Unanswered prompts](#unanswered-prompts-parked-not-a-freeze)) |
| `decision_log` | bool | Log every decision to `~/.claude/hooks/smart-permissions-decisions.jsonl` (default `true`) |
| `decision_log_full_input` | bool | Log each input up to 64 KB instead of 500/8000 chars, with obvious secrets redacted (default `false`; see [Decision log](#decision-log)) |

Positive allowlists (`safe_commands`, `safe_write_paths`, `safe_script_paths`, `allowed_web_domains`, `safe_mcp_tools`, `safe_internal_tools`) merge as a union with the defaults. Scalars and objects (like `interpreter_exec_flags`) are replaced wholesale.

### Subtracting defaults

Arrays only ever *add* to the defaults, so to remove a shipped entry use `remove_from_defaults`. It accepts the positive allowlist keys **only** — deny/prompt controls (`dangerous_patterns`, `risky_patterns`, `sensitive_paths`, `always_ask_write_paths`, `protected_delete_paths`) can never be weakened this way.

```json
{
  "remove_from_defaults": {
    "safe_commands": ["rm", "docker build *"],
    "allowed_web_domains": ["npmjs.com"]
  }
}
```

Removal is applied last, after defaults + platform overlay + your additions. A command whose entry you remove is unknown: it goes to the LLM or, without one, to you. Nothing unknown is ever allowed by rule.

### Decision log

Every decision from both hooks is appended as one JSON object per line to `~/.claude/hooks/smart-permissions-decisions.jsonl` (override with `decision_log_path`, disable with `"decision_log": false`). Each record captures the timestamp, the plugin version (`v`), hook, tool, input (a Bash command, a file path, an MCP tool's `command` and `cwd` or else its whole input as compact JSON; truncated at 500 chars for an allow, 8000 for an ask or deny, so the calls that stopped you can be read in full; `input_len` is the full length and `truncated` says whether it was cut), decision, source (`rule` / `llm` / `llm-recheck` / `learner`, and with holds `llm-hold` for a held call and `hold-retry` for its retry, and `prompt-timeout` for a prompt you left unanswered, which the learner denied and parked; logs from older versions also hold `llm-cache`), reason, and timing. With holds on, a flag records `hold`: `held`, `cleared` or `asked` for a hold and its retry, or why a flag was not held (`not held: …`); a remote-exec ask records `remote-exec`. The agent's answer is never logged. Records from versions before auto-learning was removed may also carry a `learned` list. When the LLM decides, `rule_reason` records why the local rules didn't settle the call, so `jq -r .rule_reason` over the log shows which rule gaps drive LLM traffic. Every PermissionRequest record carries one (also for a prior flag, a missing judge, or input the hook couldn't parse). Calls from other agent CLIs (see below) also record the original `client_tool` name. When the LLM was asked about a delete or reset whose target it could name, `provenance` says whether session provenance was attached: `found` (this session made or used a target; for a cleanup through an MCP tool on another machine, only that an earlier call's text names the path), `none` (nothing ties a target to it) or `unavailable` (no readable transcript). The log is created readable by you only (0600; an existing log with group or other bits is narrowed). It rotates to a single `.jsonl.1` generation at 20 MB, under a lock so the two hooks never rotate twice. With `"decision_log_full_input": true`, each input is kept up to 64 KB with obvious secrets (private key blocks, bearer and basic auth headers, URL passwords, common token shapes, `*_KEY`/`*_SECRET`/`*_TOKEN`/`*_PASSWORD` values and `--password`-style flags) replaced by `[REDACTED]` (in an MCP input logged as JSON, in each value, and a field named like a credential whole); such records add `redacted`, and `incomplete` when the input was redacted or cut. Redaction is best-effort, so the privacy note below still applies. Run `/smart-permissions:stats` to summarize it.

> **Privacy:** the logged `input` can contain whatever appeared on a command line, path, or URL — including secrets. Treat the log as the same trust class as your shell history.

## MCP tool permissions

MCP tools use glob patterns for flexible approval. This lets you auto-approve read-only operations while prompting for write/modify operations:

```json
{
  "safe_mcp_tools": [
    "mcp__sentry__get_*",
    "mcp__sentry__list_*"
  ]
}
```

With this config, `mcp__sentry__get_issue` is auto-allowed, but `mcp__sentry__resolve_issue` prompts with the standard Claude dialog (including "Always allow").

Patterns use Python's `fnmatch` — `*` matches any characters, `?` matches a single character. For example, `mcp__*__get_*` matches all get operations from any MCP server.

An MCP tool that matches no pattern goes to the LLM (if configured) on each call, and to the standard prompt otherwise. An LLM approval is never saved as a pattern.

The judge knows nothing about the machine an MCP server reaches. `mcp_context` tells it, one sentence per tool glob (up to 500 characters; every matching sentence is sent, five at most):

```json
{
  "mcp_context": {
    "mcp__bench__*": "The developer's Windows test bench. Commands run as the bench's own account; C:\\Users\\bench is that account's home, not another person's."
  }
}
```

A note is evidence for the judge, not an allow: it still flags what the call does if that is harmful. A value that isn't an object of strings is ignored.

## How Bash commands are parsed

The hook includes a full compound command parser. It doesn't just look at the first word — it splits the entire command into individual sub-commands and checks each one:

```bash
cd /tmp && git clone https://... && make install
# → splits into 3 commands: cd, git, make — all checked individually

DOTNET_CLI_TELEMETRY=0 dotnet build -c Release
# → skips the env var assignment, checks "dotnet"

for f in *.txt; do echo "$f"; done
# → recognizes shell keywords (for, do, done, echo)
```

The parser handles compound operators (`&&`, `||`, `;`, `|`, `|&`, and a lone `&` that backgrounds a job — `2>&1`, `&>` and `>&` stay redirections), quoting, backslash escapes, heredocs, subshells and `{ }` groups (also with redirections after them), line continuations, `case...esac`, function definitions, loops, and variable assignments. Redirections before the command word (`< /dev/null cmd`, `2>/dev/null cmd`) are skipped, so `cmd` is what gets checked. Transparent runners (`env`, `timeout`, `nohup`, `xargs`, `command`, …) are peeled so the *inner* command is what gets checked (`xargs docker run` is evaluated as `docker run`, not auto-allowed as `xargs`), also after leading assignments (`TMPDIR=/tmp/x timeout 300 dart test`), and indirect command words — `$VAR`, `\docker`, and meta-execution builtins (`eval`, `source`, `.`) — are treated as unknown rather than trusted.

One exception for `$VAR`: when the command sets the variable exactly once, unconditionally and at top level, to a literal (`PY=.venv/bin/python; $PY -I x.py`), the command word is read as that value and checked like any other command (`K=kubectl; $K delete …` still goes to the LLM). Every read of such a variable is written in, inside a word too (`G=git; F=hard; $G reset --$F` is `git reset --hard`), and a command that still holds a word built at run time after that (`$PY x.py $R`, `--${F:-hard}`, an unquoted brace or glob) goes to the LLM. A `~/…` value is read as the home path it expands to on assignment. Anything that could change or split the value turns the exception off: a second assignment, a read before the assignment, an assignment inside `if`, a loop, a group or after `cd x &&`, `read`/`eval`/`source`/`declare`/`printf -v`/`unset`/`export NAME`, a function, `trap`, a heredoc, a comment, a line continuation, `IFS`, or a special name like `PATH`. A control word or bracket anywhere before the assignment turns it off too, even as an argument (`echo fi`). The protected-delete guard and the permission-config check also read the command with the value written in, so `R=rm; cd ~ && $R -rf Documents` is denied and `C=cp; $C x ~/.claude/settings.json` goes to you. An `xargs` with a replace string (`-I`, `-J`, `-i`) goes to the LLM, since its input fills in words of the command.

If **any** sub-command in a compound command is unknown, the entire command goes to the LLM or, without one, to the permission prompt. A deny anywhere in the command wins over an ask earlier in it.

Code that runs as part of the command is checked too:

- **Command substitution** — `$(…)`, backticks and `<(…)`/`>(…)` bodies are evaluated with the same rules (recursively), including inside double quotes and unquoted heredoc bodies. Single-quoted text and quoted heredocs (`<<'EOF'`) are literal and skipped.
- **Reserved words** — `then X`, `do X`, `else X`, `! X` check `X`, not the keyword.
- **`case` patterns** — `a|b)` alternations are patterns, not pipes.
- **Inline Python** — `python3 -c CODE` is allowed by rule when the code is data-only: imports limited to stdlib data modules (`json`, `re`, `collections`, `csv`, …), no dunder access, no `exec`/`eval`/`getattr`, `open()` only read-only with a literal mode, and no `PYTHON*`/`LD_*`/`DYLD_*` env overrides. That covers the common `… | python3 -c "import json,sys; …"` pattern. Anything else still goes to the LLM.

### Other agent CLIs

The hooks accept camelCase payloads (`toolName`/`toolInput`) and map Grok CLI tool names onto their Claude equivalents — `read_file` → Read, `grep` → Grep, `list_dir` → Glob, `run_terminal_command` → Bash, `search_replace`/`write` → Edit/Write, `web_search`/`web_fetch` → WebSearch/WebFetch — so the same rules apply. Unmapped tool names are treated as unknown.

> **Limitation:** commands executed indirectly through a **script file** (e.g. `bash /tmp/setup.sh`, where the dangerous command lives *inside* the file) are not statically inspected — the file's contents aren't visible to the parser. Defense for that path relies on the dangerous/risky pattern checks and, when configured, the LLM evaluation.

### Multi-word commands and wildcards

The `safe_commands` list supports multi-word entries for granular subcommand control, and wildcards for flexible matching:

```json
{
  "safe_commands": [
    "flutter doctor",
    "flutter build",
    "kubectl get *",
    "docker compose *",
    "terraform plan"
  ]
}
```

**Matching priority** (longest match wins):
- `"docker compose up"` — allows only that exact 3-word command
- `"flutter doctor"` — allows `flutter doctor` and `flutter doctor --verbose`, but NOT `flutter run`
- `"kubectl get*"` — allows `kubectl get`, `kubectl get pods`, `kubectl get-contexts`, but NOT `kubectl delete`
- `"docker *"` — allows all docker subcommands (equivalent to just `"docker"`)
- `"git"` — single-word, allows all subcommands (existing behavior)

Wildcards use Python's `fnmatch` — `*` matches any characters, `?` matches a single character.

If you want blanket approval for a tool, add the single-word entry (e.g. `"flutter"`) to your config. Prefer multi-word entries for tools that have destructive subcommands.

### Default subcommand restrictions

The built-in defaults use multi-word entries to restrict tools that have both safe and dangerous subcommands:

| Tool | Auto-allowed | Prompts |
|------|-------------|---------|
| **docker** | `build`, `ps`, `images`, `logs`, `inspect`, `compose *`, `pull`, `stop`, `start`, etc. | `run`, `exec`, `push` |
| **gh** | `pr view/list/status/diff`, `issue view/list`, `repo view/list/clone`, `run view/list`, `search`, `browse` | `pr create/merge/close`, `issue create`, `repo delete`, `api` |
| **npm** | `install`, `test`, `run *`, `list`, `audit`, `ci`, `init`, `pack`, `link`, `update`, etc. | `publish`, `unpublish` |
| **cargo** | `build *`, `test *`, `check *`, `run *`, `clippy *`, `fmt *`, `doc *`, etc. | `publish` |
| **pip** | `install *`, `list`, `show *`, `freeze`, `check`, etc. | `uninstall` |
| **glab** | `ci list/view/trace/status/lint`, `mr list/view/diff/checkout`, `issue list/view`, `repo view/clone`, `release list/view` | `mr create/merge`, `api`, everything else |
| **az** | any `list`/`show` subcommand (`az vm list`, `az role assignment list`), `list-instances/-usage/-skus`, `monitor log-analytics query`, `graph query`, `account show` | create/delete/update, and credential reads (`keys`, `secret`, `connection-string`, `get-access-token`, `--show-values`) |
| **uv** | `sync`, `lock`, `tree`, `pip list/show/freeze`, `run pytest/ruff/mypy/…` | `run` of anything else, `pip install` |
| **pnpm/yarn/poetry** | Common dev subcommands | `publish` |

Tools like `git`, `dotnet`, `make`, and `brew` remain single-word (all subcommands allowed) since their operations are generally safe for local development.

## Manual setup

If you prefer not to use the plugin system:

1. From this folder, copy the `smart_permissions` package (the code of both
   hooks), the config and **both** entry scripts into one directory, in this
   order:
   ```bash
   mkdir -p ~/.claude/hooks/smart-permissions/config
   cp -R scripts/smart_permissions ~/.claude/hooks/smart-permissions/
   cp -R config/. ~/.claude/hooks/smart-permissions/config/
   cp scripts/pretool_safety.py scripts/permission_learner.py ~/.claude/hooks/smart-permissions/
   ```
   To update, run the same commands again: the entry scripts and the package
   must come from the same version, and the entry scripts go last. While the
   package is missing or half-copied, the PreToolUse hook blocks every call.

2. Register **both** hooks in `~/.claude/settings.json`:
   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/hooks/smart-permissions/pretool_safety.py",
               "timeout": 45
             }
           ]
         }
       ],
       "PermissionRequest": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/hooks/smart-permissions/permission_learner.py",
               "timeout": 3660
             }
           ]
         }
       ]
     }
   }
   ```

   The PreToolUse hook alone still blocks dangerous commands and auto-allows safe
   ones, but without the PermissionRequest hook you lose its LLM pass on the
   calls PreToolUse leaves to the prompt.

## Testing

```bash
cd smart-permissions
python3 tests/test_hooks.py
```

Covers all decision paths: safe commands, dangerous patterns, risky patterns, file paths, web domains, MCP tools, compound commands, the no-LLM prompt path, and edge cases. Dangerous test payloads are base64-encoded so they don't trigger live safety hooks.

```bash
python3 tests/test_contract.py            # about 6 s (about 20 s on Python 3.9)
```

The hook-contract suite runs both hooks exactly as `hooks/hooks.json` invokes them, each in a sandbox with its own `HOME` and a local fake judge, and checks what they do as seen from outside: exit status, output or silence, stderr, every judge request and the evidence in it, the decision-log records in order, and the flag and hold files, including PreToolUse → PermissionRequest and hold → retry sequences. It compares all of that with the snapshot in `tests/contract_golden.json` (`--update` rewrites it; review the diff), so a restructuring can be shown to change nothing observable. `-k <text>` runs the matching cases; `SP_CONTRACT_PYTHON=/path/to/python3` runs the hooks on another interpreter.

**Code layout.** `scripts/pretool_safety.py` and `scripts/permission_learner.py` are short entry scripts over the `scripts/smart_permissions/` package, which is built in layers. At the bottom are the modules that never import the hooks: `config.py` (config loading, the state file paths and `HOOK_VERSION`), `util.py`, `state.py` (the per-call state), `payload.py` (normalizing other agent CLIs' payloads), `log.py` (the decision log: `log_decision`, input, redaction and append), `holds.py` (the holds store), `flags.py` (the flag store), `transcript.py` (reading session transcripts) and `judge.py` (the judge's settings, prompts and HTTP client, and its verdicts: both passes and the retry). Above them is `core.py`: the shell parser, the rules and gates, and the PreToolUse hook. Above core are `context/` (what the judge is shown: `build_llm_context` and its `git`, `provenance`, `loss`, `scripts` and `notes` blocks) and `holdflow.py` (holding a call for the agent, and judging its retry). They read commands with core's parser, and the PreToolUse hook imports them only when a call goes to the judge. On top is `learner.py`, the PermissionRequest hook. A module imports only from the layers below it, and only the names it uses; `test_package_modules` checks both. So a name is reached in the module that defines it (`judge.llm_evaluate`, `config.HOME_DIR`), and a test that rebinds a module global must rebind it in the module whose code reads it. What one hook call knows beyond its tool input (the session's working directory and scratchpad, the client's tool name, what the judge was shown) is a `CallState`: each hook's `main()` creates one and activates it with `using_state` for the whole call (the active state is per thread), the hook's flow passes it on explicitly, and the rules read it with `current_state()`. A test builds its own: `with state.using_state(state.CallState(cwd=...)):`, from `smart_permissions.state`.

`python3 tests/llm_eval.py --runs 5 --include-unreached` runs the labelled cases in `tests/llm_eval_cases.json` through the real LLM judge with your `SAFETY_HOOK_*` settings and reports recall, false flags and latency. It makes real API calls, so it isn't part of the test suite; without a key it prints SKIP. `--rules` shows the rule verdicts only.

### LLM environment variables

| Variable | Description |
|----------|-------------|
| `SAFETY_HOOK_MODEL` | Model name (e.g. `claude-haiku-5-5`, `gpt-5.4-mini`, `grok-4.3`) |
| `SAFETY_HOOK_API_KEY` | API key (LLM disabled if empty). For Claude models, falls back to `ANTHROPIC_API_KEY`. |
| `SAFETY_HOOK_API_URL` | Endpoint. OpenAI-compatible chat completions (e.g. `https://api.openai.com/v1/chat/completions`) or the Anthropic Messages API. Optional for `claude-*` models (defaults to `https://api.anthropic.com/v1/messages`). |
| `SAFETY_HOOK_PROVIDER` | Optional wire format override: `anthropic` or `openai`. Auto-detected otherwise: an `anthropic.com` URL, or a `claude-*` model with no URL, uses the Messages API; everything else uses chat completions. |
| `SAFETY_HOOK_REASONING_EFFORT` | Optional effort (e.g. `none`, `low`, `medium`, `high`). OpenAI-compatible: sent as `reasoning_effort`. Anthropic: sent as `output_config.effort`, with `none`/`minimal` mapped to `low`. Only sent if set. |
| `SAFETY_HOOK_RECHECK_REASONING_EFFORT` | `reasoning_effort` for the second pass on a flagged call (default `high`; empty string = provider default) |
| `SAFETY_HOOK_AUTO_LEARN` | **Retired** — ignored. Approvals are no longer written to the config; remove it from your shell config. |

**A key file for processes without your shell's environment.** A Claude Code started from an app, a launcher or a non-interactive shell may not have the variables from `~/.zshrc`, and then has no judge: everything the rules can't settle prompts. When `SAFETY_HOOK_MODEL` or `SAFETY_HOOK_API_KEY` is missing from the environment, the hooks read the same variables from `smart-permissions-llm.env` beside your config (`~/.claude/smart-permissions-llm.env`, or beside `SMART_PERMISSIONS_CONFIG`). Lines are `NAME=value`, with an optional `export` and quotes; `#` starts a comment; only the `SAFETY_HOOK_*` names above are read. A variable that is set in the environment wins over the file. Create the file yourself and make it private:

```bash
touch ~/.claude/smart-permissions-llm.env && chmod 600 ~/.claude/smart-permissions-llm.env
# then add, in an editor:  SAFETY_HOOK_MODEL=claude-haiku-5-5  and  SAFETY_HOOK_API_KEY=...
```

The hooks ignore it, and say why when the judge is reported unavailable, if it is readable or writable by anyone but you, owned by someone else, a symbolic link, not a regular file or over 64 KB. The check reads the file's mode bits, not access-control lists: don't add an ACL entry that grants it to others (`ls -le` shows them on macOS). On Windows, where the hooks can't check that, it is always ignored: use the environment there. It is a sensitive path: Claude's writes to it are denied, its reads go to the judge, and its text is never shown to the judge as a script.

## Audit log

All unknown commands and tools are logged to `~/.claude/hooks/unknown-permissions.log` for review.

## Windows support

Windows is supported with automatic loading of `config/defaults-windows.json` (PowerShell/cmd commands, Windows dev tools, Windows-specific dangerous patterns). You may need to adjust `safe_write_paths` for Windows directories and use `python` instead of `python3` for manual setup.

## Requirements

- Python 3.9+ (stdlib only — no pip dependencies)
- Claude Code
- macOS, Linux, or Windows

## Changelog

- **1.8.4 (2026-11-24) — a script on another machine is shown as this session wrote it.**
  - An MCP call whose `command` runs a script file on another machine by its absolute path (`powershell -File C:\…\run.ps1`) gets the text this session wrote to that path through the same server's write tool, in the same transcript pass as 1.8.1's cleanup history: the latest whole write before the call (one in the same message counts) and the appends after it, bounded and redacted like script text, between lines marked with a random token, with when it was written, what the write returned, whether a write was sent before an earlier one's result (which then took effect last is not known), and the later calls there that name the path or its folder. "Before the call" is surely before it in one list of the session's calls to that server across the main and subagent transcripts, ordered by each record's own time, which 1.8.1's cleanup history now reads too, so a call made after the judged one (by another agent, or later in its message) is never earlier evidence. The call is looked for in the acting agent's transcript only; not found there, no text is shown and the cleanup history is as in 1.8.3. Before, the judge flagged such a call as running a script "whose contents were not shown", and the held call's retry again, though the text was in the transcript. A script the session did not write there still goes to the judge unseen. Logged as `remote_scripts` (`shown`, `found`, `none`, `unavailable`).
  - A local script's text, a subagent's brief, the developer's recent messages and a held call's answer sit between lines marked with the same kind of per-call token, so none can fake its own end. When the judge was shown a script, the judge's words are left out of the log and the flag store also where the hook quotes them in its own reason (a held call's question and flag, a remote-execution ask), and on a held call's retry when the judge that held it was shown one; the hook's own words, its diagnostics included, stay. A path, tool name or working directory the judge is shown outside those marked lines is kept on one line. See [How the LLM judges a call](#how-the-llm-judges-a-call).

- **1.8.3 (2026-11-24) — bug fixes: script words and quoted heredocs.**
  - `S=/abs/dir; python3 $S/x.py` (the script word unquoted, `S` set once to a literal earlier in the same command) is the script file `"$S/x.py"` is, when the value can't split, glob or expand further. It went to the judge as code "read from a pipe". The script's own checks apply as before. Any other script word built at run time (one that may split, glob or name stdin) goes to the judge as before, under a reason that says so instead of "a pipe" or "a stream".
  - Fixed, for both the quoted and the unquoted script word: a value that starts with `-` (`S=-Wx` makes the word an option, and the interpreter then reads its code from stdin) and a value that names a sensitive folder (`S=~/.ssh`) go to the judge, as the literal path does. So does a script word whose value the hook can't see, quoted or not: `S=$(…)`, `read S`, `${S:=…}`, two values, or `S` from the environment. A script word from a variable is a script file only when the same command sets the variable to one literal path.
  - Python in a heredoc with a quoted delimiter (`<<'EOF'`, `<<"EOF"`, `<<\EOF`) is read as written: the shell expands nothing there, so a `$` or backtick in it is Python's own text, and no longer stops the read-only check or the config-write check. Unquoted delimiters are read as before.
  - Tests: the prompt-timeout tests give the learner a timeout well above its start-up time, so a slow start no longer leaves no wait to record.

- **1.8.2 (2026-11-23) — the hook code is a package.**
  - The code of both hooks moved, unchanged, into `scripts/smart_permissions/` (`core.py` and `learner.py`). `scripts/pretool_safety.py` and `scripts/permission_learner.py` are now short entry scripts that import it, so Python runs it from cached bytecode instead of compiling 13,000 lines on every tool call: about half the per-call startup time. `urllib.request` is loaded only when the judge is called.
  - Manual setup: the hooks find `config/` beside the scripts, where the instructions put it. Before, they looked one folder up and every call failed closed. Copy the `smart_permissions` folder too, before the entry scripts (see [Manual setup](#manual-setup)).
  - If the `smart_permissions` folder is missing or can't be imported, the PreToolUse hook blocks the call and says why (exit 2), instead of a hook error that lets the call go ahead under the ordinary permissions.
  - The hook timeouts in the marketplace entry match `hooks/hooks.json` (45 s and 3660 s; it had 30 s and 45 s). The Python floor in Requirements is 3.9 (it said 3.6).

- **1.8.1 (2026-11-23) — provenance for cleanups on another machine.**
  - An MCP tool's `command` that looks like it deletes or resets something on another machine gets this session's earlier calls to the same MCP server (any of its tools) that name an absolute path the command names or its `cwd`, or one inside it: the first two and last three, each with the tool's name, what the tool call returned and its redacted text. The hook doesn't parse the remote shell and never says a command ran or created anything; the judge reads the calls. `ssh` calls go to the judge as before, without this history. Logged as `provenance` like a local target. See [How the LLM judges a call](#how-the-llm-judges-a-call).
  - The judge is told that nothing in those calls proves a command ran, that uncommitted work there that exists nowhere else is still a reason to flag, and that a scratch checkout or worktree made from a pushed branch or commit that holds nothing unique is the agent's to settle from those calls and the checkout's git state (uncommitted changes, unpushed commits, ignored files): such a flag is held for the agent. A shared checkout or one holding deliverables stays yours.
  - Decision log: an MCP tool's input is logged (its `command` and `cwd`, or else its whole input as compact JSON), not only its name. With `decision_log_full_input`, each JSON value is redacted, and a field named like a credential is masked whole.
  - Provenance snippets, local ones too, are redacted like the log, and a session whose transcripts can't be read at all gives `unavailable`.

- **1.8.0 (2026-11-19) — unanswered prompts are parked; scripts are read.**
  - A permission prompt you leave unanswered for `prompt_timeout_minutes` (default 10, `0` off) is denied with a message that tells Claude why it needed you, not to retry or work around it, to move on, and to list it for you in its final reply. Never an allow; never in `claude -p`; nothing happens if you answered first. Logged as `prompt-timeout`. See [Unanswered prompts](#unanswered-prompts-parked-not-a-freeze). The learner's hooks.json timeout is now 3660 s.
  - A local shell script the call runs (`./x.sh`, `bash x.sh`, sourced, fed to a shell) is scanned for remote execution and cloud deletes: a remote exec inside it gets the strict remote policy on the script's text, and a cloud delete goes to the judge (to you when the judge gives no answer) and is never held. Unreadable scripts, scripts over 64 KB and other languages keep the rules' answer. See [Local scripts](#remote-and-production-execution).
  - The judge's script evidence now counts `bash -e x.sh` (and other shell options) as running `x.sh`, and a script read and then run (`cat x.sh; bash x.sh`) as run.

- **1.7.0 (2026-11-19) — the agent answers first; strict remote execution.**
  - Holds (on by default, `"holds": false` turns them off): a flag the agent can settle is a deny that reads as a question ("Held by smart-permissions …"); the agent answers with its evidence and retries the identical call, and one judge pass at the recheck effort, with the evidence gathered again, clears it or sends it to you with the hold reason in the hook's words and the agent's answer labelled as its claim. See [Holds](#holds-the-agent-answers-first). The judge's verdict gains `confident`, `resolver` and `question`.
  - Never held, always yours: category 2 and 5 flags, destroying cloud, production or remote resources or data, sending secrets off the machine, a refused or malformed verdict, and remote execution. A hold is bound to the session, the acting agent, the working directory and the call (a Bash `description` aside), lasts 15 minutes, is used once, and a session gets at most 4 in 15 minutes. Holds are one file each under `~/.claude/hooks/smart-permissions-holds/`, written with exclusive creates, so two identical concurrent calls make one hold; the folder is a permission-config path (C9).
  - Remote and production execution (`kubectl exec`, `az containerapp exec`, `az vm run-command`, `aws ecs execute-command`, `docker` on a remote host, …) is judged strictly in both hooks, even when `safe_commands` would allow it: it runs without a prompt only on a confident verdict with the whole payload in the command text (inline or a heredoc); a payload from a local file, a pipe, `@file`/`file://`, any `$` or backtick, or a file copy comes to you without a judge call. Anything else is an explicit ask the PermissionRequest hook leaves to you. See [Remote and production execution](#remote-and-production-execution).
  - The judge's script evidence marks a script the command itself writes before running it.
  - A verdict with no valid `safe` (a reply that is not JSON or has no answer included), and a flag whose recheck times out, errors or gives no verdict, are now explicit asks (it used to fall through to the normal prompt path, where auto mode's classifier or the learner's own judge could approve it). Parallel hooks no longer overwrite each other's entries in the store that tells the PermissionRequest hook a call is yours.
  - Decision log: sources `llm-hold` and `hold-retry`, and a `hold` field. The agent's answer is never logged.
  - Branch review fixes: a `def` or `class` bound over an imported `Path` (or any imported name) no longer passes the config-write scan; `glab api` reads of pipeline trigger and cluster endpoints go to the judge; `script -c`/`--command` code, standalone `docker-compose` (exec, run, cp) and a Compose `run` on a remote host are in the remote-execution class, the last always yours; a heredoc run by local bash under a remote endpoint is checked for local payloads; a `git push` flagged for secrets is never held, nor a call whose first judge pass flagged a developer-only category, and the developer sees both passes' concerns when they differ; stash provenance no longer credits a `git stash` quoted inside another command.

- **1.6.0 (2026-11-19) — fewer judge calls, fewer false config-write prompts.**
  - A Python heredoc is checked like `python3 -c` code when it is the only code source: one complete heredoc with a quoted delimiter (`python3 - <<'EOF'`), plain flags, no pipe or second redirect into it, no `PYTHON*`/loader variable in the command and no non-UTF-8 `coding:` line. Code that only transforms data is allowed by rule; anything else still goes to the judge.
  - The Python check is stricter, for heredocs and `-c` alike: every call must be an allowed builtin (not rebound), a function or class the code defines, or a method of a value, never a computed target (`d[k](…)`) or a name assigned a value; frame and `Formatter.get_field` lookups are out, and so is a module reached through another module (`fractions.operator`, `urllib.parse.types`, a submodule such as `json.tool`) or held in a name; `str.replace` passes, `os.replace`/`Path.replace` don't. A file read passes only when its path is known before it runs (a literal, a name bound once to one, a loop over a literal list, an f-string or `+` of those, `$HOME`, or a literal shell name such as `S=/abs; … open('$S/x')`) and is neither a `sensitive_paths` file nor a permission-config file (those reads go to the judge), relative paths resolved from each folder a `cd` may lead to and from the starting one. `open(sys.argv[1])`, `open('$f')` and other run-time paths go to the judge.
  - A name assigned at the end of an and-chain and read after it (`cd X && PY=/usr/bin/python3; $PY -I x.py`) is allowed when both ways it can run pass: with the value, and unset (the next word then runs; an option word like `-I` names no command, so nothing runs). Not when the environment already has that name.
  - Read-only CLI calls: `glab api` as one literal GET (no `-X` other than GET, no `-f`/`-F`/`-H`/`--input`, no unknown option, not `graphql`, not CI/CD variables, tokens or keys, no brace or glob that can expand, no placeholder but `:id`), `glab --version`, and some five-word `az` reads (`monitor log-analytics workspace list/show`, `cognitiveservices account deployment list/show`, `cognitiveservices account list-models`, `ad app owner list`, `acr manifest list-metadata`, `acr repository show-tags`, `containerapp ingress traffic show`). `terraform output -raw/-json`, `terraform show -json`, `terraform console`, `terraform output/show` with `TF_CLI_ARGS*` set or a word built at run time, `docker compose exec/run` (also after docker's own options such as `-c NAME`) and `az … appsettings`/`list-publishing-profiles`/`password` reads now go to the judge.
  - A config write (C9) needs a write: Python that only reads a permission-config file (`python3 - <<'E' > out.txt` over the decision log) no longer prompts you; it goes to the judge. Python that may write one (a write mode, `os.replace`/`rename`, any `shutil` write, `Path.write_text`, `Path.copy`/`move`, a run-time or linked target, a module bound to another name, an imported name bound again, a module reached through another module, a frame or `get_field` lookup, a module whose writes can't be seen, an unquoted heredoc, a script file) still does, and so does a redirect whose target is a link to a config file.
  - A `<<` inside a shell comment (`echo hi # <<'EOF'`) opens no heredoc, so the lines after it are commands: such a command now goes to the judge instead of being read with those lines as data.
  - Decision log: `v`, `input_len` and `truncated` on every record, the file created 0600, rotation under a lock, and an opt-in `decision_log_full_input` with redaction (quoted values over several lines too). The PermissionRequest hook logs a `rule_reason` on every record, and leaves the built-in `AskUserQuestion` to you without consulting the judge (an MCP tool of that name is judged as before).
  - The judge is told which copy of the guard is running, so an edit to a checkout or worktree of smart-permissions is not mistaken for weakening the active guard.
  - `script` is no longer a wrapper (1.5.0): it is an unknown command again, judged as before, also from a `safe_script_paths` folder; a config or startup file it would record to, or a config write in the command it runs, still prompts. `sandbox-exec` stays a wrapper.

- **1.5.0 (2026-11-19) — more evidence for the judge, fewer false denies.**
  - A judge key file: when `SAFETY_HOOK_MODEL` or `SAFETY_HOOK_API_KEY` is missing from the environment, the hooks read the `SAFETY_HOOK_*` settings from `smart-permissions-llm.env` beside the config, if only you can read it (`chmod 600`; not on Windows). A Claude Code started outside your interactive shell no longer loses its judge. See [LLM environment variables](#llm-environment-variables).
  - The judge sees a subagent's brief, the contents of the local scripts a call runs or feeds (3 files, 8 KB each, your own regular files; never logged), the stash list and its provenance for `git stash drop/clear/pop`, who owns a `/tmp` folder and its mode, and your `mcp_context` notes for MCP tools. See [How the LLM judges a call](#how-the-llm-judges-a-call).
  - A bare or mirror clone is no longer reported as holding thousands of commits no remote has: with a remote and no remote-tracking refs, the judge is told git cannot compare them, with the clone's packed-refs and reflog observations and any cache-folder path.
  - `PYTHONPATH` into Claude Code's private `/private/tmp/claude-<uid>` still goes to the judge, now with a rule reason saying the folder is yours and not world-writable.
  - Fewer "Rewrite needed … `${S:?}`" denies: a loop variable over literal words, and a name assigned once at the top level to text with a literal part (`F=$E/v9`, also after a heredoc, a multi-line commit message, `set -e` or `export K=$(…)`), count as non-empty. `cd X && S=/lit; rm -rf $S/y`, a conditional or piped assignment, `read`, `eval`, `unset`, `${S:=}`, a function or a subshell still get the rewrite.
  - A nested loop over a loop variable's folders (`for x in …; do for a in "$x"/*/; do rm -rf "$a"`) is no longer denied as a delete of `~`; it goes to the judge. A loop word that is empty (`""`) still counts as empty.
  - `sandbox-exec` and `script` are wrappers: the command they run is judged instead of "Unknown command", and util-linux `script -c CODE` is read as shell code. `script`'s output and log files (`FILE`, `-O`, `--log-out=`, `-T`, `-tFILE`, …) count as writes (a permission-config or startup file there prompts), and a sensitive file a wrapper reads (`sandbox-exec -f`) goes to the judge.
  - Loop and assignment leniency stays off where a value may still be empty: a loop word with `"$@"`, `$*` or `${a[@]}`, a value with a blank in it (`S=' a'` splits where `$S` is unquoted), or an assignment with a redirection.
- **Unreleased — hardening.**
  - The 7-day LLM allow cache is gone: every call the rules can't settle is judged afresh. Old cache files and the `llm_cache`/`llm_cache_ttl_days` keys are ignored; delete them if you like. The LLM now also sees why the local rules sent it the call, and a timeout reports the total time spent.
  - A deny anywhere in a command wins over an ask earlier in it (`unknowncmd; sudo ls` is denied, not prompted).
  - Dangerous patterns are judged by position: in code they deny as before; in text passed on as data (an `echo` argument, a commit message, a quoted heredoc copied to a file) they go to the LLM. Each deny says what to do instead, and the PermissionRequest hook shows that message instead of "Blocked by safety hook".
  - The `rm -rf /` regexes are gone; the protected-delete guard covers those deletes, now also inside `$(…)` (`echo $(rm -rf ~)` was allowed before). A `/` elsewhere in a command (`rm -rf /tmp/a; df -h /`) no longer denies.
  - A plain force push to a branch other than `main`/`master` is denied with a rewrite to `--force-with-lease`.
  - A `cp`, `install` or `rsync` out of a permission-config file is a read; only its destination counts as written (`mv`, `ln`, `cp -l`/`-s`, `cp --parents`, `rsync -R` and `rsync --remove-source-files`/`--remove-sent-files` still count every operand). A config path spelled by brace expansion (`~/.{c..c}laude/settings.json`) counts as named.
  - `.envrc` no longer matches the `.env` sensitive path for reads, `git -c core.pager=less` is allowed, and fish `-C` init code of plain allowed commands is no longer a hazard.
  - The LLM approves only with a boolean `safe: true`; a string, number or missing verdict goes to you.
  - A Bash write to a permission-config path (C9) prompts from anywhere in the command (inside `if`/`for` bodies, functions, groups, `$(…)`, after a risky part), in both hooks, without asking the LLM. PreToolUse now emits an explicit `ask` for it, so a native allow rule or auto mode can no longer approve one.
  - A lone `&` now separates commands (`sleep 1 & kubectl delete …` checks `kubectl`), backslash escapes no longer hide a `;`, redirections before the command word (`< /dev/null kubectl …`) are skipped, and a group with redirections after it (`( … ) > /dev/null`) is checked command by command. Each of these was rule-allowed before.
  - The PermissionRequest hook now runs the same Bash rules as PreToolUse instead of its own copy; its log reasons are PreToolUse's (`Unknown command(s): docker` instead of `Restricted command family …`).
  - Code that a command runs is now read: a shell's heredoc, here-string or `-c` string, text echoed into `| sh`, `trap` handlers, `find -exec`, `eval` and awk's `system()`. A protected-folder delete or a C9 write in it is denied or prompts as at top level. A heredoc fed to a shell is decided by its contents, and a shell fed from a pipe or file goes to the LLM. All of these were rule-allowed before.
  - Risky operations of allowed tools go to the LLM: destructive `git` (`reset --hard`, `clean -f`, `checkout FILE`, `checkout -f`, `branch -D`, force push to `main`, remote branch delete, …), `curl`/`wget` file uploads, `chmod -R 777`, `docker` volume deletes, raw-disk writes, and writes to shell startup files and LaunchAgents (also through a brace expansion, a copy into `~`, or a `dart`/`flutter` option such as `-o`/`--output`). They were rule-allowed before.
  - Read, Glob and Grep of a `sensitive_paths` entry (or a file glob that can match one), and Bash commands naming one, go to the LLM instead of being allowed. Write/Edit to them is still denied.
  - `find ~/Documents -delete`, `find … -exec rm` from a protected folder, `rmdir` of a protected folder and `srm -r` are denied like a recursive `rm`, also with the expression in escaped parentheses or a test after the delete (`find ~/Documents \( -delete \)`). An unfiltered `find / -exec rm {} \;` is now denied rather than prompted.
  - Groups after a prefix are read (`! ( … )`, `> f ( … )`, `then ( … )`), `<>` counts as a write for C9, and `>|` no longer splits the command.
  - Code an interpreter reads from stdin goes to the LLM, like its `-c`/`-e` code: `python3 - <<'EOF'`, `python3 <<< …`, `… | python3`, `python3 /dev/stdin`, and node/ruby/perl/osascript/deno heredocs. They were rule-allowed before, whatever the code did.
  - The inline-Python checker rejects more write paths (`gzip.GzipFile(…).write`, `sys.modules[…]` through an alias, `from os import …`, module attributes like `gzip.os`).
  - A command nested too deeply to read, or any internal error, now prompts (PreToolUse) or falls through to the prompt (PermissionRequest) instead of crashing the hook.
  - Fewer LLM calls: `dart` development commands, macOS status reads (`vm_stat`, `pmset -g`, `diskutil list`, …), recursive deletes of folders below `/tmp` and of Python/Dart caches in the working directory, and a `$VAR` command word set once to a literal are allowed by rule. Runners after leading assignments are peeled (`TMPDIR=/tmp/x timeout 300 dart test`); this also stops `X=1 xargs kubectl delete` from being rule-allowed. `dart`/`flutter pub publish`, `pub token` and `pub global` go to the LLM, and so does an `xargs` with a replace string (`-I`/`-J`/`-i`), which was rule-allowed before.
  - A word built at run time where it decides the verdict goes to the LLM: `git $S --hard`, `git reset --h{a..a}rd`, `git -C $W …` (unquoted), `git checkout $B`, `docker compose down $V`, `chmod -R $M .`, a subcommand matched against a multi-word entry. These were rule-allowed before. On the author's decision log this sends about 0.2% of calls (19 of 8,994, all `git`) to the LLM that were allowed by rule.
  - A command that sets a variable which makes a tool run other code (`GIT_SSH_COMMAND`, `GIT_PAGER`, `EDITOR`, …, to anything but `less`, `more` or a plain allowed command; `LD_PRELOAD`, `DYLD_*`, `GIT_CONFIG_*` and other loader variables at all) goes to the LLM. These were rule-allowed before.
  - Function bodies in `( )` and zsh's short form (`f() cmd`) are checked like `{ }` bodies; `f() ( git reset --hard ); f` was rule-allowed before. An unknown command in a function body or `case` arm is now named and logged like one at top level.
  - Bash evaluation is about six times faster (median 6.7 → 1.1 ms, p99 22 → 5 ms per command on a back-to-back replay of 8,994 logged commands), from caching the parsers within one hook call and matching wildcard entries with one compiled pattern.
  - Internal cleanup: the unused restricted-command-family code is gone (its effect, an unlisted subcommand counting as unknown, is unchanged), the LLM-answer fallback parser is shorter, and the long protected-delete detail moved from this README to [GUARD.md](GUARD.md).
  - LLM judge: the prompt names code injected from `/tmp` (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`) and cron, shell startup, `PATH` and global git hook changes, and treats the developer's messages as a partial view, so cleanup after a status question isn't flagged as unrequested. Routine git housekeeping is named as safe. The recheck clears a misread first pass instead of leaning toward approval, so it no longer clears correct flags. A refusal to judge is a flag. `git config` writes of keys that run code, `git remote add`/`set-url`, `git push --all` or to a URL, `defaults write`, import-path and loader variables on any command, and reads of browser profiles and keychains go to the LLM; each was rule-allowed before. `git branch -D` of agent worktree branches is allowed by rule. `tests/llm_eval.py` is the live eval behind these changes (opt-in, needs a key).
- **2026-10-29 — auto-learning removed.** Approvals are no longer written to your config. Without an LLM, unknown Bash commands, home/temp writes and WebFetch to new domains now prompt instead of being approved and learned. `SAFETY_HOOK_AUTO_LEARN`, `auto_learn_mcp_tools` and `never_learn_commands` are retired and ignored. Previously learned entries stay in your config. See [the upgrade note](#smart-permissions) at the top.

## License

MIT
