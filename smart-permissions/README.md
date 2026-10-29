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
  │  LLM flagged it and the recheck confirmed       ──→  ASK (human)   │
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
  past the judge. It also sees why the local rules sent the call (`Unknown
  command(s): flyctl`, `Risky: … appears only in text passed on as data`), as
  a hint about what to check.
- **No cache.** Every call is judged afresh, so a verdict always reflects the
  current context. A timeout or error reports the total time spent
  (`LLM unavailable (…; 6.2s in all)`) and goes to you.
- **Strict verdicts.** Only an answer whose `safe` is the boolean `true`
  approves. A string (`"true"`), a number, or a missing or malformed verdict
  goes to you.
- **Second pass.** A flagged call is judged again at
  `SAFETY_HOOK_RECHECK_REASONING_EFFORT` (default `high`), with the first
  verdict attached. If the recheck clears it, the call runs (`source:
  llm-recheck`). If the recheck confirms it, the hook
  emits an explicit `ask`, so you decide — even in auto mode, where a silent
  fall-through would go to Claude's classifier instead. The PermissionRequest
  hook that fires for that prompt leaves it to you rather than asking the LLM a
  third time. If the recheck can't run in time, the call falls through to the
  normal prompt path.
- **No LLM hard denies.** Only the local rules deny outright: the
  dangerous patterns and the protected-delete guard below.

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
that prompt, so the rewrite is what keeps the agent moving.

The guard follows what the shell would do to reach the target: assignments,
`cd`, `pushd`/`popd`, loops, `|| exit`, zsh and bash word splitting, and values
it can't know (checked both as some folder and as empty). A target with too
many paths to check is denied with "list the targets". Two kinds of recursive
`rm` are allowed by rule because they only clear scratch space: a folder below
`/tmp`, and a Python or Dart cache (`__pycache__`, `.dart_tool`, …) in the
working directory, each spelled out in full. The full rules, with the zsh and
bash details and the known limits, are in [GUARD.md](GUARD.md).

Every other recursive or bulk delete (`rm -r`, `find -delete`, `find -exec rm`,
`xargs rm`) goes to the LLM on every call. It is never auto-allowed by rule,
and its verdict covers only that call. The LLM sees the working directory and your
recent messages. It approves build output, caches and temp files, and flags a
whole project or data the task doesn't cover. Without an LLM configured, these
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
- **Scratch deletes** — a recursive `rm` of a folder below `/tmp`, or of a Python/Dart cache in the working directory (see [Recursive deletes](#recursive-deletes))

### What gets blocked

- `sudo` anything
- `rm -rf /`, and a recursive delete of anything above home, by the protected-delete guard (any flag order or spelling, inside `$(…)` too)
- Recursive deletes of home or its top-level folders (see [Recursive deletes](#recursive-deletes))
- `curl | sh`, `wget | bash`, and other remote code execution chains
- Writes to device files (`> /dev/sda`), fork bombs, `mkfs`, `dd` to devices
- Write/Edit to sensitive paths (`~/.ssh/`, `~/.aws/`, `.env`). Reading them goes to the LLM (see below)
- Any of these inside code another command runs: `bash -c '…'`, `sh <<'EOF'`, `echo '…' | bash`, `trap '…' EXIT`, `find -exec sh -c '…'`, `eval`, awk's `system()`
- A plain force push to a branch other than `main`/`master` (`git push --force`, `-f`, `+branch`) is denied with a rewrite: push with `--force-with-lease` instead, which git refuses if someone else pushed in the meantime. A lease push is allowed.

Each deny says what to do instead: `sudo` asks the user to run the step themselves (`! sudo …`), `curl … | sh` to download the script to a file and show it first, a device write to use a regular file. Both hooks show the same message.

A dangerous pattern counts only where it can run. When it appears only in text passed on as data, the call goes to the LLM instead of being denied: an `echo`/`printf` argument, a `git commit`/`git tag` `-m` message, a `gh` `--body`/`--title`, or a quoted heredoc copied by `cat`/`tee` (`git commit -m 'drop sudo from the setup script'`). It is never allowed by rule. Anything else is code and is denied: any match in a command with a pipe, a group or a substitution (`echo '…' | sh`, `( … )`, `<(…)`), text written to a file in a command that also does something else (`echo '…' > a.sh; sh a.sh`), `printf -v`, a word with `$…` or a backtick, an unquoted heredoc with expansions, a heredoc fed to an interpreter, `trap`, `git log --grep`, or a parse the splitter is unsure of. To write such text to a file, use the Write tool or a heredoc on its own.

### What gets prompted

- **Dangerous subcommands** — `npm publish`, `docker run`, `docker exec`, `docker push`, `gh pr create`, `gh pr merge`, `cargo publish`, `pip uninstall`, `dart`/`flutter pub publish`, `pub token` and `pub global` (also behind global options or a wrapper: `dart --verbosity=all pub publish`, `xargs flutter pub publish`), and a `dart`/`flutter` subcommand built at run time (`flutter $S publish`), or any word built at run time unless the subcommand is `test`, `analyze`, `format`, `run` or a `.dart` script (`dart compile exe x -o "$OUT"`)
- `bash -c`, `sh -c`, `fish --command`, `osascript -e` (inline interpreter execution)
- **Code run by another command** — code a shell reads from a heredoc or here-string is checked like a top-level command: `bash <<'EOF'` with `ls` in it is allowed, with an unknown command it prompts. A shell fed from a pipe or a file (`… | sh`, `bash < f`), heredoc code with `$…` expansions, a login shell, an rc file or `BASH_ENV` (also when exported earlier in the command), fish code (its `-c` and `-C` init code are still read for denies and C9), an unknown command in a `trap` handler or `find -exec`, and an awk program that runs commands (`system()`, `print | "cmd"`) prompt
- `rm *` or `rm .*` (wildcard deletion)
- `find -delete` or `find -exec rm` with a filter (`find / -name tmp -delete`)
- **Risky operations of allowed tools** (always to the LLM) — `git reset --hard`, `git clean -f`, `git checkout` of a file or `.` (an operand that is a glob, has a file extension or exists in the folder counts as a file), `git checkout -f`/`git switch -f`, `git restore` of the work tree, `git stash drop`/`clear`, `git branch -D`, `git filter-branch`, a force push to `main`/`master` or with no branch named, a push that deletes a remote branch, `git -c` settings that run a command (an `alias.*` that isn't `!cmd` is read as the git command it stands for; a pager or editor that is `less`, `more` or a plain allowed command, like `core.pager=cat`, is fine); `curl` uploads of local files (`-d @file`, `-F f=@file`, `-T`, `-K`) and `wget --post-file`; `chmod -R` that makes a tree world-writable; `docker volume rm`/`prune`, `docker system prune`, `docker compose down -v`; writes to raw disks (`/dev/disk*`, `/dev/sd*`); writes to shell startup files (`~/.zshrc`, `~/.bashrc`, …) and `~/Library/LaunchAgents`, also as a `dart`/`flutter` option's value (`dart compile js x.dart -o ~/.zshrc`)
- **Sensitive paths read** — Read, Glob or Grep of a `sensitive_paths` entry (also a file glob that can match one, like `**/.ssh*` or `*.env`), and a Bash command naming one (`cat ~/.ssh/id_rsa`, `cat .env`, `git show HEAD:.env`)
- Archive extraction to system roots (`tar -C /usr/`)
- **Subcommands not on the list** — a command that ships (or is configured) only with multi-word entries, like `docker`, `npm`, `gh`, `terraform`, `kubectl`, `cargo`, `helm`, `pip`, is unknown with any other subcommand (`docker run`, `npm publish`): it is never approved by rule, and goes to the LLM or, without one, to you.
- **Words built at run time where they decide the verdict** — a `$VAR`, `$(…)`, unquoted glob or brace expansion in a word the rules read to choose a verdict: a git option or subcommand (`git $S --hard`, `git reset --h{a..a}rd`, `git -c "$K" log`), any word of a git subcommand the risky-operation checks read (`git checkout $B`, `git push origin HEAD:$R`), any word of `docker volume`/`system`/`compose`, a `chmod` mode, or a subcommand matched against a multi-word entry (`az {group,x} list`). A quoted value of `git -C`, `--git-dir` or `--work-tree` is one word whatever it holds, so `git -C "$W" status` and `git -C "$(pwd)" status` are still allowed; an unquoted `git -C $W` (or a quoted `"$@"`) can split into a subcommand and goes to the LLM. A `git -c alias.…` makes every word deciding, and so does a wrapper the rules can't line up with its words (`env -S "git $S"`). Built words elsewhere (`git log $R`, `chmod +x $F`) are fine.
- **Environment that runs other code** — a command that sets a variable a tool runs as a program (`GIT_SSH_COMMAND`, `GIT_PAGER`, `PAGER`, `GIT_EDITOR`, `EDITOR`, `VISUAL`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PROXY_COMMAND`, …) to anything but `less`, `more` or a plain allowed command, or sets a loader variable at all (`LD_PRELOAD`, `LD_AUDIT`, `DYLD_*`, `BASH_ENV`, `GIT_EXEC_PATH`, `GIT_CONFIG_*`). Such a word counts anywhere in a command except as an argument a plain command just passes on (`git commit -m "PAGER=x"`): a leading assignment, `env` (also `env -S '…'` and behind other wrappers), `export`, `declare`/`local`/`typeset`, also behind `builtin` or `command`. An append (`PAGER+=…`), an element (`PAGER[1]=…`), an array (`LD_PRELOAD=(…)`) and, after a wrapper or builtin, a name built at run time (`export "$K=…"`, a brace or backtick in the name) always count. `GIT_PAGER=cat git log` is allowed, `GIT_SSH_COMMAND="sh -c …" git fetch` goes to the LLM. A value set without `=` (`read`, `printf -v`) isn't read.
- **Function bodies** — every form of a function the command defines (`f() { …; }`, `f() ( … )`, `function f { … }`, zsh's `f() cmd`) is checked command by command like the top level, and so is each `case` arm.
- **Permission-config writes (C9)** — Write/Edit/NotebookEdit targeting `~/.claude/settings*`, `~/.claude/hooks/`, `~/.claude/keybindings.json`, or the plugin's own config / log / LLM-flag files, and Bash commands that write to them (`tee`, `>`, `sed -i`, `mv`, `ln`, a `dart`/`flutter` command that names one (`dart compile exe x -o …`), or a `cp`/`install`/`rsync` whose destination is one; copying one of them elsewhere is a read) anywhere in the command: after `;` or `&`, inside `if`/`for` bodies, functions, groups and `$(…)`. A Bash command that names one of those paths but can't be parsed with confidence prompts too. These *always* prompt — never auto-allowed, never LLM-vouched, whatever else the command does short of a hard deny — even when their parent (`~/.claude/`) is a safe write path, so the agent can't rewrite its own permission rules. The hook emits an explicit `ask` for them rather than falling through, so neither a native allow rule (`Bash(cp:*)`, an earlier "Always allow") nor auto mode can approve one. Both hooks apply the same check. This guard is not subtractable.
- WebFetch to domains not in the allow list
- MCP tools not matching any `safe_mcp_tools` pattern
- Anything else the rules can't settle (a novel CLI tool, a write outside the safe folders), when no LLM is configured

With an LLM configured, everything in this list except permission-config writes goes to the LLM first, and you see only what it won't approve. When something *does* prompt, you get the standard Claude permission dialog with "Always allow", so it only prompts once if you choose to permanently allow it — except a permission-config write, which asks every time.

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
| `safe_internal_tools` | string array | Claude Code / harness internal tools auto-allowed (no side effects outside the harness) |
| `sensitive_paths` | string array | Write/Edit to a path containing one is denied (substring match); Read/Glob/Grep of one, and Bash commands naming one, go to the LLM (matched where a path component ends, case-insensitive: `/.env` matches `.env.local`, not `.envrc`) |
| `always_ask_write_paths` | string array | Path substrings that always prompt on Write/Edit (permission-config self-escalation guard, C9). **Not subtractable.** |
| `dangerous_patterns` | string array | Regex patterns that deny when they match code (the whole command or one of its commands); a match only in data goes to the LLM |
| `protected_delete_paths` | string array | Folders a recursive delete may never touch, nor anything above them (default `~`, `~/*`; globs expand on disk). **Not subtractable.** |
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |
| `remove_from_defaults` | object | Subtract shipped entries from allowlist keys (see [Subtracting defaults](#subtracting-defaults)) |
| `decision_log` | bool | Log every decision to `~/.claude/hooks/smart-permissions-decisions.jsonl` (default `true`) |

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

Every decision from both hooks is appended as one JSON object per line to `~/.claude/hooks/smart-permissions-decisions.jsonl` (override with `decision_log_path`, disable with `"decision_log": false`). Each record captures the timestamp, hook, tool, truncated input (≤500 chars), decision, source (`rule` / `llm` / `llm-recheck` / `learner`; logs from older versions also hold `llm-cache`), reason, and timing. Records from versions before auto-learning was removed may also carry a `learned` list. When the LLM decides, `rule_reason` records why the local rules didn't settle the call, so `jq -r .rule_reason` over the log shows which rule gaps drive LLM traffic. Calls from other agent CLIs (see below) also record the original `client_tool` name. It rotates to a single `.jsonl.1` generation at 5 MB. Run `/smart-permissions:stats` to summarize it.

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

1. Copy **both** scripts and the config (the learner imports shared logic from
   `pretool_safety.py`, so they must sit in the same directory):
   ```bash
   mkdir -p ~/.claude/hooks/smart-permissions
   cp scripts/pretool_safety.py scripts/permission_learner.py ~/.claude/hooks/smart-permissions/
   cp -r config/ ~/.claude/hooks/smart-permissions/config/
   ```

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
               "timeout": 45
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

## Audit log

All unknown commands and tools are logged to `~/.claude/hooks/unknown-permissions.log` for review.

## Windows support

Windows is supported with automatic loading of `config/defaults-windows.json` (PowerShell/cmd commands, Windows dev tools, Windows-specific dangerous patterns). You may need to adjust `safe_write_paths` for Windows directories and use `python` instead of `python3` for manual setup.

## Requirements

- Python 3.6+ (stdlib only — no pip dependencies)
- Claude Code
- macOS, Linux, or Windows

## Changelog

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
  - The inline-Python checker rejects more write paths (`gzip.GzipFile(…).write`, `sys.modules[…]` through an alias, `from os import …`, module attributes like `gzip.os`).
  - A command nested too deeply to read, or any internal error, now prompts (PreToolUse) or falls through to the prompt (PermissionRequest) instead of crashing the hook.
  - Fewer LLM calls: `dart` development commands, macOS status reads (`vm_stat`, `pmset -g`, `diskutil list`, …), recursive deletes of folders below `/tmp` and of Python/Dart caches in the working directory, and a `$VAR` command word set once to a literal are allowed by rule. Runners after leading assignments are peeled (`TMPDIR=/tmp/x timeout 300 dart test`); this also stops `X=1 xargs kubectl delete` from being rule-allowed. `dart`/`flutter pub publish`, `pub token` and `pub global` go to the LLM, and so does an `xargs` with a replace string (`-I`/`-J`/`-i`), which was rule-allowed before.
  - A word built at run time where it decides the verdict goes to the LLM: `git $S --hard`, `git reset --h{a..a}rd`, `git -C $W …` (unquoted), `git checkout $B`, `docker compose down $V`, `chmod -R $M .`, a subcommand matched against a multi-word entry. These were rule-allowed before. On the author's decision log this sends about 0.2% of calls (19 of 8,994, all `git`) to the LLM that were allowed by rule.
  - A command that sets a variable which makes a tool run other code (`GIT_SSH_COMMAND`, `GIT_PAGER`, `EDITOR`, …, to anything but `less`, `more` or a plain allowed command; `LD_PRELOAD`, `DYLD_*`, `GIT_CONFIG_*` and other loader variables at all) goes to the LLM. These were rule-allowed before.
  - Function bodies in `( )` and zsh's short form (`f() cmd`) are checked like `{ }` bodies; `f() ( git reset --hard ); f` was rule-allowed before. An unknown command in a function body or `case` arm is now named and logged like one at top level.
  - Bash evaluation is about six times faster (median 6.7 → 1.1 ms, p99 22 → 5 ms per command on a back-to-back replay of 8,994 logged commands), from caching the parsers within one hook call and matching wildcard entries with one compiled pattern.
  - Internal cleanup: the unused restricted-command-family code is gone (its effect, an unlisted subcommand counting as unknown, is unchanged), the LLM-answer fallback parser is shorter, and the long protected-delete detail moved from this README to [GUARD.md](GUARD.md).
- **2026-10-29 — auto-learning removed.** Approvals are no longer written to your config. Without an LLM, unknown Bash commands, home/temp writes and WebFetch to new domains now prompt instead of being approved and learned. `SAFETY_HOOK_AUTO_LEARN`, `auto_learn_mcp_tools` and `never_learn_commands` are retired and ignored. Previously learned entries stay in your config. See [the upgrade note](#smart-permissions) at the top.

## License

MIT
