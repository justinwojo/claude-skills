# Smart Permissions

A hook plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that replaces the built-in permission system with smarter, configurable auto-approval. It lets Claude work autonomously on safe operations while still blocking genuinely dangerous commands.

Out of the box, Claude Code prompts you for every file write, every bash command, and every web fetch. With this plugin, common development operations are auto-approved based on rules you control.

The plugin evaluates in a strict **trust order — rules → LLM → human**. Local rules decide first. Anything they can't classify is handed to an optional LLM (if you've configured one). Only what neither can vouch for reaches you as a standard permission prompt with full "Always allow" support. A second hook (PermissionRequest) also auto-approves and *learns* unknown-but-safe commands, so your permissions build up naturally as you work — while restricted command families, permission-config edits, and anything risky always stop for confirmation.

## Installation

```
/plugin marketplace add justinwojo/claude-skills
/plugin install smart-permissions@justinwojo-claude-skills
```

Then run the setup wizard to configure it:

```
/smart-permissions:setup
```

The wizard walks you through LLM evaluation, auto-learn, safe commands, write paths, and MCP tool permissions.

## How it works

Every tool call passes through **two** hooks. The PreToolUse hook runs first;
if it can't decide, the PermissionRequest hook (the "learner") gets a second,
LLM-consulting pass before Claude ever shows you a prompt:

```
Tool call
  ┌─ PreToolUse ─────────────────────────────────────────────────────┐
  │  Dangerous pattern? (sudo, rm -rf /, curl|sh)   ──→  DENY          │
  │  Recursive delete of a protected folder (~/Dev) ──→  DENY          │
  │  rm -r target on a possibly-empty $VAR          ──→  DENY + rewrite│
  │  Other recursive delete (rm -r, find -delete)   ──→  LLM (no cache)│
  │  Risky pattern? (rm *, find / -delete)          ──→  ASK (no cache)│
  │  Permission-config write? (settings, this cfg)  ──→  ASK (C9)      │
  │  Known-safe command/subcommand?                 ──→  ALLOW         │
  │  MCP tool in safe list? (glob patterns)         ──→  ALLOW         │
  │  Otherwise (unknown)                            ──→  LLM eval      │
  │                                                     (+ cache, opt) │
  │  LLM flagged it and the recheck confirmed       ──→  ASK (human)   │
  └───────────────────────────────────────────────────────────────────┘
                          │ still undecided ("ask")
                          ▼
  ┌─ PermissionRequest (learner) ────────────────────────────────────┐
  │  Re-check dangerous/risky patterns              ──→  DENY / ASK    │
  │  LLM configured?  ── yes ─→ LLM eval (+ cache)   ──→  ALLOW / ASK  │
  │                   └─ no  ─→ unknown-but-safe cmd ──→  ALLOW + LEARN │
  │  Restricted family / MCP / config write         ──→  ASK           │
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
  past the judge.
- **Second pass.** A flagged call is judged again at
  `SAFETY_HOOK_RECHECK_REASONING_EFFORT` (default `high`), with the first
  verdict attached. If the recheck clears it, the call runs (`source:
  llm-recheck`; never cached or learned). If the recheck confirms it, the hook
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

A recursive `rm` whose target leans on a variable that may be empty is denied
with a rewrite for the agent to run instead. `rm -rf "$T/$k"` becomes
`rm -rf /` when both are empty. Claude Code stops for manual approval on that
shape, and no hook, auto mode or bypass mode can clear that prompt. The deny
tells the agent to write `"${T:?}/${k:?}"`: the shell then aborts instead of
deleting when a value is empty, which proves the empty case away at run time,
and Claude Code runs it without asking. The rule covers targets that start with
`/`, `~`, `$VAR` or `$(…)`, and requires a guard on every variable that the
command sets or unsets itself or that is unset or empty in the environment. It
also covers `"$D"/*` and `/tmp/$k`, which Claude Code's own check lets through;
the rewrite keeps globs, brace groups and a leading `~` outside the quotes
(`"${D:?}/"*`). A
bare `rm -rf "$X"` is left alone, since an empty X deletes nothing, and so is a
`$`, glob or `~` in quotes or escaped. One guard covers later uses of the same
name, and `${X:-${Y:?}}` counts as guarded. Values that can't take a guard in
place (`$!`, `${X%/}`, `${X:+…}`, `${!X}`, a `$(…)` other than `$(pwd)`) get
"use a literal path", and so does a whole target the protected-folder guard
can't follow (`rm -rf "${HOME%/}"`; `"$@"` is exempt) and any `..` after an
expansion (`"$D/../x"`, or glued on as `"$D"../*`). A variable that can hold
`.` or `..` is refused even when guarded, if it forms a whole path component.
That covers a loop or `read` variable fed by `ls -a`/`--all` (or `ls $flags`
with `flags=-a`, a copy of it, or one inherited), a `.*` glob, a variable holding such a list, a value taken
from one (`g=$f`, `g=$(echo "$f")`), and `$1`…`${99}` or `"$@"` after
`set -- "$f"` (including `for g; do` and `for g do`). Guarded
targets still go to the LLM like any other recursive delete. The
protected-folder guard reads through `${X:?}` and the default operators
(including a `~` in the default), `$(pwd)` (unless the command redefines
`pwd`), `${X:=…}`, zsh's `${X::=…}` and `$((X=1))` assignments in any command, and
`export`/`declare`/`local` assignments, also behind `builtin` or `command` and
their flags. Anything that may not run, or runs in a subshell (inside
`if`/`while`/`for`/`case`/`{ }`, after `&&` or `||`, in `( )`, a pipeline or
an `&` job, or an arithmetic operand like `0 && (X=1)`), adds what it assigns
or `cd`s to beside the old value. Each command is followed once per directory
the command may be in, and the target is checked against each. `pushd`/`popd`
follow the directory stack and `cd -` the previous directory; once that can't be
known (an entry from before the command, `cd +1`, a stack change that may not
run, a plain `cd` under zsh's `AUTO_PUSHD`, a folder already on the stack under
`PUSHD_IGNORE_DUPS`, `setopt` or `shopt` in the command), they may go to any directory seen
so far; a bare `pushd` may also go home (`PUSHD_TO_HOME`), and pushing the
current folder again counts as a duplicate too. A `cd` to a folder that doesn't
exist (or a `cd OLD NEW` whose OLD isn't in the path, or a `cd ~-/…` that isn't
there) may fail and leave the shell where it was. What runs there: nothing after
an `|| exit [N]`/`|| return [N]` (N a number or `$?`) that ends the command (not
one piped on, and not in a command that defines, disables or aliases them, even
with a quoted name like `function "exit"` or an escaped one like `$'\x64isable'`, uses `eval`, `source` or `.`, or runs a
command whose name is expanded, like `$a$b exit`); the commands after the `&&` chain the `cd` starts (`cd x && a; rm
…` runs the `rm` either way); otherwise the next command. `set -e` isn't counted
(quoting, variables, `eval` or a function can turn it off), so the delete after a
may-fail `cd` is checked from both folders. A deny caused that way says to chain
the delete with `cd DIR && rm …`. The `cd`/`pushd`/`popd` operands are counted
after expansion: an unquoted `$X` (or `$(cmd)`) that expands to nothing is gone,
so `cd $X` goes home (a deny caused that way says to quote it; a quote inside
`${X:+"x"}` doesn't keep it), a flag is only zsh's own (`-q`, `-s`, `-L`, `-P`, `--`;
`popd` takes just `-q`) before any operand, literal or expanded (`cd -bad /tmp` and
`cd /tmp -q` are `cd OLD NEW`, which fails), `cd -s` fails when a folder its
operand names (or `cd -s -`'s previous folder) is a symlink, `cd -P` ends in the
physical folder (`link/..` is the link target's parent), an unquoted brace group is its words (`cd {A,B}` is `cd A
B`), and an unquoted `$(cmd)`, glob or `"$@"` may make any number of operands; the descriptor in `2>&1` or `{fd}>f` is not an operand.
A `cd`/`pushd` with more than two operands, or a `popd` given anything but
`+N`/`-N`, is an error that changes nothing. zsh's `cd
OLD NEW` swaps OLD for NEW in the current directory (an empty NEW removes OLD,
an empty OLD puts NEW in front; either may be a stack tilde), and `~+`, `~-` and `~N` (in a
`cd` or an `rm` target) are the current, previous and stack directories; once a
`cd` has run, `~-` in a value (`T=~-`, `for T in ~-`, `${X:-~-}`) is the tracked
previous directory too (and `~1`, `~-1`, `~+1` there any directory seen so far,
`~$N`/`~$U` there any of those or home; a
`~$N`/`~$U` delete target, named only at run time, is denied; a quoted one, `'~$U'`,
is a file by that name, but `''~$U` and `$''~$U` are not quoted; zsh's `$'…'`
is read with its escapes decoded, a NUL kept in a value as zsh keeps it but
ending a `cd` or `rm` path as the system call does, and zsh's `$"…"` is a `$` and a quoted string: `cd $"/tmp"` goes to
`$/tmp`), and `$OLDPWD` is where that `cd` came from (or, when it
may not run or may fail, what it held before). The `cd`/`pushd` operands are expanded
once, so `cd "${D::=$D/..}"` climbs once. Inside a loop, or after zsh's
`repeat N`, a relative `cd` and an assignment that reads a variable can also end
up anywhere. A body with no `;` before it is a command of its own: `for g do
rm …` (or `for f g do`), zsh's `if [[ -d x && -d y ]] rm …`, `while (( n )) { … }`, `for f (a b)
rm …` and `f() rm …`, and `function f { … }`, also after `repeat N`, `time`,
`{`, `!` or a function head (`f() { if [[ -d x ]] rm …; }`). zsh's `-`, `noglob`,
`nocorrect`, `repeat N` and `time` run the command after them, and `for f g in …`
gives each name any of the values (a loop over `ls -a` marks each name as one
that can hold `..`). A `${Z:=…}` in a list too big to follow
leaves `Z` too big to follow, so a delete that reads it is denied. A `for` loop
over a list it can follow is checked once per value, with braces expanded, globs
matched and words split where an expansion can split them (`for f in ~/*` is
denied); a word it can't follow adds an unknown value beside the rest. zsh's
brace expansion inside a default (`${X:-~/{Desktop,Documents}}`) is checked
too. A value it can't know (`X=$(cmd)`, a `read` variable, a loop over
`$(cmd)`) is checked both as some folder and as empty, each such value on its
own, also through assignments and loop lists, so `"${X:?}/../.."` still climbs to `/` and `"${X:-$HOME/Dev}"` still
reaches `~/Dev`. A target with too many paths to check (a brace expansion over
4096 words, more than 8192 loop values or mixes of values in one word, a copy
of such a value, more than 256 directories the command may be in, or more than
about a second of checking in one command) is denied with "list the targets". A target that hits a protected folder even with every such value
non-empty is denied outright; one that only an empty value would turn into a
protected folder gets the rewrite first.

All of the above is zsh's reading (the macOS default shell). Every command is
also read as bash runs it (Linux, Git Bash on Windows, or zsh with
`SH_WORD_SPLIT`), and a protected folder either reading reaches is denied. In
bash an unquoted value splits into words (`X="build $HOME/Dev"; rm -rf $X`
deletes `~/Dev`), in an `rm` target and a `for` list alike. It splits at the
characters of a literal `IFS=…` too, and once IFS is set some other way, at
any characters at all (any stretch of the value is a possible word; past 256
characters only at each one, or all its punctuation, and the LLM judges the rest). Quoted
text beside the value (`"a b"$X`), and a quoted `for` word, are never split. `$"…"` is a plain quoted string, and a
`$'…'` string ends at a NUL, so `$'\0'`, `$'\c@'` and `$'\400'` are empty. A `~` after a quote
(`''~/x`) is not home. `cd` takes only `-L`, `-P`, `-e` and `-@`, and
`pushd`/`popd` only `-n`, which doesn't change directory (though a later
`popd` may go to what `pushd -n` pushed, an expanded or split one too). Any other `-x` there, including
`cd -1`, fails and leaves the shell where it was. A second operand makes
bash 5 fail and bash 3.2 go to the first, so both are checked. An unquoted
`cd $D` whose value holds a space is its words (`D="-L $HOME"` is `cd -L
~`; an expanded `~` stays a literal name), one holding only spaces is a bare
`cd` (home), an expanded `-P` goes to the LLM, and it lands anywhere once IFS
is set. `unset IFS` and reads like `$IFS` or `${#IFS}` leave the
default. `enable -n exit` turns
the builtin off as zsh's `disable` does, and `shopt` counts like `setopt`.

In either shell, an `rm` argument whose value the guard can work out and that
turns out to be a flag (`F=-rf; rm $F ~/Dev`, or bash's `X="-rf ~/Dev"; rm
$X` and `F="r ~/Dev"; rm -$F`) makes the delete recursive; past `--` it is a
name. Once options are set (`setopt`, `shopt`), a `cd NAME` with no `NAME`
folder there may also go to `$NAME` (CDABLE_VARS). When the command sets
`CDPATH` (or the environment has it), a relative `cd NAME` may also go to
each of its folders' `NAME`, and it fails only when none of them exists;
zsh's `cdpath=(…)` array isn't followed, so there it lands anywhere.

Every other recursive or bulk delete (`rm -r`, `find -delete`, `find -exec rm`,
`xargs rm`) goes to the LLM on every call. It is never auto-allowed by rule,
never cached, and never learned. The LLM sees the working directory and your
recent messages. It approves build output, caches and temp files, and flags a
whole project or data the task doesn't cover. Without an LLM configured, these
fall through to the normal prompt. The guard reads only the command text: a
delete hidden in a script file or an inline interpreter (`python -c`) reaches
the LLM through the other rules, not this one.

Known limits: the guard models plain shell, not deliberate obfuscation. A
`cd` flag that comes from a variable (`F=-P; cd $F link`), a brace group
holding `${…}` in a `cd` operand (`cd {/tmp,${HOME}/x}`), a brace-spelled
builtin (`di{s,s}able exit`, `e{x,x}it() …`) or a nested `~${U:-${V}}` can
put the shell somewhere the guard doesn't follow. None of these is
auto-allowed: they reach the LLM like any other recursive delete.

### What gets auto-allowed

- **Read-only tools** — Read, Glob, Grep, WebSearch are always safe
- **File writes** to safe directories — `~/Dev/`, `/tmp/`, `~/.claude/`
- **Bash commands** using known tools — git, dotnet, compilers, file utilities, and 100+ more
- **Safe subcommands** of restricted tools — `npm install`, `docker build`, `gh pr view`, `cargo test`, etc.
- **Relative scripts** — `./build.sh`, `scripts/test.sh` (project scripts are trusted)
- **WebFetch** to allowed domains — GitHub, StackOverflow, language docs, etc.
- **MCP tools** matching `safe_mcp_tools` patterns — configure per-server with globs
- **Global flags** before subcommands — `docker --context prod build`, `npm --prefix /tmp run dev`, etc.

### What gets blocked

- `sudo` anything
- `rm -rf /` (caught by both regex and token-based analysis for flag reordering)
- Recursive deletes of home or its top-level folders (see [Recursive deletes](#recursive-deletes))
- `curl | sh`, `wget | bash`, and other remote code execution chains
- Writes to device files (`> /dev/sda`), fork bombs, `mkfs`, `dd` to devices
- Reads/writes to sensitive paths (`~/.ssh/`, `~/.aws/`, `~/.env`)

### What gets prompted

- **Dangerous subcommands** — `npm publish`, `docker run`, `docker exec`, `docker push`, `gh pr create`, `gh pr merge`, `cargo publish`, `pip uninstall`
- `bash -c`, `sh -c`, `osascript -e` (inline interpreter execution)
- `rm *` or `rm .*` (wildcard deletion)
- `find / -delete` or `find / -exec rm` (recursive deletion from root)
- Archive extraction to system roots (`tar -C /usr/`)
- **Restricted command families** — a base command that ships (or is configured) only with multi-word entries, like `docker`, `npm`, `gh`, `terraform`, `kubectl`, `cargo`, `helm`, `pip`. An unrecognized subcommand (`docker run`, `npm publish`) is never blanket-approved; without an LLM it prompts, with one the LLM decides.
- **Permission-config writes (C9)** — Write/Edit/NotebookEdit targeting `~/.claude/settings*`, `~/.claude/hooks/`, `~/.claude/keybindings.json`, or the plugin's own config / cache / log files. These *always* prompt — never auto-allowed, never learned, never LLM-vouched — even when their parent (`~/.claude/`) is a safe write path, so the agent can't rewrite its own permission rules. This guard is not subtractable.
- WebFetch to domains not in the allow list
- MCP tools not matching any `safe_mcp_tools` pattern (unless auto-learned — see below)

Genuinely-unknown, non-restricted commands (e.g. a novel CLI tool) are auto-approved and learned by the PermissionRequest hook rather than prompting — so they build up in your config as you work. When something *does* prompt, you get the standard Claude permission dialog with "Always allow", so it only prompts once if you choose to permanently allow it.

## Security model / threat boundary

**This plugin is a guardrail, not a sandbox.** It reduces friction and catches obvious mistakes: it blocks plainly-dangerous commands (`sudo`, `rm -rf /`, `curl … | sh`), routes unknown commands through the LLM or the permission prompt, and auto-approves the ones you've marked (or that are obviously) safe. That is its whole job.

It is **not** a security boundary against a determined adversarial agent that already has Bash access. A shell can write files through indirection that static command analysis cannot fully see — variables (`CFG=~/.claude/settings.json; cp x "$CFG"`), `cd` plus relative paths, hardlinks, script *files* whose contents aren't inspected (`bash /tmp/p.sh`), or archive extraction (`tar -C ~/.claude …`). Writes to the plugin's own config/cache/settings via those routes cannot be reliably prevented by a hook, and none of them were preventable before this plugin either. The Bash config-path write guard is **best-effort for naive/accidental cases only** — do not treat it as airtight.

The permission-config files live in the **user trust domain** (`~/.claude/`): anything running as you can ultimately reach them. If you need a real boundary against untrusted code, use OS-level sandboxing (containers, VMs, seccomp/AppArmor) — not this plugin.

- Guardrail against mistakes and unknown commands: **yes.**
- Barrier against code actively trying to escalate its own permissions: **no** — use OS sandboxing.
- The one new escalation surface this design introduces — the **LLM decision cache** — is mitigated: the cache only ever grants an allow when an LLM is actually configured (a planted entry can't approve anything in a no-LLM setup), and denies are never cached.

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
| `sensitive_paths` | string array | Path substrings that always deny for file operations |
| `always_ask_write_paths` | string array | Path substrings that always prompt on Write/Edit (permission-config self-escalation guard, C9). **Not subtractable.** |
| `never_learn_commands` | string array | Command first-words never persisted to the allowlist (still LLM-approvable per call) |
| `dangerous_patterns` | string array | Regex patterns that always deny (full command match) |
| `protected_delete_paths` | string array | Folders a recursive delete may never touch, nor anything above them (default `~`, `~/*`; globs expand on disk). **Not subtractable.** |
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |
| `remove_from_defaults` | object | Subtract shipped entries from allowlist keys (see [Subtracting defaults](#subtracting-defaults)) |
| `decision_log` | bool | Log every decision to `~/.claude/hooks/smart-permissions-decisions.jsonl` (default `true`) |
| `llm_cache` | bool | Cache LLM *allow* decisions for identical repeat calls (default `true`) |
| `llm_cache_ttl_days` | number | How long a cached allow stays valid (default `7`) |
| `auto_learn_mcp_tools` | bool | Persist LLM-approved MCP tool names to `safe_mcp_tools` (default `true`) |

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

Removal is applied last, after defaults + platform overlay + your additions. Removing a `safe_commands` entry also makes that base a **restricted family** — the first word of a removed entry means "ask me", never "unknown → allow" — and the learner will never re-add an entry you subtracted.

### Decision log

Every decision from both hooks is appended as one JSON object per line to `~/.claude/hooks/smart-permissions-decisions.jsonl` (override with `decision_log_path`, disable with `"decision_log": false`). Each record captures the timestamp, hook, tool, truncated input (≤500 chars), decision, source (`rule` / `llm` / `llm-cache` / `llm-recheck` / `learner`), reason, timing, and anything learned. When the LLM decides, `rule_reason` records why the local rules didn't settle the call, so `jq -r .rule_reason` over the log shows which rule gaps drive LLM traffic. Calls from other agent CLIs (see below) also record the original `client_tool` name. It rotates to a single `.jsonl.1` generation at 5 MB. Run `/smart-permissions:stats` to summarize it.

> **Privacy:** the logged `input` can contain whatever appeared on a command line, path, or URL — including secrets. Treat the log as the same trust class as your shell history.

### LLM decision cache

When an LLM approves an otherwise-unknown call, that **allow** is cached keyed on the exact tool name + full input, so identical repeats don't pay for another LLM round-trip (`source: llm-cache` in the log). Only allows are cached (a cached false-deny would stick), risky-class calls are never cached, and entries expire after `llm_cache_ttl_days` (capped at 500 entries). One consequence to be aware of: if you'd approve a command via the LLM once and then change your mind, the cached allow persists until it expires or you clear `~/.claude/hooks/smart-permissions-llm-cache.json` — a bounded stale-allow window. Disable entirely with `"llm_cache": false`.

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

### MCP auto-learn

When an MCP tool is approved by the LLM (with `SAFETY_HOOK_AUTO_LEARN` enabled), the plugin persists that **exact tool name** to `safe_mcp_tools` so identical calls are instant next time. It only ever learns the precise name that was approved — never a wildcard — so approving `mcp__sentry__get_issue` never broadens to `mcp__sentry__*`.

> **Migration note:** earlier versions never auto-learned MCP tools. This behavior is on by default now. Set `"auto_learn_mcp_tools": false` in your config to restore the old "explicit patterns only" behavior; you can still add glob patterns by hand at any time, and Claude's "Always allow" remains available when a tool prompts.

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

The parser handles compound operators (`&&`, `||`, `;`, `|`), quoting, heredocs, subshells, line continuations, `case...esac`, function definitions, loops, and variable assignments. Transparent runners (`env`, `timeout`, `nohup`, `xargs`, `command`, …) are peeled so the *inner* command is what gets checked (`xargs docker run` is evaluated as `docker run`, not auto-allowed as `xargs`), and indirect command words — `$VAR`, `\docker`, and meta-execution builtins (`eval`, `source`, `.`) — are treated as unknown rather than trusted.

If **any** sub-command in a compound command is unknown, the entire command falls through to the permission prompt.

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

**Auto-learning** is conservative by design:
- When `flutter doctor` is approved, it learns `"flutter doctor"` — not `"flutter"`. So `flutter run` still prompts separately.
- Commands with flags before the subcommand (like `docker --context prod build`) are matched correctly but **not auto-learned**, since flag parsing is ambiguous without command-specific knowledge. These commands are still auto-approved each time by the PermissionRequest hook — they just don't get persisted to your config.
- Single-word base commands are never auto-learned to prevent accidental blanket approvals.
- If you want blanket approval for a tool, manually add the single-word entry (e.g. `"flutter"`) to your config.

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
   ones, but without the PermissionRequest hook you lose LLM evaluation, learning,
   and the restricted-family / config-write prompts.

## Testing

```bash
cd smart-permissions
python3 tests/test_hooks.py
```

Covers all decision paths: safe commands, dangerous patterns, risky patterns, file paths, web domains, MCP tools, compound commands, edge cases, and config learning. Dangerous test payloads are base64-encoded so they don't trigger live safety hooks.

### LLM environment variables

| Variable | Description |
|----------|-------------|
| `SAFETY_HOOK_MODEL` | Model name (e.g. `claude-haiku-5-5`, `gpt-5.4-mini`, `grok-4.3`) |
| `SAFETY_HOOK_API_KEY` | API key (LLM disabled if empty). For Claude models, falls back to `ANTHROPIC_API_KEY`. |
| `SAFETY_HOOK_API_URL` | Endpoint. OpenAI-compatible chat completions (e.g. `https://api.openai.com/v1/chat/completions`) or the Anthropic Messages API. Optional for `claude-*` models (defaults to `https://api.anthropic.com/v1/messages`). |
| `SAFETY_HOOK_PROVIDER` | Optional wire format override: `anthropic` or `openai`. Auto-detected otherwise: an `anthropic.com` URL, or a `claude-*` model with no URL, uses the Messages API; everything else uses chat completions. |
| `SAFETY_HOOK_REASONING_EFFORT` | Optional effort (e.g. `none`, `low`, `medium`, `high`). OpenAI-compatible: sent as `reasoning_effort`. Anthropic: sent as `output_config.effort`, with `none`/`minimal` mapped to `low`. Only sent if set. |
| `SAFETY_HOOK_RECHECK_REASONING_EFFORT` | `reasoning_effort` for the second pass on a flagged call (default `high`; empty string = provider default) |
| `SAFETY_HOOK_AUTO_LEARN` | Persist LLM-approved commands to config (`true` / `1` / `yes`) |

## Audit log

All unknown commands and tools are logged to `~/.claude/hooks/unknown-permissions.log` for review.

## Windows support

Windows is supported with automatic loading of `config/defaults-windows.json` (PowerShell/cmd commands, Windows dev tools, Windows-specific dangerous patterns). You may need to adjust `safe_write_paths` for Windows directories and use `python` instead of `python3` for manual setup.

## Requirements

- Python 3.6+ (stdlib only — no pip dependencies)
- Claude Code
- macOS, Linux, or Windows

## License

MIT
