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
  │  Risky pattern? (rm *, find / -delete)          ──→  ASK (no cache)│
  │  Permission-config write? (settings, this cfg)  ──→  ASK (C9)      │
  │  Known-safe command/subcommand?                 ──→  ALLOW         │
  │  MCP tool in safe list? (glob patterns)         ──→  ALLOW         │
  │  Otherwise (unknown)                            ──→  LLM eval      │
  │                                                     (+ cache, opt) │
  └───────────────────────────────────────────────────────────────────┘
                          │ still undecided ("ask")
                          ▼
  ┌─ PermissionRequest (learner) ────────────────────────────────────┐
  │  Re-check dangerous/risky patterns              ──→  DENY / ASK    │
  │  LLM configured?  ── yes ─→ LLM eval (+ cache)   ──→  ALLOW/DENY   │
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
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |
| `remove_from_defaults` | object | Subtract shipped entries from allowlist keys (see [Subtracting defaults](#subtracting-defaults)) |
| `decision_log` | bool | Log every decision to `~/.claude/hooks/smart-permissions-decisions.jsonl` (default `true`) |
| `llm_cache` | bool | Cache LLM *allow* decisions for identical repeat calls (default `true`) |
| `llm_cache_ttl_days` | number | How long a cached allow stays valid (default `7`) |
| `auto_learn_mcp_tools` | bool | Persist LLM-approved MCP tool names to `safe_mcp_tools` (default `true`) |

Positive allowlists (`safe_commands`, `safe_write_paths`, `safe_script_paths`, `allowed_web_domains`, `safe_mcp_tools`, `safe_internal_tools`) merge as a union with the defaults. Scalars and objects (like `interpreter_exec_flags`) are replaced wholesale.

### Subtracting defaults

Arrays only ever *add* to the defaults, so to remove a shipped entry use `remove_from_defaults`. It accepts the positive allowlist keys **only** — deny/prompt controls (`dangerous_patterns`, `risky_patterns`, `sensitive_paths`, `always_ask_write_paths`) can never be weakened this way.

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

Every decision from both hooks is appended as one JSON object per line to `~/.claude/hooks/smart-permissions-decisions.jsonl` (override with `decision_log_path`, disable with `"decision_log": false`). Each record captures the timestamp, hook, tool, truncated input (≤500 chars), decision, source (`rule` / `llm` / `llm-cache` / `learner`), reason, timing, and anything learned. It rotates to a single `.jsonl.1` generation at 5 MB. Run `/smart-permissions:stats` to summarize it.

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
| `SAFETY_HOOK_API_URL` | Chat completions endpoint (e.g. `https://api.openai.com/v1/chat/completions`) |
| `SAFETY_HOOK_API_KEY` | API key (LLM disabled if empty) |
| `SAFETY_HOOK_MODEL` | Model name (e.g. `grok-4.3`, `gpt-5.4-mini`) |
| `SAFETY_HOOK_REASONING_EFFORT` | Optional `reasoning_effort` value (e.g. `none`, `low`, `medium`, `high`). Only sent if set; otherwise the provider default applies. |
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
