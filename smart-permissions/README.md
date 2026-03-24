# Smart Permissions

A hook plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that replaces the built-in permission system with smarter, configurable auto-approval. It lets Claude work autonomously on safe operations while still blocking genuinely dangerous commands.

Out of the box, Claude Code prompts you for every file write, every bash command, and every web fetch. With this plugin, common development operations are auto-approved based on rules you control. Unknown commands fall through to the standard permission prompt with full "Always allow" support, so your permissions build up naturally as you work.

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

Every tool call passes through the PreToolUse hook before executing:

```
Tool call
  ┌─ PreToolUse ─────────────────────────────────────────────────────┐
  │                                                                   │
  │  Dangerous pattern? (sudo, rm -rf /, curl|sh)  ──→  DENY         │
  │  Risky pattern? (rm *, find / -delete)          ──→  DENY         │
  │  Known-safe command/subcommand?                  ──→  ALLOW        │
  │  MCP tool in safe list? (glob patterns)         ──→  ALLOW        │
  │  Unknown command?                               ──→  LLM eval     │
  │                                                      (optional)   │
  └───────────────────────────────────────────────────────────────────┘
                          │
                    Falls through if
                    still undecided
                          │
              Standard Claude permission prompt
              (with "Always allow" option)
```

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
- Unknown commands not in the safe list or LLM-approved
- WebFetch to domains not in the allow list
- MCP tools not matching any `safe_mcp_tools` pattern

When prompted, you get the standard Claude permission dialog with "Always allow" — so unknown commands only prompt once if you choose to permanently allow them.

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
| `sensitive_paths` | string array | Path substrings that always deny for file operations |
| `dangerous_patterns` | string array | Regex patterns that always deny (full command match) |
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |

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

MCP tools are never auto-learned. You explicitly choose which ones to trust by adding patterns to your config, or use Claude's "Always allow" when prompted for individual tools.

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

The parser handles compound operators (`&&`, `||`, `;`, `|`), quoting, heredocs, subshells, line continuations, `case...esac`, function definitions, loops, and variable assignments.

If **any** sub-command in a compound command is unknown, the entire command falls through to the permission prompt.

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

1. Copy the scripts and config:
   ```bash
   mkdir -p ~/.claude/hooks/smart-permissions
   cp scripts/pretool_safety.py ~/.claude/hooks/smart-permissions/
   cp -r config/ ~/.claude/hooks/smart-permissions/config/
   ```

2. Add the hook to `~/.claude/settings.json`:
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
               "timeout": 30
             }
           ]
         }
       ]
     }
   }
   ```

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
| `SAFETY_HOOK_MODEL` | Model name (e.g. `grok-4-1-fast-reasoning`, `gpt-5.4-mini`) |
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
