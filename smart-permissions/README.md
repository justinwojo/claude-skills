# Smart Permissions

A hook plugin for [Claude Code](https://docs.anthropic.com/en/docs/claude-code) that replaces the built-in permission system with smarter, configurable auto-approval. It lets Claude work autonomously on safe operations while still blocking genuinely dangerous commands.

Out of the box, Claude Code prompts you for every file write, every bash command, and every web fetch. With this plugin, common development operations are auto-approved based on rules you control, and the system learns new commands as you work.

## How it works

Every tool call passes through two hooks before executing:

```
Tool call
  ┌─ PreToolUse ─────────────────────────────────────────────────────┐
  │                                                                   │
  │  Dangerous pattern? (sudo, rm -rf /, curl|sh)  ──→  DENY         │
  │  Risky pattern? (rm *, find / -delete)          ──→  PROMPT       │
  │  Known-safe command? (git, npm, cargo, etc.)    ──→  ALLOW        │
  │  Unknown command?                               ──→  LLM eval     │
  │                                                      (optional)   │
  └───────────────────────────────────────────────────────────────────┘
                          │
                    Falls through if
                    still undecided
                          │
  ┌─ PermissionRequest ──────────────────────────────────────────────┐
  │                                                                   │
  │  Re-check dangerous?  ──→  DENY                                   │
  │  Re-check risky?      ──→  PROMPT (show normal permission dialog) │
  │  Just unknown?        ──→  ALLOW + save to config for next time   │
  │                                                                   │
  └───────────────────────────────────────────────────────────────────┘
```

### What gets auto-allowed

- **Read-only tools** — Read, Glob, Grep, WebSearch are always safe
- **File writes** to safe directories — `~/Dev/`, `/tmp/`, `~/.claude/`
- **Bash commands** using known tools — git, npm, cargo, docker, dotnet, compilers, file utilities, and 100+ more
- **Relative scripts** — `./build.sh`, `scripts/test.sh` (project scripts are trusted)
- **WebFetch** to allowed domains — GitHub, StackOverflow, language docs, etc.

### What gets blocked

- `sudo` anything
- `rm -rf /` (caught by both regex and token-based analysis for flag reordering)
- `curl | sh`, `wget | bash`, and other remote code execution chains
- Writes to device files (`> /dev/sda`), fork bombs, `mkfs`, `dd` to devices
- Reads/writes to sensitive paths (`~/.ssh/`, `~/.aws/`, `~/.env`)

### What gets prompted

- `bash -c`, `sh -c`, `osascript -e` (inline interpreter execution)
- `rm *` or `rm .*` (wildcard deletion)
- `find / -delete` or `find / -exec rm` (recursive deletion from root)
- Archive extraction to system roots (`tar -C /usr/`)
- Unknown commands not in the safe list (first encounter only — see [Self-learning](#self-learning-permissions))
- WebFetch to domains not in the allow list

## Installation

### Via plugin system (recommended)

```
/plugin marketplace add justinwojo/claude-skills
/plugin install smart-permissions@justinwojo-claude-skills
```

Hooks activate automatically after installation. No manual settings.json editing needed.

### Manual setup

1. Copy the scripts and config:
   ```bash
   mkdir -p ~/.claude/hooks/smart-permissions
   cp scripts/pretool_safety.py ~/.claude/hooks/smart-permissions/
   cp scripts/permission_learner.py ~/.claude/hooks/smart-permissions/
   cp -r config/ ~/.claude/hooks/smart-permissions/config/
   ```

2. Add both hooks to `~/.claude/settings.json`:
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
       ],
       "PermissionRequest": [
         {
           "matcher": "",
           "hooks": [
             {
               "type": "command",
               "command": "python3 ~/.claude/hooks/smart-permissions/permission_learner.py",
               "timeout": 30
             }
           ]
         }
       ]
     }
   }
   ```

   For manual setup, the script finds `config/defaults.json` relative to its own location (`../config/defaults.json`). Keep the directory structure intact.

## Configuration

### Defaults

The plugin ships with `config/defaults.json` containing safe commands for common development across languages and platforms: git, npm, cargo, docker, compilers, file utilities, and more. Review it to see exactly what's included.

Entries starting with `__ ` are section labels for readability — they're stripped at load time and don't affect behavior.

### User overrides

Your personal config lives at `~/.claude/smart-permissions-config.json`. You don't need to create this file — it's **generated automatically** the first time the hook runs. It starts empty and grows as the plugin learns new commands during normal use (see [Self-learning permissions](#self-learning-permissions)).

You can edit it any time to pre-add tools you know you'll need:

```json
{
  "safe_commands": [
    "flutter", "dart", "gradle", "mvn",
    "kubectl", "terraform", "ansible", "helm"
  ],
  "safe_write_paths": [
    "~/Projects/",
    "~/workspace/"
  ],
  "allowed_web_domains": [
    "docs.flutter.dev",
    "pub.dev"
  ]
}
```

**Arrays are merged** (union), not replaced. Your additions extend the defaults, so you never need to re-list built-in commands. Only include what's unique to your workflow.

If you need to remove a default entry, fork `config/defaults.json`. There's no "remove" mechanism by design — the defaults represent a vetted baseline.

### All config keys

| Key | Type | Description |
|-----|------|-------------|
| `safe_commands` | string array | First-word commands auto-allowed in Bash |
| `safe_write_paths` | string array | Directories where Write/Edit are auto-allowed (supports `~/`) |
| `safe_script_paths` | string array | Directories where absolute-path scripts are auto-allowed |
| `allowed_web_domains` | string array | Domains auto-allowed for WebFetch (subdomains included) |
| `sensitive_paths` | string array | Path substrings that always deny for file operations |
| `dangerous_patterns` | string array | Regex patterns that always deny (full command match) |
| `risky_patterns` | string array | Regex patterns that prompt instead of auto-allowing |
| `interpreter_exec_flags` | object | `{"interpreter": ["-flag"]}` — flag combos that trigger a prompt |

## Self-learning permissions

The plugin learns your workflow over time. Two mechanisms work together:

### Automatic learning (via PermissionRequest hook)

When a command isn't in the safe list and isn't dangerous or risky, the PermissionRequest hook auto-approves it **and** saves it to `~/.claude/smart-permissions-config.json`.

The first time you use `terraform`, it gets auto-approved and written to your config. The second time, PreToolUse recognizes it from the config and allows it instantly — no extra processing.

Commands matching `dangerous_patterns` or `risky_patterns` are **never** auto-learned. They always block or prompt, no matter how many times they appear.

### LLM auto-learn (opt-in)

Set `SAFETY_HOOK_AUTO_LEARN=true` to also learn from LLM approvals:

```bash
export SAFETY_HOOK_AUTO_LEARN=true
```

When the LLM evaluates an unknown command as safe, it gets saved to your config. This creates a fully autonomous loop — the LLM is consulted once per new command, then it's instant:

```
New command → LLM says safe → allowed + saved to config → next time: instant allow
```

Without this flag, the LLM still approves or denies in real time but doesn't persist its decisions.

### What gets learned

| Tool type | What's saved | Config key |
|-----------|-------------|------------|
| Bash | First command word (e.g., `terraform`) | `safe_commands` |
| Write / Edit | Parent directory of the target file | `safe_write_paths` |
| WebFetch | Hostname from the URL | `allowed_web_domains` |

## LLM safety evaluation (optional)

When a tool call can't be decided by local rules, the hook can call an LLM for a safety judgment before falling through to the permission prompt. This is completely optional — without an API key, unknown commands simply prompt you normally.

Any OpenAI-compatible chat completions API works. The LLM receives the tool name and parameters, and responds with `{"safe": true}` or `{"safe": false, "reason": "..."}`.

### Setup

Set environment variables for your preferred provider:

```bash
# xAI Grok (default provider)
export SAFETY_HOOK_API_KEY=$XAI_API_KEY

# OpenAI / ChatGPT
export SAFETY_HOOK_API_URL=https://api.openai.com/v1/chat/completions
export SAFETY_HOOK_API_KEY=$OPENAI_API_KEY
export SAFETY_HOOK_MODEL=gpt-4o-mini

# Local Ollama (no billing)
export SAFETY_HOOK_API_URL=http://localhost:11434/v1/chat/completions
export SAFETY_HOOK_MODEL=llama3
export SAFETY_HOOK_API_KEY=unused  # Must be non-empty to enable LLM path
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SAFETY_HOOK_API_URL` | `https://api.x.ai/v1/chat/completions` | Chat completions endpoint |
| `SAFETY_HOOK_API_KEY` | Falls back to `$XAI_API_KEY` | API key (LLM disabled if empty) |
| `SAFETY_HOOK_MODEL` | `grok-4-1-fast-reasoning` | Model name to use |
| `SAFETY_HOOK_AUTO_LEARN` | `false` | Persist LLM-approved commands to config (`true` / `1` / `yes`) |

## Audit log

All unknown commands and tools are logged to `~/.claude/hooks/unknown-permissions.log`, regardless of whether they were auto-learned or prompted. This gives you an audit trail:

```
2025-03-20 14:32:01  command   terraform
2025-03-20 14:33:15  command   kubectl
2025-03-20 15:01:44  tool      SomeNewTool
```

Review this periodically to see what's been auto-approved, or to spot patterns you might want to add to `dangerous_patterns` or `risky_patterns`.

## How Bash commands are parsed

The hook includes a full compound command parser. It doesn't just look at the first word — it splits the entire command into individual sub-commands and checks each one. This handles real-world commands like:

```bash
cd /tmp && git clone https://... && make install
# → splits into 3 commands: cd, git, make — all checked individually

DOTNET_CLI_TELEMETRY=0 dotnet build -c Release
# → skips the env var assignment, checks "dotnet"

for f in *.txt; do echo "$f"; done
# → recognizes shell keywords (for, do, done, echo)
```

The parser respects:

- **Compound operators** — `&&`, `||`, `;`, `|`, newlines
- **Quoting** — single quotes, double quotes, escape sequences
- **Heredocs** — `<<EOF ... EOF` (including `<<-` and quoted markers)
- **Nesting** — parenthesized subshells `(...)` and brace groups `{...}`
- **Line continuations** — trailing `\` joins lines
- **Shell constructs** — `case...esac`, function definitions, `for`/`while` loops
- **Variable assignments** — `VAR=value` and `VAR=$(command)` prefixes

If **any** sub-command in a compound command is unknown, the entire command is prompted. A safe `git status` doesn't give a free pass to an unsafe second command chained after it.

Relative scripts (`./build.sh`, `scripts/test.sh`) are always allowed — scripts in your project directory are considered trusted.

## Testing

The plugin includes a test suite with 93 test cases covering all decision paths:

```bash
cd smart-permissions
python3 tests/test_hooks.py
```

The tests validate:
- Read-only and internal tools are always allowed
- Safe Bash commands, compounds, pipes, heredocs, loops, and subshells
- All dangerous patterns are denied (sudo, rm -rf /, curl|sh, fork bombs, etc.)
- Risky patterns prompt instead of auto-allowing
- Interpreter execution flags (bash -c, osascript -e) prompt
- File path evaluation (safe paths, sensitive paths)
- WebFetch domain allow-listing
- Edge cases (empty commands, comments, malformed input, function definitions, case statements)
- PermissionRequest auto-approval for unknown-but-safe commands
- PermissionRequest denial for dangerous commands
- PermissionRequest fall-through for risky commands
- Config file learning and deduplication

Dangerous test payloads are base64-encoded in the test file so they don't trigger live safety hooks.

## Windows support

The plugin works on Windows with some caveats:

**What works automatically:**
- File path evaluation — paths are normalized for Windows separators
- Sensitive path detection — `/.ssh/`, `/.aws/` patterns match both `\` and `/` paths
- Config file bootstrap and learning
- LLM safety evaluation
- Windows-specific defaults are loaded automatically (`config/defaults-windows.json`), adding PowerShell/cmd commands, Windows dev tools (choco, scoop, winget), and Windows-specific dangerous patterns (Format-Volume, del /s /q C:\, Invoke-WebRequest|iex)

**What you may need to adjust:**

- **Python command:** The hooks.json uses `python3`, which may not exist on Windows. If you install manually, use `python` instead in your settings.json. For plugin installs, the plugin system handles invocation.
- **Safe write paths:** The defaults include macOS/Linux paths (`~/Dev/`, `/tmp/`). On Windows, add your paths via `~/.claude/smart-permissions-config.json`:
  ```json
  {
    "safe_write_paths": [
      "~/source/repos/",
      "~/Documents/Projects/"
    ]
  }
  ```
- **Bash parsing:** The compound command parser is designed for bash/sh syntax. Claude Code on Windows typically runs commands through a bash-compatible shell (Git Bash, WSL), so this generally works. Pure PowerShell syntax is not fully parsed, but the dangerous pattern matching still catches Windows-specific threats.

## Requirements

- Python 3.6+ (stdlib only — no pip dependencies)
- Claude Code
- macOS, Linux, or Windows

## License

MIT
