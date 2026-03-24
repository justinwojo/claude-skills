---
description: Interactive setup wizard for the smart-permissions plugin
allowed-tools: ["Read", "Edit", "Write", "Bash", "Glob", "Grep", "AskUserQuestion"]
---

# Smart Permissions Setup

Walk the user through configuring the smart-permissions plugin. Read current state first, then guide them through each section interactively.

## Step 1: Check Current State

Read these files to understand what's already configured:

1. `~/.claude/smart-permissions-config.json` — user config (may not exist yet)
2. `~/.claude/settings.json` — check for existing permissions in `permissions.allow`

Also check which environment variables are set:

```bash
echo "SAFETY_HOOK_API_URL=${SAFETY_HOOK_API_URL:-(not set)}"
echo "SAFETY_HOOK_API_KEY=${SAFETY_HOOK_API_KEY:+(set)}"
echo "SAFETY_HOOK_MODEL=${SAFETY_HOOK_MODEL:-(not set)}"
echo "SAFETY_HOOK_AUTO_LEARN=${SAFETY_HOOK_AUTO_LEARN:-(not set)}"
```

Present a summary of the current state to the user before proceeding.

## Step 2: LLM Safety Evaluation

Use AskUserQuestion to ask if they want to configure LLM fallback evaluation:

```json
{
  "question": "Do you want to enable LLM safety evaluation for unknown commands? This uses any OpenAI-compatible chat completions API.",
  "options": [
    {
      "label": "Yes, I have an OpenAI-compatible API I want to use",
      "description": "Requires API URL, key, and model name"
    },
    {
      "label": "Yes, using local Ollama",
      "description": "Free, runs locally — requires Ollama installed with a model pulled"
    },
    {
      "label": "No, skip LLM evaluation",
      "description": "Unknown commands will show the standard Claude permission prompt"
    }
  ]
}
```

Based on their choice:

**OpenAI-compatible API:** Ask which provider they want to use and show the appropriate export lines. All three variables are required. Recommend these models by provider:

- **xAI Grok:** `grok-4-1-fast-reasoning` — fast, cheap, and capable
- **OpenAI:** `gpt-5.4-mini` (best balance) or `gpt-5.4-nano` (maximum cost efficiency)
- **Groq, Together, etc.:** Whatever model they prefer

```bash
# Example for xAI Grok:
export SAFETY_HOOK_API_URL="https://api.x.ai/v1/chat/completions"
export SAFETY_HOOK_API_KEY="your-api-key"
export SAFETY_HOOK_MODEL="grok-4-1-fast-reasoning"

# Example for OpenAI:
export SAFETY_HOOK_API_URL="https://api.openai.com/v1/chat/completions"
export SAFETY_HOOK_API_KEY="your-api-key"
export SAFETY_HOOK_MODEL="gpt-5.4-mini"
```

**Ollama:** Show:

```bash
export SAFETY_HOOK_API_URL="http://localhost:11434/v1/chat/completions"
export SAFETY_HOOK_API_KEY="unused"  # Must be non-empty to enable LLM path
export SAFETY_HOOK_MODEL="llama3"
```

Do NOT edit their shell config files — just show them what to add to `~/.zshrc` or `~/.bashrc`.

If they chose a provider and the relevant API key is already set, confirm it's working.

## Step 3: Auto-Learn

Only show this step if they enabled LLM evaluation in step 2.

Use AskUserQuestion:

```json
{
  "question": "Do you want the plugin to auto-learn commands approved by the LLM?",
  "options": [
    {
      "label": "Yes, enable auto-learn",
      "description": "LLM-approved commands are saved to your config so they're instant next time"
    },
    {
      "label": "No, don't auto-learn",
      "description": "The LLM evaluates each time but doesn't persist decisions"
    }
  ]
}
```

If they enable it, tell them to add `export SAFETY_HOOK_AUTO_LEARN=true` to their shell config.

## Step 4: Safe Commands

Show them the current `safe_commands` list from their config (if any) and the defaults.

Mention that commands support three formats:
- **Single-word** (`flutter`) — allows all subcommands
- **Multi-word** (`flutter doctor`, `docker compose up`) — allows only that specific subcommand
- **Wildcards** (`kubectl get*`, `docker *`) — allows matching subcommands via glob patterns

Use AskUserQuestion:

```json
{
  "question": "Do you want to add any commands to your safe list? These are auto-approved without prompting. You can use multi-word entries (e.g. 'flutter doctor') or wildcards (e.g. 'kubectl get*').",
  "options": [
    {
      "label": "Yes, add commands",
      "description": "I'll ask you which commands to add"
    },
    {
      "label": "No, the defaults are fine",
      "description": "You can always add commands later via the config file"
    }
  ]
}
```

If yes, ask them to list the commands they want to add (free-form text input). Then update their `~/.claude/smart-permissions-config.json` file, merging into the existing `safe_commands` array without duplicating entries already present.

## Step 5: Safe Write Paths

Show them the current `safe_write_paths` from defaults and their config.

Use AskUserQuestion:

```json
{
  "question": "Do you want to add any directories where file writes are auto-approved?",
  "options": [
    {
      "label": "Yes, add paths",
      "description": "I'll ask you which directories to add"
    },
    {
      "label": "No, the defaults are fine",
      "description": "Default: ~/Dev/, /tmp/, ~/.claude/"
    }
  ]
}
```

If yes, ask for directories. Paths should end with `/` and can use `~/`. Update the config file.

## Step 6: MCP Tool Permissions

Use AskUserQuestion:

```json
{
  "question": "Do you use any MCP servers that you want to configure auto-approval for?",
  "options": [
    {
      "label": "Yes, configure MCP permissions",
      "description": "Set up glob patterns to auto-approve read-only MCP operations"
    },
    {
      "label": "No, skip MCP setup",
      "description": "MCP tools will use the standard Claude permission prompt"
    }
  ]
}
```

If yes:

1. Check if they have any MCP servers configured by reading `~/.claude/settings.json` and any `.claude/settings.json` in the current project for `mcpServers` entries.
2. For each MCP server found, suggest read-only patterns. Common conventions:
   - `mcp__<server>__get_*` — get/read operations
   - `mcp__<server>__list_*` — list operations
   - `mcp__<server>__search_*` — search operations
   - `mcp__<server>__*` — full trust (all operations)
3. Ask which patterns they want to add.
4. Update `safe_mcp_tools` in the config file.

## Step 7: Review Existing settings.json Permissions

Look at their `permissions.allow` entries in `~/.claude/settings.json`. If they have many `Bash(cmd:*)` entries that overlap with the plugin's `safe_commands` defaults, mention that the plugin handles these automatically and they could optionally clean up the redundant entries from settings.json. Do NOT remove them automatically — just inform them.

## Step 8: Summary

Show a summary of everything configured:

```
## Smart Permissions Setup Complete

**LLM Evaluation:** {enabled/disabled} ({provider})
**Auto-Learn:** {enabled/disabled}
**Safe Commands:** {count} custom + {count} defaults
**Safe Write Paths:** {count} custom + {count} defaults
**MCP Tool Patterns:** {count} patterns
**Config file:** ~/.claude/smart-permissions-config.json

To make changes later, edit ~/.claude/smart-permissions-config.json directly
or run /smart-permissions:setup again.
```

If LLM evaluation was configured in step 2, remind the user:

```
If you added environment variables to your shell config, either restart your
terminal or run `source ~/.zshrc` (or `source ~/.bashrc`) to pick them up.
```

## Important Notes

- NEVER edit the user's shell config files (~/.zshrc, ~/.bashrc) — only show them what to add
- NEVER remove entries from settings.json permissions — only inform the user about redundancies
- Always read the config file before writing to avoid overwriting user changes
- When updating the config, preserve all existing entries and only add new ones
- Use `_comment` and `_*_examples` fields (prefixed with `_`) for hints — these are ignored by the plugin
