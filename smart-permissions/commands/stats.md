---
description: Summarize recent smart-permissions decisions from the decision log
allowed-tools: ["Bash", "Read"]
---

# Smart Permissions Stats

Summarize the plugin's recent permission decisions from its structured decision
log. Every PreToolUse and PermissionRequest decision (allow / deny / ask) is
appended to a JSONL file; this command turns that history into a readable report.

## Step 1: Locate the log

The decision log lives beside the user config:

- Default: `~/.claude/hooks/smart-permissions-decisions.jsonl`
- If `decision_log_path` is set in `~/.claude/smart-permissions-config.json`, use that.
- A single rotated generation may exist at the same path with a `.1` suffix
  (older entries). Only read `.1` if the user asks for a longer history.

If the file does not exist, tell the user logging may be disabled
(`"decision_log": false` in their config) or no decisions have been recorded yet,
and stop.

## Step 2: Parse and summarize

Read the JSONL (one JSON object per line). Each record has these fields:

| Field | Meaning |
|-------|---------|
| `ts` | ISO timestamp (seconds) |
| `hook` | `pretool` or `permission_request` |
| `tool` | tool name (`Bash`, `Write`, `WebFetch`, `mcp__…`, …) |
| `input` | the tool input, truncated to 500 chars (command / path / url) |
| `decision` | `allow`, `deny`, or `ask` |
| `source` | `rule`, `llm`, `llm-cache`, or `learner` |
| `reason` | human-readable decision reason |
| `duration_ms` | hook wall-clock time (optional) |
| `llm_ms` | LLM round-trip time, when an LLM was called (optional) |
| `learned` | list of entries persisted to the config, when any (optional) |

Use a quick Bash/jq (or `python3`) pass to compute totals. Example:

```bash
LOG="$HOME/.claude/hooks/smart-permissions-decisions.jsonl"
python3 - "$LOG" <<'PY'
import sys, json, collections
recs = []
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
except FileNotFoundError:
    print("No decision log found."); raise SystemExit
by_dec = collections.Counter(r.get("decision") for r in recs)
by_src = collections.Counter(r.get("source") for r in recs)
learned = [e for r in recs for e in (r.get("learned") or [])]
print(f"Total decisions: {len(recs)}")
print("By decision:", dict(by_dec))
print("By source:", dict(by_src))
print(f"Entries learned: {len(learned)}")
# Most-asked / most-denied inputs
asks = collections.Counter(r.get("input") for r in recs if r.get("decision") == "ask")
denies = collections.Counter(r.get("input") for r in recs if r.get("decision") == "deny")
print("\nTop asked:")
for inp, n in asks.most_common(10):
    print(f"  {n:>4}  {inp}")
print("\nTop denied:")
for inp, n in denies.most_common(10):
    print(f"  {n:>4}  {inp}")
PY
```

## Step 3: Present the report

Show the user:

1. **Totals** — decisions by outcome (allow/deny/ask) and by source
   (rule / llm / llm-cache / learner).
2. **What's prompting most** — the most frequent `ask` inputs. These are good
   candidates to add to `safe_commands` (or configure LLM evaluation for).
3. **What's being denied** — the most frequent `deny` inputs, so the user can
   spot anything unexpected.
4. **Recently learned** — the last several `learned` entries and where they went
   (`safe_commands`, `safe_write_paths`, `allowed_web_domains`, `safe_mcp_tools`).
5. If an LLM is configured, note the average `llm_ms` and how many decisions were
   served from the cache (`source: llm-cache`) versus a live call (`source: llm`).

Keep the report concise. Offer to add any frequently-asked commands to the user's
`~/.claude/smart-permissions-config.json` if they want.

## Privacy note

The `input` field can contain whatever appeared in a command, path, or URL —
including secrets passed on a command line. Treat the decision log as the same
trust class as your shell history. Do not paste its raw contents anywhere public.
