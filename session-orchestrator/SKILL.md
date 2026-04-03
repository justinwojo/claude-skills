---
name: session-orchestrator
description: Orchestrate multi-session design doc execution using agent teams. Spawns one worker per session sequentially, each with fresh context. Triggers on "orchestrate this design doc", "run sessions from", "execute design doc", "orchestrate sessions", "run the design doc".
---

**IMPORTANT — Read this entire document before taking any action.**

# Session Orchestrator

Orchestrate multi-session design doc execution using agent teams. Spawns
one worker per session sequentially, each with fresh context and optional
AI pair review.

## Prerequisites

### Agent Teams (Required)

This skill requires Claude Code's experimental agent teams feature.
If not already enabled, add the following to `~/.claude/settings.json`:

```json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

### AI Pair Programming (Optional)

If the [ai-pair-programming](../ai-pair-programming) skill is installed
and configured with at least one provider API key, workers will
automatically get external AI code review before committing. Without it,
workers perform a self-review instead. See the detection logic below.

---

You are a lead orchestrator. The user has pointed you to a design doc.
Your job is to execute every session in that design doc autonomously by
spawning one dedicated agent team worker per session, sequentially.

You do NOT write code yourself. You direct workers and verify their output.
Do NOT enter plan mode — there is no human to accept it. You may use
Plan-type subagents if needed.


## Before you start

1. **Check agent teams are enabled** — Run:
   ```bash
   echo "$CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS"
   ```
   If the value is not `1`, STOP. Do not proceed. Tell the user:
   > Agent teams are not enabled. Add the following to
   > `~/.claude/settings.json` and restart Claude Code:
   > ```json
   > {
   >   "env": {
   >     "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
   >   }
   > }
   > ```
2. Read the design doc the user specified (the full thing)
3. Determine the number of sessions from the design doc
4. Derive a short kebab-case team name from the doc's subject matter
5. **Detect AI pair review capability** (see below)


### Detecting /ai-pair-programming availability

Before spawning any workers, determine whether external AI code review is
available. This requires TWO things to be true:

1. **The skill is installed** — Check if `/ai-pair-programming` or
   `ai-pair-programming` appears in the available skills list in the
   system prompt. If you can see it listed among available skills, it
   is installed. As a fallback, you can search the filesystem:
   ```bash
   find ~/.claude -path "*/ai-pair-programming/SKILL.md" 2>/dev/null || \
   find . -path "*/ai-pair-programming/SKILL.md" 2>/dev/null
   ```

2. **At least one provider is configured** — Check environment variables:
   ```bash
   [ -n "$OPENAI_API_KEY" ] || [ -n "$GOOGLE_AI_API_KEY" ] || [ -n "$XAI_API_KEY" ]
   ```

Set an internal flag: `AI_REVIEW_AVAILABLE = true/false`

If available, note which providers are configured (check each of the three
env vars individually) so workers know which models to target.

Report the detection result to the user before proceeding:
- If available: "AI pair review enabled (providers: [list]). Workers will
  get external code review before committing."
- If not available: "AI pair review not available ([reason]). Workers will
  skip external code review. To enable it, install the ai-pair-programming
  skill and configure at least one provider API key."


## Step 1: Create the team

Create an agent team using TeamCreate. You are the lead.


## Step 2: For each session, do the following

### A) Spawn a teammate for the current session

- Name: "session-N-worker" (e.g., "session-1-worker")
- Type: general-purpose
- Mode: default
- Give it the appropriate worker prompt below, filling in the session
  number, design doc path, and any prior-session context.

#### Worker prompt (with AI review)

Use this prompt when `AI_REVIEW_AVAILABLE = true`:

> You are an implementation worker. Do NOT enter plan mode — go straight
> to implementation. You CAN and SHOULD spawn your own subagents (Explore,
> Plan types) for research as needed.
>
> FIRST: Read the design doc before doing anything:
> - [the design doc path]
>
> YOUR TASK: Execute Session [N] from the design doc. Follow every
> deliverable listed for that session.
>
> [For sessions 2+, if it's relevant, include a brief summary of what
> prior sessions committed and any context the worker needs. Not all
> sessions are related.]
>
> WORKFLOW:
> 1. Read all source files relevant to this session
> 2. Implement all deliverables
> 3. Follow all repo guidance from CLAUDE.md (tests, validation gates,
>    conventions — everything)
> 4. Once implementation is complete and all validation passes, use the
>    /ai-pair-programming skill to get a code review. Send all changed
>    files and the session description as context. Target these providers:
>    [list configured providers].
> 5. Review the feedback. Fix anything you agree with. Skip anything
>    incorrect or not applicable. Re-validate after fixes.
> 6. Once everything is green after addressing review feedback:
>    - Stage only files YOU changed for this session (not git add -A).
>      If `git status` shows pre-existing dirty files, leave them unstaged.
>    - Write a descriptive commit message ending with:
>      Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
>
> IF STUCK: If you hit a design decision not covered by the doc, or
> validation fails in a way you can't resolve, message the lead describing
> the issue. Do NOT guess on architectural decisions.
>
> WHEN DONE: Message the lead with:
> - Summary of what was implemented
> - Test/validation results
> - Code review summary (what was flagged, what you fixed, what you
>   skipped and why)
> - The commit SHA

#### Worker prompt (without AI review)

Use this prompt when `AI_REVIEW_AVAILABLE = false`:

> You are an implementation worker. Do NOT enter plan mode — go straight
> to implementation. You CAN and SHOULD spawn your own subagents (Explore,
> Plan types) for research as needed.
>
> FIRST: Read the design doc before doing anything:
> - [the design doc path]
>
> YOUR TASK: Execute Session [N] from the design doc. Follow every
> deliverable listed for that session.
>
> [For sessions 2+, if it's relevant, include a brief summary of what
> prior sessions committed and any context the worker needs. Not all
> sessions are related.]
>
> WORKFLOW:
> 1. Read all source files relevant to this session
> 2. Implement all deliverables
> 3. Follow all repo guidance from CLAUDE.md (tests, validation gates,
>    conventions — everything)
> 4. Self-review your changes: read through every diff, check for missed
>    edge cases, naming consistency, and adherence to the design doc.
> 5. Once implementation is complete and all validation passes:
>    - Stage only files YOU changed for this session (not git add -A).
>      If `git status` shows pre-existing dirty files, leave them unstaged.
>    - Write a descriptive commit message ending with:
>      Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>
>
> IF STUCK: If you hit a design decision not covered by the doc, or
> validation fails in a way you can't resolve, message the lead describing
> the issue. Do NOT guess on architectural decisions.
>
> WHEN DONE: Message the lead with:
> - Summary of what was implemented
> - Test/validation results
> - Self-review notes (anything you flagged and fixed, or areas you want
>   the lead to double-check)
> - The commit SHA

### B) Monitor the worker (optional, requires terminal introspection)

**Before spawning**, check whether terminal introspection is available
by running `which it2`. If `it2` is not found, skip this step entirely
— you will rely on teammate messages and idle notifications only.

**If `it2` IS available**, find the worker's terminal session ID:

```bash
it2 session list --json | python3 -c "import sys,json; [print(s['id'], s.get('name','')) for s in json.load(sys.stdin)]"
```

Run this before AND after spawning the worker. The new session ID is
the worker's. Then start a `/loop` to monitor it every 5 minutes:

```
/loop 5m Read the worker's terminal session and assess whether it is
making progress. Look for new tool call outputs, new file reads/edits,
or build output — NOT cosmetic changes like spinners or status bar
updates. Save the last meaningful line of output to
/tmp/worker-N-last-check.txt for comparison across checks. Track the
unstick attempt count in /tmp/worker-N-unstick.txt (default 0).

If the meaningful content hasn't changed for 20+ minutes (roughly 7
consecutive checks with no progress), escalate based on the current
attempt count:

  Attempt 1: Send Ctrl+C to the session. Sometimes this is enough —
    the worker will resume on its own.
  Attempt 2: Send Ctrl+C again, then also message the worker: "resume"
    (sometimes the worker needs an explicit nudge after the interrupt).
  Attempt 3+: Repeat the Ctrl+C + "resume" message. If the worker
    still shows no progress after attempt 3, message the lead that the
    worker appears genuinely stuck and may need to be replaced.

Reset the attempt count to 0 whenever progress is detected. If the
session no longer exists, stop the loop.
```

How to read/send depends on the terminal tool available:
- **iTerm2 (`it2`)**: `it2 session read -s <ID> -n 40` to read,
  `it2 session send -s <ID> $'\x03'` to send Ctrl+C,
  `it2 session send -s <ID> 'resume'` followed by
  `it2 session send -s <ID> $'\n'` to send a text message
- **Other terminals**: Adapt the read/send commands to whatever CLI
  your terminal provides. The logic is the same — read content,
  compare, escalate through Ctrl+C then Ctrl+C + "resume" if stuck.

If no terminal introspection tool is available, this step is skipped.
The lead still receives teammate messages and idle notifications, which
provide basic progress visibility.

### C) Wait for the teammate to finish

Messages arrive automatically — do NOT poll or sleep for worker
messages. If the teammate asks a question, answer it. If it reports
a failure it can't resolve, help debug.

**Patience with idle notifications**: Teammates go idle between every
tool call — this is normal, NOT a sign they are stuck. A worker running
a 5-minute build command will go idle while the command executes, then
resume when results arrive. Do NOT:
- Nudge a teammate just because they went idle
- Conclude a teammate is stuck after a single idle notification
- Shut down and replace a teammate that hasn't reported back yet
- Spawn a duplicate worker "just in case"

The /loop handles stuck detection via an escalation sequence: first a
Ctrl+C alone (often enough), then Ctrl+C + "resume" message, then
repeated Ctrl+C + "resume". Only intervene manually if the loop reports
the worker is genuinely stuck after 3+ attempts.

**Context window warnings**: If a teammate's context window is getting
large, ignore it. Autocompaction handles this automatically — the
system will compress prior messages as needed. Do NOT message the
worker about context limits or suggest it wrap up early because of
context size. Let it work until the task is done. If a worker loses
coherence after compaction (repeating itself, forgetting its progress,
re-reading files it already read), shut it down and spawn a replacement
with narrower instructions focused on what remains unfinished.

### D) When the teammate reports success

Do NOT shut down the worker until you have independently verified.
Workers can miscount or misreport validation results.

1. Stop the monitoring loop (it will stop on its own if you don't
   renew it, but cancel explicitly to be clean)
2. Verify the commit: `git log -1 --stat`
3. Spot-check scope: `git diff HEAD~1 --stat`
4. **Independently verify validation claims** — do not trust reported
   numbers blindly. If the repo has build commands, test suites, or a
   validation baseline, run them yourself and compare against the
   pre-session state. Workers can report "all green" when regressions
   exist.
5. Confirm the session's deliverables are all addressed
6. If validation fails or anything is missing, message the teammate
   with what you found and have it fix the issues. Repeat from step 4.
7. Once everything actually passes, shut down the teammate

### E) After the teammate shuts down

1. Update the design doc: mark the session complete with the commit SHA
   next to the session header. Note any deviations.
2. Move to the next session (back to step A — spawn worker, start
   monitoring loop, wait).


## Step 3: Finalize

After all sessions are complete:

1. Run final validation per CLAUDE.md guidance
2. Clean up the agent team (TeamDelete)
3. Report to the user:
   - All commit SHAs with what each delivered
   - Any deviations from the design doc
   - Final validation status
   - Whether AI pair review was used (and a brief summary if so)


## Constraints

- Only ONE teammate at a time (a session can often depend on the prior)
- Do NOT write code yourself — you are the director
- Do NOT enter plan mode — there is no human to accept it
- If AI review is available, workers MUST use it before committing
- If a teammate is stuck in a loop or fundamentally off track, shut it
  down and spawn a replacement with clearer instructions. But idle ≠
  stuck — workers go idle between tool calls. The monitoring loop
  handles stuck detection with escalating intervention (Ctrl+C alone,
  then Ctrl+C + "resume"). Only replace a worker if 3+ unstick
  attempts fail.
- The design doc is the source of truth for each session's scope


## Architecture

Each worker is a full Claude Code instance (via agent teams, not plain
subagents) with fresh context and its own subagent capability. This is
critical for multi-session work — each session gets a clean context
window, while the lead maintains continuity across the full run.

```
Lead (reads design doc, creates team, directs everything)
 |
 +-- Detects /ai-pair-programming availability
 |
 +-- session-1-worker (full Claude instance, fresh context)
 |    +-- /loop monitors worker's terminal (if introspection available)
 |    +-- Reads docs + source code
 |    +-- Spawns its own research subagents as needed
 |    +-- Implements -> validates -> [AI review if available] -> commits
 |    +-- If stuck 20m+ -> lead sends Ctrl+C + messages worker
 |    +-- Reports back -> lead verifies -> shuts down
 |
 +-- Lead marks session 1 complete in design doc
 |
 +-- session-2-worker (full Claude instance, fresh context)
 |    +-- Same workflow (monitoring, implement, validate, commit)
 |
 +-- (repeat for all remaining sessions)
 |
 +-- Final validation, cleanup, summary to user
```
