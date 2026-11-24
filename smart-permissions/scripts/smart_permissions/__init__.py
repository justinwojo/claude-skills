"""smart-permissions hook code (stdlib only), in layers, bottom up:

config      config loading and merging, derived constants, state file paths, HOOK_VERSION
util        small stateless helpers
state       the per-call state of one hook invocation
payload     normalizing a hook payload (other agent CLIs' tool names and keys)
log         the decision log (log_decision; input, redaction, append); the unknown-command log
holds       the holds store
flags       the flag store (calls PreToolUse put to the developer)
transcript  reading session transcripts (recent messages, an agent's answer)
judge       the judge's settings, prompts and HTTP client, and its verdicts (both passes, the retry)
core        the shell parser, the rules and gates, and the PreToolUse hook (main)
context/    what the judge is shown: build_llm_context and its blocks (git, provenance,
            loss, scripts, notes)
holdflow    holding a call for the agent to answer, and judging its retry
learner     the PermissionRequest hook

A module imports only from the layers below it, and only the names it uses.
context/ and holdflow read commands with core's parser, so they sit above it;
core's hook flow imports them when a call goes to the judge.
The entry points are the shims beside this package, scripts/pretool_safety.py
and scripts/permission_learner.py, which hooks/hooks.json runs.
"""
