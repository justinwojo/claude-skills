"""smart-permissions hook code (stdlib only).

core     the PreToolUse hook and the shared rules, judge context and orchestration
learner  the PermissionRequest hook
config   config loading and merging, derived constants, state file paths
judge    the judge's settings, prompt texts and HTTP client
log      the decision log (log_decision; input, redaction, append); the unknown-command log
flags    the flag store (calls PreToolUse put to the developer)
holds    the holds store
state    the per-call state of one hook invocation
payload  normalizing a hook payload (other agent CLIs' tool names and keys)
util     small stateless helpers

core imports the others and re-exports their names; they never import core.
The entry points are the shims beside this package, scripts/pretool_safety.py
and scripts/permission_learner.py, which hooks/hooks.json runs.
"""
