"""smart-permissions hook code (stdlib only).

core     the PreToolUse hook and the shared rules, judge context and orchestration
learner  the PermissionRequest hook
config   config loading and merging, derived constants, state file paths
judge    the judge's settings, prompt texts and HTTP client
log      decision-log input, redaction and append; the unknown-command log
holds    the holds store
util     small stateless helpers

core imports the others and re-exports their names; they never import core.
The entry points are the shims beside this package, scripts/pretool_safety.py
and scripts/permission_learner.py, which hooks/hooks.json runs.
"""
