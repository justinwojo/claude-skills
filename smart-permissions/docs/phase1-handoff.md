# Phase 1 handoff (smart-permissions 1.5.0) → Phase 2

Branch `smart-permissions-holds`. The spec is [findings-2026-11-19-prompts.md](findings-2026-11-19-prompts.md):
Phase 1 plus the council amendments. Phase 1 changes evidence and rules only. No verdict policy changed.

## What landed

1. **Judge key file.** `LLM_ENV_FILE` is `smart-permissions-llm.env` beside the user config.
   - `_load_llm_env_file(path)` returns `(values, note)`. It refuses a file that is a link, not regular,
     owned by someone else, group/world-accessible, or over 64 KB.
   - The file is opened non-blocking, so a FIFO can't hang the hook. Where `os.getuid` or `O_NOFOLLOW` is
     missing (Windows), the file is ignored.
   - The hook reads the file only when `SAFETY_HOOK_MODEL` or `SAFETY_HOOK_API_KEY` is missing from the env.
     `_llm_setting(key)`: the environment wins per key. A blank model or key falls back to the file.
   - `llm_not_configured_reason()` names the file and the note.
   - The path is in `always_ask_write_paths` and `sensitive_paths`.
2. **Clones without remote-tracking refs.** `_clone_observations(repo, bare, deadline)` runs only when the
   repo has a remote. `_repo_loss` changes its count line for such a clone.
   - It reports:
     - a mirror setting;
     - the branch count;
     - loose refs and reflogs (all of `refs/`, `logs/refs/`, `logs/HEAD`) newer than `packed-refs`;
     - `_CACHE_ROOTS`.
   - A scan that ran out of time says so instead of claiming absence.
   - It never says the commits are recoverable.
3. **Subagent brief.** `subagent_brief(path)` returns the first user message of `agent_transcript_path`.
   - System reminders are stripped and the text is capped at 4000 chars, head and tail kept.
   - It returns None for a tool result, a meta record, a missing or non-regular file, or malformed records.
     It never raises.
   - `build_llm_context` labels it as written by an agent and places it before the lead's messages.
4. **Script contents.**
   - `script_files(command, cwd, deadline)` returns `[(path, how)]`. It finds runner operands,
     `source`/`.`, stdin files that look like scripts, cat/base64/… operands that look like scripts, path
     command words, and existing shell scripts named anywhere (at most 20 matches).
   - It follows `cd` (not a scoped one: `_cd_in_scope`) and literal assignments.
   - The cap is 3 files, within a deadline.
   - It never collects a `sensitive_paths` file, the judge key file, or a link to either (`_private_file`).
     On Windows (no `os.getuid`) it collects nothing.
   - `script_context(command, cwd, deadline)` builds the text block: 8 KB per file, 16 KB in total. It shows
     owner-owned regular files only, opens them non-blocking and checks them with fstat.
   - The block notes truncated, missing, binary and unseen-helper files.
   - Script text is not logged:
     - `SCRIPT_CONTEXT_TEXTS` holds what the judge was shown in this call.
     - `log_decision` and the flag state the learner logs from (`_flag_put`) keep only the judge's category
       numbers (`_loggable_reason`), never its words.
     - The reason shown to the human goes through `scrub_script_text` (quoted script text becomes
       `[script text]`).
5. **Stashes.** `stash_context(command, cwd, input_data, deadline)` runs for `git stash drop|clear|pop`,
   including when options come before the subcommand.
   - It shows the stash list with dates before or after session start.
   - `_session_stash_commands(input_data, repo, deadline)` reports this session's Bash calls that ran a
     stash-making `git stash` in that repo (`_makes_stash`), each marked ok, failed or no result yet.
   - A call counts only when every directory named up to that stash command is in the repo, with certainty
     (`_stash_made_in`: `_git_command_dirs` on the text up to it). A nested repository doesn't count. This
     under-credits, for example `git -C X stash` from outside X, which is the safe direction.
   - The transcript scan gets one `PROVENANCE_BUDGET_S` slice.
   - `git stash pop` remains a rules allow (policy unchanged), so its evidence applies only when it reaches
     the judge.
6. **/tmp.**
   - `_temp_top(path)` and `_temp_privacy(top, st)` give the owner and mode of the folder right under /tmp.
     `temp_privacy_context(paths)` is the judge block.
   - `_private_temp_entries(value)` adds the "not world-writable" note to the PYTHONPATH reason in
     `_env_hazard`. It works on real paths, so `..` and links can't leave the folder. That reason is still
     an ask.
   - `_delete_loss` names the remotes of a repo whose root is under /tmp, and now also covers file targets
     (glob matches) inside a repo.
7. **`mcp_context`.** The config dict `MCP_CONTEXT` maps a glob to a sentence; a wrong type is ignored.
   `_mcp_context_notes(tool)` feeds the context. There are no shipped values.
8. **Rules.**
   - `_steer_nonempty(command, segments)` makes the rm-variable steer lenient: loop names over literal
     words, and single top-level literal-text assignments.
     - Neither applies to a multi-name zsh loop, a word with a multi-field expansion (`"$@"b`, `${a[@]}`:
       `_MULTI_FIELD_RE`), a value with a blank (`_steer_literal`), or an assignment with a redirection.
     - Writes, loop heads, defaults and reads are counted on the continuation-joined text.
     - `$'…'` and `$"…"` give no literal text.
   - Loop frames in `_protected_delete_check` fix the nested-loop "protected folder ~" false deny. They
     apply only to one-name loops with no multi-field word. A `""` loop word counts as empty.
   - `sandbox-exec` and `script` are wrappers. (Phase 1b dropped `script`; see below.)
     - `_script_args(tokens)` reads `script` options for util-linux and BSD, util-linux options in any order.
     - `-c CODE` resolves to `sh -c CODE`, and so does `FILE -- WORD…`, which util-linux joins with spaces
       into shell code.
     - Long options match by unique prefix (GNU getopt); an ambiguous one is a doubt. A number after a bare
       `-t` is skipped as BSD's interval and also counted as a possible output file.
     - FILE and the `-O/-I/-B/-T/-tFILE/--log-*` logs are writes (`_wrapper_written_files`).
     - An unknown option is a doubt, and so is a FILE or option value built at run time (`"$OUT"`, `"$@"`,
       a glob). Any `script` call whose own words aren't literal therefore asks, as on HEAD.
     - A wrapper's own words go through the sensitive-path check (`sandbox-exec -f PROFILE`).

The judge prompt (`LLM_SAFETY_PROMPT`) now covers three points:

- how to read a brief and script contents;
- to describe script lines rather than quote them;
- that a developer-owned folder with no group or other write is not world-writable.

`build_llm_context` wraps the new /tmp and stash blocks so they can't fail the hook (`_quietly`). The
script and brief readers catch their own errors.

Tests: `test_phase1_evidence_and_rule_fixes` in tests/test_hooks.py, including the "review fixes" and
"review round 2" sections. Eval cases E01–E08 are in tests/llm_eval_cases.json. `llm_eval.py` supports
`sandbox.brief`, a case-level `mcp_context`, and a `{root}` directly under /tmp.

## Interfaces Phase 2 can rely on

- `build_llm_context(input_data) -> str`. Every new block is appended here, so both hooks get it.
  `input_data` needs `cwd`, `tool_name`, `tool_input` and `transcript_path`, plus `agent_transcript_path`
  for a subagent.
- `subagent_brief(path, limit=4000) -> str | None`. Phase 2's "covered by the developer's messages or the
  subagent brief" check can call it directly.
- `script_files(command, cwd, deadline=None) -> [(abs_path, how)]` and
  `_read_script(path, limit) -> (text | None, note)`.
  - A note containing "TRUNCATED", "not shown", "could not be read" or "does not exist" means the judge did
    not see the full payload. That is the "full payload visible" input of the prod-exec policy.
  - `script_context` adds "names other local scripts not shown here" for unseen helpers.
  - Phase 2 should probably return these as structured flags rather than parse the text.
- `SCRIPT_CONTEXT_TEXTS`, `scrub_script_text(reason)` and `_loggable_reason(reason)`. A Phase 2 resolver
  field that echoes judge text must go through them too.
- `stash_context(...)` and `_session_stash_commands(...) -> ([(ts, cmd, outcome)], whole)` are the hook-side
  stash check the amendments mention.
- `_temp_top` / `_temp_privacy` / `_private_temp_entries` for /tmp facts.
- `MCP_CONTEXT` and `_mcp_context_notes(tool)`.
- `_llm_setting(key)`, `LLM_ENV_FILE` and `LLM_ENV_FILE_NOTE`.

## Open questions for Phase 2

- `script_files` does not treat `ssh host 'bash -s' < x.sh`-style remote targets specially. Phase 2's
  remote-exec class needs its own recognizer (`az containerapp exec`, `kubectl exec`, …). The script
  collector only supplies the payload.
- The script collector shows a file's contents *now*. A call that writes the script first (heredoc then
  run) shows the old file or "does not exist now". Phase 2 may want to treat that as "payload not visible".
- A failed `cd` is assumed to succeed when following it to a script (the same assumption the
  `destructive_targets` evidence makes).
- Holds need the acting agent's transcript. `agent_transcript_path` is present for subagents, and
  `_session_transcripts` already lists subagent transcripts.
- Eval:
  - E07 (a prod container exec with a visible read-only script) is labelled allow, per the owner's "OK if
    it does what it should". Under Phase 2 policy it would need `confident: true`. Relabel it if the policy
    decides otherwise.
  - E05 relies on `/private/tmp/claude-<uid>` existing on the eval machine with uid 501. On another machine
    the rule reason lacks the private note.
- The review loop hit its five-round cap. The round-5 fixes are tested but were not re-reviewed by Codex:
  runtime-built `script` words as a doubt, an attached `-tN` counted as a file, and the whole-text parse in
  `_stash_made_in`. `script` produced Highs in rounds 2–5. If it keeps costing, the fallback is to drop it
  from `_INTERPRETER_WRAPPERS` (HEAD's behaviour: every call asks) and keep only `sandbox-exec`.
- The key file's privacy check reads mode bits, not ACLs (macOS `ls -le`). The README says so. A
  `chmod 600` file with an ACL grant passes.
- Separator-free loops (`for a in x do rm -rf ~`) are rule-allowed. This is a parse quirk on HEAD too, not
  new. Bash and zsh reject that text as a syntax error, so nothing runs. The form that does parse (`do` on
  the next line) denies.
- Field splitting through an *expansion* inside an assigned value (`S="$X"a` with a blank `X`, used
  unquoted) is not modelled by the steer. The `${S:?}` rewrite the steer asks for doesn't guard it either.

# Phase 1b (smart-permissions 1.6.0): fewer judge calls

Same branch. Rules and evidence only; no verdict policy changed. Nothing new is allowed that the
historical logs show as a non-allow (replay gate below).

## What landed

- **a. Python heredocs.** `_interpreter_stdin_verdict(part, command)` lets a `python`/`python3` part through
  to the AST check only when its flags are plain (no `-X`/`-W`), it reads `-` or nothing, its one stdin
  is one complete heredoc with a quoted delimiter (`_quoted_heredoc_code`), nothing pipes into it
  (`_piped_into`), and `_python_heredoc_ok` passes: no hijack env, no non-UTF-8 coding cookie, the header
  found once in the original command, and the real body (from the command text, not the splitter's
  part) equal to the part's body with `#` lines dropped.
- **a. Stricter AST check** for heredocs and `-c` alike (`_safe_python_code`): calls must be safe
  builtins, names bound in the code, or methods; `.replace` only with 2–3 plain positional args on a
  non-module receiver; `open` only read-mode with a path `_py_string_resolver` can resolve (literals,
  names bound once, loops over literal lists, f-strings and `+`), each candidate passing the native Read
  sensitive check (`_python_read_ok`). Relative paths resolve against every `cd` target and need certainty
  (`_py_candidate_paths`). Shell constants (`S=/abs; python3 -c "open('$S/x')"`) and `$HOME` are
  substituted first (`_code_with_constants`).
- **Comment heredoc.** A `<<` after an unquoted `#` (`_commented_heredoc`) opened a heredoc in our parser
  but not in the shell, hiding the following lines as data. It is now a judge ask (not human-required).
  This was allowed on 1.5.0 too.
- **c. Conditional bindings.** `_conditional_alternatives(part, command)` returns the bound and unset
  alternatives for a name assigned at the end of an and-chain (`_command_constants(conditional=True)`);
  each is judged by the rules and every one must allow. Refused when the name is in `os.environ`.
- **d. CLI reads.** `_glab_risk`, `_terraform_risk`, `docker compose exec/run` in `_docker_risk`, new exact
  `az`/`glab` entries in defaults.json, `_MAX_COMMAND_WORDS` 4 → 5, and the az credential pattern
  extended (`appsettings`, `list-publishing-profiles`, `password`).
- **e. Decision log.** Records carry `v` (`HOOK_VERSION`), `input_len`, `truncated`; files are 0600;
  `_append_log_line` rotates under a non-blocking flock with a size re-check. Opt-in
  `decision_log_full_input` (64 KB, `_redact_secrets`, `redacted`/`incomplete` flags).
- **f. Learner.** Every exit logs a `rule_reason`; the built-in `AskUserQuestion` (exact name) logs an ask
  and exits without the judge.
- **g. C9 needs a write.** `_writes_config(cmd, relieve)` relieves a Python part whose code passes
  `_python_writes_no_config` (a full write scan: write modes, os/shutil/pathlib writers, modules whose
  writes can't be seen); an unproven Python part naming a config path still prompts. `_heredoc_views`
  attaches heredoc bodies to their header part. Redirect targets are checked by realpath
  (`_redirect_reaches_config`), so a link into a config file prompts.
- **h.** `live_hook_note(tool_input)` tells the judge which copy of the guard is live when a call names
  hook files.
- **i.** `script` is no longer a wrapper; `_script_args` and its tests are gone. `script` stays in
  `_FILE_WRITER_COMMANDS`.

Replay gate: 41,596 distinct complete inputs from the historical logs replayed against 1.5.0 and 1.6.0
rules (see the 1.6.0 commit message for the counts). Tests: `test_phase1b_fewer_judge_calls`. Eval
case E09 (patching the guard in a worktree); `llm_eval.py` now adds `live_hook_note` to the context.

## Interfaces

- `HOOK_VERSION`.
- `_safe_python_code(code) -> bool` (the strict read-only subset) and
  `_python_writes_no_config(code) -> bool` (the C9 write scan). A Phase 2 "Python writes to safe paths"
  rule would start from the second, not the first.
- `_py_string_resolver(tree)` and `_py_candidate_paths(path)` for static path facts.
- `_conditional_alternatives(part, command) -> (bound, unset) | None`.
- `_append_log_line(path, line, max_bytes)` for any new log.
- `live_hook_note(tool_input) -> str`.

## Open questions

- A name read but never assigned in the command is assumed to come from the environment, which the
  hook can see (`os.environ`); a value set later by a sourced file is not modelled.
- `split_compound_command` drops every line starting with `#`, heredoc bodies included. The heredoc path
  works around it (`_comment_lines_dropped`, the real-body check), and `_cd_in_scope` now uses the same
  view. Fixing the splitter itself would touch every rule.
- `_command_constants` refuses any command containing `<<`, so `S=/abs; python3 - <<'E'` with `$S` in a
  quoted body can't use constants (a quoted body doesn't expand anyway) and `$PY - <<'E'` stays with the
  judge (8 log cases).
- The comment-heredoc ask is new; a legitimate `# … <<` in a comment now reaches the judge.
- Dynamic reads (`open(f)` over a computed list, `open(sys.argv[1])`) still go to the judge; they are the
  largest remaining inline-Python group.
- The Python read check resolves links as they are before the command runs. An earlier part of the same
  command can make a link (`cp -P a x; python3 … open('x')`). Bash readers are weaker still: `cat LINK`
  of a link to a sensitive file is a rules allow (the sensitive-path check is textual for Bash). A
  link-aware check for Bash readers would close both.
- `_py_module_attr_unsafe` / `_py_chain_is_module` look re-exports and submodules up in the hook's own
  interpreter (importing allowlisted stdlib modules); a different `python3` on PATH may export other
  names. `_SAFE_PY_SUBMODULES` lists the data-only submodules allowed through a chain.
- `_py_rebound_names(tree)` is shared by the strict checker and the C9 scan; it must stay importable on
  Python 3.9 (match and type-parameter nodes are looked up with getattr).
- glab placeholders other than `:id` go to the judge; docker's own global options are parsed before
  `compose` (`_DOCKER_VALUE_OPTS`, `_DOCKER_FLAGS`).
- A relative `./script` (a link to the utility) is trusted like any project script.
