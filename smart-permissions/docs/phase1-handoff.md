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

# Phase 2 (smart-permissions 1.7.0): hold and ask

Same branch. Verdict policy changes: a flag the agent can settle is held as a question; remote and
production execution is judged strictly. Holds are on by default after a live `claude -p` trial (below).

## What landed

- **Verdict fields.** `LLM_SAFETY_PROMPT` and `_SAFETY_SCHEMA` add `confident` (bool), `resolver`
  (`agent`/`developer`) and `question`; only `safe` stays required. `_llm_evaluate`'s info carries the
  deciding pass as `verdict` (a refused pass is marked `refused`). `_llm_user_prompt` is factored out.
- **Holds** (`HOLDS_ENABLED`, config `holds`, default true in defaults.json). `_hold_new` (after both
  passes flag): `hold_resolver` → `("agent", "")` or `("developer", why)`; developer when the verdict is
  missing or refused, category 2/5, category 3 on WebFetch/MCP/egress (`_sends_off_machine`),
  `cloud_destroy`, `remote_exec`, or a `resolver` other than `"agent"`. Not held either without a session id or
  a readable transcript, at the session cap (`HOLD_SESSION_CAP` 4 per `HOLD_CAP_WINDOW_S` 900s), or for a
  call held once already. A held call is a PreToolUse deny with `hold_message`, logged `llm-hold`.
- **Retry** (`_hold_retry`, before the normal judge): a live `held` hold made before this hook started,
  claimed once (`hold_claim`, an O_EXCL `.retry` marker). No answer → the developer without a judge call;
  otherwise `llm_evaluate_retry` (one pass at `LLM_RECHECK_REASONING_EFFORT`, `LLM_HOLD_RETRY_NOTE` with
  the reason, question and answer) clears (`hold-retry` allow) or asks (`hold_retry_ask`: question,
  hold reason, what the retry found, the claim labelled and cut to 600 chars). Every explicit ask goes
  through `_ask_developer`, which writes the flag store, so the learner never overrules it.
- **Answer** (`agent_answer_since`): assistant `text` and `thinking` blocks after the hold, from the acting
  agent's transcript (`acting_transcript`: `agent_transcript_path`, else
  `<session>/subagents/agent-<agent_id>.jsonl` when `agent_id` is set, never the lead's), reminders stripped, last 3000 chars.
  Thinking counts because the live trial showed agents settling the question there and retrying with no
  visible message.
- **Store.** `HOLD_DIR` (`~/.claude/hooks/smart-permissions-holds/`, in the C9 state paths), one JSON file per
  `hold_key` (sha256 of session, agent, cwd, tool, input minus Bash `description`). `_hold_write` writes
  a unique temp file and links it in (exclusive) or replaces; `hold_create` returns the hold in force on
  a race, so two identical concurrent calls make one hold and both are denied. TTL 900s, files pruned
  after a day by `hold_count`. The answer is never stored or logged.
- **Remote exec** (`remote_exec(command) -> label | None`): az/aws/gcloud/fly pairs, kubectl/oc exec verbs,
  `heroku run`, docker/podman on a remote host (`-H`, `--context`/`-c`, `--connection`, podman
  `--remote`/`--url`, `DOCKER_HOST`/`DOCKER_CONTEXT`, a `docker context use` in the command or docker's
  current context; local contexts excluded), also behind runners such as `script`, `timeout`, `env`, and
  through the guard's constants (`K=kubectl; $K exec`). Plain `ssh` is excluded (the decision log showed
  it routinely approved). First `remote_gap(command, label)` (fail-closed `remote_payload_gap`): the
  payload must be the command text (inline or a heredoc), with no redirect or pipe outside heredoc
  bodies, no `$` or backtick anywhere (quoting is not parsed), no `@file`/`file://`/`--…-uri`, no
  `source`, no file copy in any of its remote commands (`_remote_execs`). A gap is an explicit ask before
  any judge call, in both hooks, so an opaque payload is never sent to the judge. Otherwise a rules
  allow becomes a judge call and `remote_exec_verdict(decision, reason, info, label)` keeps the judge's
  allow only with `confident is True`. A docker config that can't be read whole counts as a remote
  context. Every such ask is `hold: remote-exec`.
- **Review-driven redesign.** The first version allowed a remote exec fed from a local script the judge
  was shown in full (script gaps tracked per file). Review kept finding ways around that bookkeeping
  (the file cap, wrappers, writes through variables, credential files read as payloads), so it was cut
  back to the text rule above. E07 (a diagnostics script piped into a prod container shell) is now
  labelled `flag`/`developer_only`. `script_context` still marks a script the command writes first.
- **Eval.** `llm_eval.py` scores each run's outcome (`outcome_of`: allow/hold/developer/fallthrough) and
  each case's `sequence` (hold → answer → `llm_evaluate_retry`; a run that did not hold uses the case's
  stand-in `hold`; `retry_setup` changes the sandbox before the retry's evidence). New cases S01-S06 and
  sequences on E01, E04, P02, P05, P08; E08 is `developer_only`. Final `--runs 3` (judge
  claude-haiku-5-5, effort low, recheck high): recall 100% of 228 runs; false flags 6 of 192 (first pass
  11); 233 stopped runs, 20 held, 213 to the developer, 4 holds on should-allow runs; developer-only
  72 runs, held 0, allowed 0; sequences: natural retries right 1/4 (one retry ran out of time, one
  answer twice not accepted), forced retries 44/44; latency p50 3219 ms, p90 4879, max 24010 (the
  budget); retry p50 3198, p90 9400, max 24003.
- **Tests.** `test_phase2_holds`, `test_phase2_remote_exec`; `_run_cfg` gains `outputs` and
  `SP_MOCK_DELAY`.
- **Also changed.** A verdict with no valid `safe`, and a first-pass flag whose recheck times out,
  errors or is unparseable, are explicit asks recorded in the flag store (1.6.0 fell through). The flag
  store's writes take an `fcntl` lock and a unique temp file, so parallel hooks keep every entry.

## Live trial (`claude -p`, Claude Code 2.1.328)

Scratch repos, the plugin from this worktree via `--plugin-dir`, `--setting-sources project` so the
installed copy did not load (one smart-permissions instance in the init record), a scratch config with
holds on. A pre-session stash whose change is already on main, with "drop leftover state whose changes
are already committed on main": nine runs, seven holds. After a hold the agent rewrote the command into
a guarded one once (judged fresh, allowed); retried with no visible answer three times (two of them
with a system-prompt hint to retry; the answer was in its thinking, fixed by reading thinking); twice
answered briefly, was flagged again on the retry, then rewrote the command (allowed); and once, after
the thinking fix, answered and retried the identical call, which the retry judge cleared (`hold-retry`
allow). The other two runs were allowed without a hold. A prod namespace delete under a
staging request reached an explicit ask (`not held: it deletes cloud, production or remote resources`)
and `-p` denied it with the reason. In `-p`, that ask produced no PermissionRequest record.

## Denial limit

Auto mode's limits (3 consecutive, 20 total) count classifier blocks. In the 2.1.328 binary the counter
is incremented on the classifier-block path, not the "Hook denied" path, and `PermissionDenied` does not
fire for PreToolUse blocks, so hook denies (holds) are not counted. In `-p` the limit never aborts a run.
This is read from minified code and the docs, not from a documented guarantee.

## Interfaces

- `hold_key(input_data, tool, tool_input)`, `hold_get/hold_create/hold_claim/hold_finish/hold_count`.
- `hold_resolver(tool, tool_input, verdict) -> (resolver, why)`.
- `remote_exec(command)`, `remote_payload_gap(command, label)`,
  `remote_gap(command, label)`, `remote_exec_verdict(decision, reason, info, label)`, `cloud_destroy(command)`.
- `llm_evaluate_retry(tool, tool_input, hold, answer, timeout, context, rule_reason)`.
- `agent_answer_since(path, since, limit)`, `acting_transcript(input_data)`.

## Open questions

- The judge sends most flags to the developer (in the final eval, 20 of 233 stopped runs were held).
  Most are true dangers, but some agent-resolvable ones (a pre-session stash under "tidy") go to the
  developer too. Worth watching in the decision log (`hold: not held: …`).
- The retry judge clears well-evidenced answers but rejects ones that do not address the question's
  point; agents often answer briefly. The hold message could carry a short example of a good answer.
- `bash script.sh` / `./script.sh` is a rules allow by default (since before 1.7.0), so a local script that
  deletes production resources never reaches the judge; the remote-exec class only covers commands
  that name a remote exec. A rule that reads a local script for cloud-destroy or remote-exec commands
  would close it.
- The review loop ran its five Codex rounds (security scope). The round-5 fixes (a reply that is not
  JSON or has malformed content → explicit ask; a heredoc body run by local bash checked for remote
  payload gaps; docker config keys matched without case, anything unreadable or too deep → remote) are
  tested but were not re-reviewed by Codex.
- `cloud_destroy` and `_sends_off_machine` are pattern lists; they gate only the resolver (never hold),
  so a miss falls back to the judge's own `resolver`.
- A held call that the agent rewrites is judged fresh; a rewrite that only adds a cosmetic wrapper gets
  a fresh hold (one per distinct call), bounded by the session cap.

## Branch review (1.7.0 review fixes)

One Codex round on `main..HEAD` (emphasis on each phase's unreviewed round-5 fixes) and one on its
fixes; the second round's fixes were not re-reviewed. Tests: `test_review_fixes_1_7_0`.

- Fixed: def/class rebinding of an imported name in `_python_writes_no_config`; glab `triggers` and
  `clusters` endpoints; `script` code (separate or attached to its option) and standalone
  `docker-compose`/`podman-compose` (exec, run, cp, attach) in `_remote_execs` (which now takes an
  `env_remote`); a Compose `run` on a remote host is a payload gap (local compose file); a local-bash
  heredoc body is scanned with docker counted as remote; `hold_resolver_info` (the first pass's
  developer-only category blocks a hold; llm_eval uses it too); a recheck whose category differs
  from the first pass names both; `git push`/`send-email` (by subcommand, `_git_subcommand`) in
  `_sends_off_machine`; `_stash_made_in` walks `split_compound_command` segments.
- Left open (Low or by design): the judge-reply JSON fallback and the recheck clearing a first-pass
  flag (both on main); a script that exists only on the remote side (the judge's `confident` call);
  project-local modules imported by `python3 -` (project scripts are rule-allowed already); docker
  contexts with local-looking names pointing at a remote daemon; a remote docker delete in
  `cloud_destroy`; embedded credentials in script evidence; the hold cap race; the judge's free-text
  retry reason in the log; a standalone Compose service named like a verb (over-strict); a quoted
  backslash-newline before a stash (under-credit); glab resource names matching secret components
  (over-strict); BSD `script` printing remote-exec text (over-strict).

# 1.8.0: unanswered prompts are parked; local scripts are read

Same branch. A policy change for prompts (a deny after a wait, never an allow) and a narrow rule change
for project scripts.

## What landed

- **Prompt timeout** (`permission_learner._developer_prompt`). Every learner path that used to exit with
  no decision (a definite ask, no judge, a PreToolUse flag or explicit ask from the flag store, a remote
  payload gap, a judge flag or error) logs its `ask` as before, then, unless the timeout is off or the
  run is unattended, sleeps once for the rest of `PROMPT_TIMEOUT_S` (counted from hook start) and prints
  a PermissionRequest deny (`interrupt: false`) with `parked_message(reason, minutes)`. Not for allows,
  rule denies, `AskUserQuestion`, malformed input or a hook error.
  - Config `prompt_timeout_minutes` (defaults.json 10). `_prompt_timeout_s`: bool/non-number/NaN → 10,
    `<= 0` → off, else clamped to 1–60 minutes (`PROMPT_TIMEOUT_MAX_MINUTES`). hooks.json gives the
    learner `timeout: 3660`.
  - `_unattended()`: `CLAUDE_CODE_SESSION_ATTENDED == "0"`, or the variable absent and
    `CLAUDE_CODE_ENTRYPOINT` starting with `sdk`. Checked on Claude Code 2.1.329: `claude -p` runs the
    PermissionRequest hook for a fall-through with `ATTENDED=0`, `ENTRYPOINT=sdk-cli`; an interactive
    session has `1` and `cli`. Without this a `-p` run would stall for the full timeout.
  - After the sleep: nothing if the parent process changed (Claude Code gone) or `_prompt_answered`
    finds a `tool_result` for every `tool_use` in the acting transcript tail with this call's name and
    input (the prompt has no id, so one identical call still pending counts as unanswered; the developer
    answered; Claude Code ignores a late hook decision anyway, this keeps the log
    true). A transcript it can't read counts as unanswered: the deny is harmless if ignored.
  - The message carries the reason the developer would have seen, through `scrub_script_text`; the log
    record (`source: prompt-timeout`, `hold: prompt-timeout`, decision `deny`, the `rule_reason`) keeps
    `_loggable_reason(reason)`. It follows the call's `ask` record. With no judge, a PreToolUse flag
    (an explicit ask) is the reason shown, not the judge-setup message.
  - Tests set `CLAUDE_CODE_SESSION_ATTENDED=0` for the whole suite; `_run_cfg(patch=…)` injects
    `_m.PROMPT_TIMEOUT_S` and a recording `_m._sleep`.
- **Script hazard** (`script_hazard(command, cwd=None, deadline=None)`). For each file `script_files`
  finds that runs as shell code (`_runs_as_shell`: run by a shell runner, sourced, fed on stdin to a
  shell, or run directly with a shell `#!` or none), read up to `SCRIPT_SCAN_MAX_BYTES` (64 KB) with
  `_read_script` and scanned with `_remote_execs` and `cloud_destroy`. Every script is scanned; returns
  `(remote, gap, destroy)` (each the first of its kind across the scripts, or None) or None for no hit.
  The gap, for a remote hit: the call writes the script first; the judge is not shown all of it (the
  8 KB per-file and 16 KB total budgets of `script_context`, in the same order); the call feeds it input
  (a `<` redirect, or a pipe before its name); else `remote_gap` on the script text. A docker endpoint
  the command names (`DOCKER_CONTEXT=… ./x.sh`, `_names_docker_endpoint`) applies to the script. A
  script the call writes first (`_written_files`, factored out of `script_context`) is scanned both as
  the file is now and as the command's heredoc bodies and quoted words. Unreadable files and files over
  64 KB give no hit (the rules' answer, as before).
  - PreToolUse: a remote hit becomes the call's `remote` when the command has none, and a script gap is
    the call's gap when the command has none (gap → explicit ask with no judge call; else the strict
    confident-only judge path). A destroy hit turns a rules allow into a judge call with rule reason
    "Runs a local script that deletes …: judged", skips `_hold_retry`, and is an explicit ask when the
    judge gives no answer (no judge, an error). `hold_resolver` sends both to the developer. The learner
    applies the remote hit and gap the same way (gap → developer, no judge).
- **Script collector** (`script_files`, also the judge's evidence): `bash -e x.sh` (any shell option but
  `-c`) runs `x.sh`; a script read and then run (`cat x.sh; bash x.sh`) is labelled by the run.

Tests: `test_prompt_timeout_1_8_0`, `test_script_hazard_1_8_0`.

## Interfaces

- `PROMPT_TIMEOUT_S`, `PROMPT_TIMEOUT_MAX_MINUTES`, `_prompt_timeout_s(value)` (pretool_safety).
- `permission_learner.parked_message(reason, minutes)`, `_developer_prompt(input_data, tool, tool_input,
  reason, start, rule_reason)`, `_unattended()`, `_prompt_answered(input_data)`, `_sleep` (the one wait; tests patch it).
- `script_hazard(command, cwd=None, deadline=None)`, `_runs_as_shell(how, text=None)`,
  `_written_files(command, cwd)`, `_heredoc_bodies(text)`, `_names_docker_endpoint(command)`,
  `SCRIPT_SCAN_MAX_BYTES`.

## Open questions

- Not live-tested end to end in an interactive session with the plugin (the dialog-during-hook behaviour
  was verified with a plain sleeping hook on 2.1.328/329). Whether Claude Code kills the learner when the
  developer answers is unknown; either way nothing reaches Claude.
- Parallel tool calls: if Claude Code queues their dialogs while every learner runs, the later prompts'
  timers start before their dialog shows.
- `ATTENDED`/`ENTRYPOINT` are observed, not documented. A future Claude Code that drops both would make
  `-p` runs wait (bounded by the timeout), not approve anything.
- The script scan: shell scripts only (not `python3 x.py`, `make`, `npm run`), one level (a script that
  calls another script is not followed), at most `SCRIPT_CONTEXT_MAX_FILES` files, text patterns only
  (`$CLI delete` is missed), and `cloud_destroy`'s word match can send a read-only script to the judge
  (`kubectl get pods --context delete`). A remote script past about 50 lines hits `remote_payload_gap`'s
  50-round cap and is "it could not be read" (an explicit ask), unchanged so direct remote calls keep
  their policy. `cat x.sh | bash` already asks (shell reading stdin) but is not scanned.
  `llm_eval.py` does not apply it (its sandbox scripts are built after the rule verdict).
- A remote exec in a script with any `$` is a gap, so nearly every real remote script comes to the
  developer; that is the 1.7.0 text rule applied to the script, by design.
