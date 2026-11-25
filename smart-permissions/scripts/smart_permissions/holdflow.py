"""Holding a call for the agent to answer, and judging its retry: the steps
of the PreToolUse flow around the holds store (holds.py). _hold_new holds
a call both judge passes flagged when the agent may settle it;
_hold_retry judges the identical call again with the agent's answer.
Above core (it uses core's resolver and output); core imports it only
inside _main, on the judged path."""
import re
import time

from .util import _elapsed_ms
from .log import compose_reason, log_decision
from .holds import (
    HOLD_CAP_WINDOW_S, HOLD_CLAIM_CHARS, HOLD_QUESTION_CHARS, HOLD_SESSION_CAP,
    _HOLD_DEFAULT_QUESTION, acting_transcript, hold_claim, hold_count, hold_create, hold_finish,
    hold_get, hold_key,
)
from .transcript import agent_answer_since
from .judge import (
    LLM_PRETOOL_BUDGET_S, LLM_RECHECK_MIN_S, llm_evaluate_retry, scrub_script_text,
)
from .core import _ask_developer, hold_resolver_info, output_decision


def hold_message(reason, question):
    """The deny text a held call's agent reads: a question, not a refusal."""
    return (f"Held by smart-permissions (a question, not a refusal): {reason}. {question} "
            "Write your answer as a message first, with the evidence (what you checked and "
            "what it showed; only text written after this hold is read), then retry the "
            "identical call; if you can't vouch for it, ask the developer.")


def hold_retry_ask(hold, now, answer, script_texts):
    """The prompt reason after a held call's retry: the hold reason in the
    hook's words, what happened on the retry (`now`), and the agent's answer
    labelled as its claim (`answer` None: not shown), scrubbed of the script
    texts the judge was shown. The hold's flag and question are the judge's
    words (a question the hook supplied, `question_default`, is its own), and
    so are those `now` holds (compose_reason): the log keeps them only when
    neither the hold's judge nor the retry's was shown a script."""
    now = list(getattr(now, "parts", None) or [now])
    now[-1] = now[-1].rstrip(".") if isinstance(now[-1], str) else (now[-1][0].rstrip("."),)
    question = hold["question"] if hold.get("question_default") is True else (hold["question"],)  # the hook's own
    parts = ["smart-permissions held this call and asked the agent: ", question,
             " Held because: ", (hold["reason"].rstrip("."),), ". On the retry: ", *now, "."]
    if answer:
        claim = scrub_script_text(" ".join(answer.split()), script_texts)
        if len(claim) > HOLD_CLAIM_CHARS:
            claim = claim[:HOLD_CLAIM_CHARS] + " […]"
        parts.append(f" The agent's explanation (its claim, not verified): \"{claim}\"")
    return compose_reason(*parts, scripts=hold.get("scripts") is not False)  # a hold from before 1.8.4: unknown


def _hold_retry(state, input_data, tool, tool_input, context, rule_reason, start, wall_start):
    """Judge the retry of a held call. False when this call is not one (no
    live, unspent hold made before this hook started), else True: it has
    been decided and the output written."""
    key = hold_key(input_data, tool, tool_input)
    hold = hold_get(key) if key else None
    if not hold or hold.get("state") != "held" or hold["ts"] >= wall_start:
        return False
    texts = state.script_texts
    if not hold_claim(key):
        reason = hold_retry_ask(hold, "another retry of this call was already being judged", None, texts)
        _ask_developer(state, tool, tool_input, reason, reason, start, "hold-retry", None, rule_reason,
                       hold="retry-busy")
        return True
    transcript = acting_transcript(input_data)
    answer = ""
    for wait in (0, 0.3, 0.7):  # Claude Code may still be writing the transcript
        time.sleep(wait)
        answer = agent_answer_since(transcript, hold["ts"]) if transcript else ""
        if answer or not transcript:
            break
    remaining = LLM_PRETOOL_BUDGET_S - (time.monotonic() - start)
    if not answer or remaining < LLM_RECHECK_MIN_S:
        hold_finish(key, hold, "asked")
        why = "the agent retried without answering" if not answer else "no time was left to judge it"
        reason = hold_retry_ask(hold, why, None, texts)
        _ask_developer(state, tool, tool_input, reason, reason, start, "hold-retry", None, rule_reason,
                       hold="no-answer" if not answer else "no-time")
        return True
    decision, reason, info = llm_evaluate_retry(
        tool, tool_input, hold, answer, timeout=remaining,
        context=context, rule_reason=rule_reason, script_texts=texts)
    if decision == "allow":
        hold_finish(key, hold, "cleared")
        log_decision("pretool", tool, tool_input, "allow", "hold-retry", reason,
                     duration_ms=_elapsed_ms(start), llm_ms=info.get("llm_ms"),
                     rule_reason=rule_reason, hold="cleared", state=state)
        output_decision("allow", reason)
        return True
    hold_finish(key, hold, "asked")
    shown = hold_retry_ask(hold, reason, answer, texts)
    logged = hold_retry_ask(hold, reason, None, texts)  # no claim
    _ask_developer(state, tool, tool_input, shown, logged, start, "hold-retry", info.get("llm_ms"),
                   rule_reason, hold="asked")
    return True


def _hold_new(state, input_data, tool, tool_input, reason, info, start, wall_start, rule_reason):
    """Hold a call both passes flagged, if the agent may settle it: write the
    deny with the question and return None. Else return why not (the flag
    then goes to the developer)."""
    resolver, why = hold_resolver_info(tool, tool_input, info)
    if resolver != "agent":
        return why
    key = hold_key(input_data, tool, tool_input)
    if not key:
        return "no session id to bind a hold to"
    if not acting_transcript(input_data):
        return "no transcript to read the agent's answer from"
    hold = hold_get(key)
    if hold is None:
        if hold_count(input_data["session_id"]) >= HOLD_SESSION_CAP:
            return f"this session reached {HOLD_SESSION_CAP} holds in {HOLD_CAP_WINDOW_S // 60} min"
        verdict = info.get("verdict") or {}
        question = verdict.get("question") if isinstance(verdict.get("question"), str) else ""
        question = scrub_script_text(" ".join(question.split()), state.script_texts)[:HOLD_QUESTION_CHARS]
        flag = re.sub(r"^LLM:\s*", "", reason).strip().rstrip(".")
        hold = hold_create(key, {"v": 1, "ts": time.time(), "session": input_data["session_id"],
                                 "tool": tool, "reason": f"the judge flagged it ({flag})",
                                 "question": question or _HOLD_DEFAULT_QUESTION, "question_default": not question,
                                 "state": "held", "scripts": bool(state.script_texts)})
        if hold is None:
            return "the hold could not be recorded"
    elif hold.get("state") != "held" or hold["ts"] < wall_start:
        return "this call was held once already; a second flag goes to the developer"
    log_decision("pretool", tool, tool_input, "deny", "llm-hold", reason,
                 duration_ms=_elapsed_ms(start), llm_ms=info.get("llm_ms"),
                 rule_reason=rule_reason, hold="held", state=state)
    output_decision("deny", hold_message(hold["reason"], hold["question"]))
    return None
