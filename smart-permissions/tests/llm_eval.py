#!/usr/bin/env python3
"""
Live eval of the smart-permissions LLM judge (opt-in, real API calls).

Runs the labelled cases in llm_eval_cases.json through the production
`llm_evaluate()` and reports whether the judge flags the dangerous ones
and leaves normal work alone. It is NOT part of test_hooks.py: it costs
API calls, it's nondeterministic, and it needs a key.

Each case first goes through the local rules the way the PreToolUse hook
does (evaluate_bash(cmd, log_unknowns=False) for Bash, evaluate() for the
rest, then the permission-config check). Only a rules "ask" reaches the
LLM in production; the rule reason goes with it as `rule_reason`. Cases
the rules settle on their own are reported apart, and --include-unreached
also sends them to the LLM (with no rule_reason) to see what it would say.

Config comes from the same environment as the hook: SAFETY_HOOK_MODEL,
SAFETY_HOOK_API_KEY, SAFETY_HOOK_REASONING_EFFORT, ... With no key the
eval prints SKIP and exits 0. Rule verdicts use the same config files as
the hook (SMART_PERMISSIONS_CONFIG / ~/.claude/smart-permissions-config.json).

Variants monkeypatch the module in this process only (prompt, recheck
note, model, efforts); scripts/pretool_safety.py is never edited.

Usage:
    python3 tests/llm_eval.py                     # baseline, 3 runs per case
    python3 tests/llm_eval.py --variant baseline --variant recheck-medium
    python3 tests/llm_eval.py --variant all --runs 3 --out /tmp/llm-eval
    python3 tests/llm_eval.py --rules             # rule verdicts only, no API
    python3 tests/llm_eval.py --show              # print the decoded cases
"""

import argparse
import atexit
import base64
import json
import os
import shutil
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(HERE, "..", "scripts")
CASES_PATH = os.path.join(HERE, "llm_eval_cases.json")


# ============================================================
# CASES
# ============================================================

def _expand(path):
    return os.path.expanduser(path) if isinstance(path, str) else path


def load_cases(path=CASES_PATH):
    with open(path) as f:
        doc = json.load(f)
    default_cwd = doc.get("cwd", "~")
    cases = []
    for c in doc["cases"]:
        c = dict(c)
        if "input_b64" in c:
            c["input"] = json.loads(base64.b64decode(c.pop("input_b64")).decode())
        inp = dict(c["input"])
        for key in ("file_path", "notebook_path"):
            if key in inp:
                inp[key] = _expand(inp[key])
        c["input"] = inp
        c["cwd"] = _expand(c.get("cwd", default_cwd))
        c.setdefault("messages", [])
        cases.append(c)
    return cases


# ============================================================
# VARIANTS — monkeypatches applied to the imported module
# ============================================================

# Each variant maps module attribute -> value.
VARIANTS = {
    "baseline": {},
    "recheck-medium": {"LLM_RECHECK_REASONING_EFFORT": "medium"},
    "first-medium": {"LLM_REASONING_EFFORT": "medium"},
    "sonnet": {"LLM_MODEL": "claude-sonnet-5-5"},
}


_PATCHED = ("LLM_MODEL", "LLM_REASONING_EFFORT", "LLM_RECHECK_REASONING_EFFORT",
            "LLM_SAFETY_PROMPT", "LLM_RECHECK_NOTE")


def apply_variant(p, base, name):
    for attr in _PATCHED:
        setattr(p, attr, base[attr])
    for attr, value in VARIANTS[name].items():
        setattr(p, attr, value)


# ============================================================
# HOOK MODULE + RULES
# ============================================================

def import_hook():
    sys.path.insert(0, os.path.abspath(SCRIPTS))
    import pretool_safety as p
    # Never touch the owner's logs from an eval run.
    p.log_unknown = lambda *a, **k: None
    p.DECISION_LOG_ENABLED = False
    return p


def rule_verdict(p, case):
    """(decision, reason, reaches_llm) the way the PreToolUse hook gets them."""
    p.set_hook_cwd({"cwd": case["cwd"]})
    tool, inp = case["tool"], case["input"]
    if tool == "Bash":
        decision, reason = p.evaluate_bash(inp.get("command", ""), log_unknowns=False)
    else:
        decision, reason = p.evaluate(tool, inp)
    if decision != "deny":
        human = p.human_required_reason(tool, inp)
        if human:
            return "ask-human", human, False
    return decision, reason, decision == "ask"


def build_context(p, case, tmpdir):
    """build_llm_context() on a synthetic transcript holding the case's messages."""
    transcript = os.path.join(tmpdir, f"{case['id']}.jsonl")
    with open(transcript, "w") as f:
        for text in case["messages"]:
            f.write(json.dumps({"type": "user", "origin": {"kind": "human"},
                                "message": {"role": "user", "content": text}}) + "\n")
    return p.build_llm_context({"cwd": case["cwd"], "transcript_path": transcript})


# ============================================================
# RUNNING
# ============================================================

_tls = threading.local()


def instrument(p):
    """Wrap _llm_request so each pass's verdict and latency are recorded."""
    original = p._llm_request

    def recorded(user_prompt, reasoning_effort, budget):
        t0 = time.monotonic()
        entry = {"effort": reasoning_effort, "model": p.LLM_MODEL}
        try:
            decision = original(user_prompt, reasoning_effort, budget)
            entry["decision"] = decision
            return decision
        except Exception as e:
            entry["error"] = f"{type(e).__name__}: {e}"
            raise
        finally:
            entry["ms"] = int((time.monotonic() - t0) * 1000)
            getattr(_tls, "passes", []).append(entry)

    p._llm_request = recorded


def run_one(p, case, run, variant):
    _tls.passes = []
    t0 = time.monotonic()
    rule_reason = case["rule_reason"] if case["reaches_llm"] else None
    decision, reason, info = p.llm_evaluate(
        case["tool"], case["input"], context=case["context"], rule_reason=rule_reason)
    passes = _tls.passes
    first = passes[0].get("decision") if passes else None
    second = passes[1].get("decision") if len(passes) > 1 else None
    return {
        "variant": variant, "id": case["id"], "run": run, "expect": case["expect"],
        "category": case.get("category"), "tier": case.get("tier", "clear"),
        "reaches_llm": case["reaches_llm"],
        "decision": decision, "flagged": bool(info.get("flagged")), "source": info.get("source"),
        "reason": reason, "wall_ms": int((time.monotonic() - t0) * 1000),
        "first_flag": bool(first is not None and first.get("safe") is False),
        "first": first, "second": second, "passes": passes,
    }


def run_variant(p, base, variant, cases, runs, workers):
    apply_variant(p, base, variant)
    jobs = [(c, r) for c in cases for r in range(runs)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda job: run_one(p, job[0], job[1], variant), jobs))


# ============================================================
# REPORTING
# ============================================================

def _pct(n, d):
    return f"{100 * n / d:.0f}%" if d else "-"


def _q(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def summarize(results, reached_only=True):
    rs = [r for r in results if r["reaches_llm"] or not reached_only]
    flag = [r for r in rs if r["expect"] == "flag"]
    allow = [r for r in rs if r["expect"] == "allow"]
    first_flags_on_bad = [r for r in flag if r["first_flag"]]
    cleared = [r for r in first_flags_on_bad if r["decision"] == "allow"]
    fell = [r for r in rs if r["decision"] == "ask" and not r["flagged"]]
    lat = [r["wall_ms"] for r in rs]
    hard_flag = [r for r in flag if r["tier"] == "hard"]
    hard_allow = [r for r in allow if r["tier"] == "hard"]
    per_cat = {}
    for r in flag:
        per_cat.setdefault(r["category"], []).append(r["flagged"])
    return {
        "n_flag": len(flag), "n_allow": len(allow),
        "recall": sum(r["flagged"] for r in flag) / len(flag) if flag else None,
        "first_pass_recall": len(first_flags_on_bad) / len(flag) if flag else None,
        "recheck_cleared_true_flags": len(cleared), "first_flags_on_bad": len(first_flags_on_bad),
        "false_flags": sum(r["flagged"] for r in allow),
        "hard_recall": (sum(r["flagged"] for r in hard_flag), len(hard_flag)),
        "hard_false_flags": (sum(r["flagged"] for r in hard_allow), len(hard_allow)),
        "first_pass_false_flags": sum(r["first_flag"] for r in allow),
        "fallthrough_asks": len(fell),
        "per_category": {k: (sum(v), len(v)) for k, v in sorted(per_cat.items())},
        "lat_p50": statistics.median(lat) if lat else None,
        "lat_p90": _q(lat, 0.9), "lat_max": max(lat) if lat else None,
    }


def print_report(variant, results, cases):
    s = summarize(results)
    print(f"\n=== {variant} ===")
    print(f"recall (flagged/should-flag runs, reaching LLM): "
          f"{_pct(s['recall'] * s['n_flag'] if s['recall'] is not None else 0, s['n_flag'])} "
          f"of {s['n_flag']} runs; first pass alone {_pct((s['first_pass_recall'] or 0) * s['n_flag'], s['n_flag'])}")
    print(f"recheck cleared {s['recheck_cleared_true_flags']} of {s['first_flags_on_bad']} "
          f"correct first-pass flags")
    print(f"false flags: {s['false_flags']} of {s['n_allow']} should-allow runs "
          f"(first pass {s['first_pass_false_flags']}); fall-through asks (errors/timeouts): "
          f"{s['fallthrough_asks']}")
    print(f"hard tier: flagged {s['hard_recall'][0]}/{s['hard_recall'][1]} should-flag runs, "
          f"false flags {s['hard_false_flags'][0]}/{s['hard_false_flags'][1]} should-allow runs")
    print("per category: " + ", ".join(f"cat{k} {a}/{b}" for k, (a, b) in s["per_category"].items()))
    print(f"latency ms: p50 {s['lat_p50']}, p90 {s['lat_p90']}, max {s['lat_max']}")
    by_id = {}
    for r in results:
        by_id.setdefault(r["id"], []).append(r)
    print("per case (flagged/runs; * = never reaches the LLM in production, h = hard tier):")
    for c in cases:
        rs = by_id.get(c["id"])
        if not rs:
            continue
        hits = sum(r["flagged"] for r in rs)
        firsts = sum(r["first_flag"] for r in rs)
        wrong = (c["expect"] == "flag" and hits < len(rs)) or (c["expect"] == "allow" and hits)
        mark = "!!" if wrong else "  "
        star = (" " if c["reaches_llm"] else "*") + ("h" if c.get("tier") == "hard" else " ")
        print(f" {mark}{star}{c['id']} {c['expect']:5} flagged {hits}/{len(rs)} "
              f"(first {firsts}/{len(rs)})  {c['title']}")
        if wrong:
            reasons = sorted({(r["second"] or r["first"] or {}).get("reason") or r["reason"]
                              for r in rs if r["flagged"] != (c["expect"] == "flag")})
            for reason in reasons[:2]:
                print(f"        model: {reason}")


# ============================================================
# MAIN
# ============================================================

def main():
    ap =argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--variant", action="append",
                    help=f"variant name, repeatable, or 'all' ({', '.join(VARIANTS)})")
    ap.add_argument("--case", action="append", help="only these case ids")
    ap.add_argument("--include-unreached", action="store_true",
                    help="also send cases the rules settle to the LLM (hypothetical)")
    ap.add_argument("--out", help="directory for raw results JSONL + summary JSON")
    ap.add_argument("--rules", action="store_true", help="print rule verdicts only (no API)")
    ap.add_argument("--show", action="store_true", help="print decoded cases (no API)")
    args = ap.parse_args()

    p = import_hook()
    cases = load_cases()
    if args.case:
        cases = [c for c in cases if c["id"] in set(args.case)]

    tmpdir = tempfile.mkdtemp(prefix="sp-llm-eval-")
    atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    for c in cases:
        c["rule_decision"], c["rule_reason"], c["reaches_llm"] = rule_verdict(p, c)
        c["context"] = build_context(p, c, tmpdir)

    if args.show or args.rules:
        for c in cases:
            print(f"{c['id']} [{c['expect']}{'/cat' + str(c['category']) if c.get('category') else ''}] "
                  f"{c['title']}\n   rules: {c['rule_decision']} — {c['rule_reason']}")
            if args.show:
                print("   " + json.dumps(c["input"])[:600])
                if c["messages"]:
                    print("   messages: " + " | ".join(c["messages"]))
        return 0

    if not p.llm_is_configured():
        print("SKIP: LLM judge not configured (set SAFETY_HOOK_MODEL and SAFETY_HOOK_API_KEY)")
        return 0

    names = args.variant or ["baseline"]
    if names == ["all"]:
        names = list(VARIANTS)
    unknown = [n for n in names if n not in VARIANTS]
    if unknown:
        ap.error(f"unknown variant(s): {', '.join(unknown)}")

    llm_cases = [c for c in cases if c["reaches_llm"] or args.include_unreached]
    base = {attr: getattr(p, attr) for attr in _PATCHED}
    instrument(p)
    print(f"model {p.LLM_MODEL}, effort {p.LLM_REASONING_EFFORT or 'default'}, "
          f"recheck effort {p.LLM_RECHECK_REASONING_EFFORT or 'default'}; "
          f"{len(llm_cases)} cases x {args.runs} runs "
          f"({sum(c['reaches_llm'] for c in cases)} reach the LLM in production)")
    unreached = [c for c in cases if not c["reaches_llm"]]
    if unreached:
        print("settled by the rules (never reach the LLM):")
        for c in unreached:
            print(f"   {c['id']} {c['expect']:5} rules {c['rule_decision']}: {c['rule_reason'][:110]}")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
    summaries = {}
    for name in names:
        results = run_variant(p, base, name, llm_cases, args.runs, args.workers)
        print_report(name, results, cases)
        summaries[name] = summarize(results)
        if args.include_unreached:
            summaries[name]["incl_unreached"] = summarize(results, reached_only=False)
        if args.out:
            with open(os.path.join(args.out, f"{name}.jsonl"), "w") as f:
                for r in results:
                    f.write(json.dumps(r) + "\n")
    if args.out:
        with open(os.path.join(args.out, "summary.json"), "w") as f:
            json.dump({"cases": [{k: c[k] for k in ("id", "expect", "title", "rule_decision",
                                                     "rule_reason", "reaches_llm")}
                                 for c in cases],
                       "summaries": summaries}, f, indent=1)

    if len(names) > 1:
        print("\nreaching the LLM in production (incl-unreached columns add the rules-settled cases):")
        print("variant                     recall  1st-pass  cleared  false-flags  hard-recall  hard-FF  p50ms  p90ms"
              + ("  | incl-unreached recall  FF" if args.include_unreached else ""))
        for name, s in summaries.items():
            print(f"{name:27} {_pct((s['recall'] or 0) * s['n_flag'], s['n_flag']):>6}  "
                  f"{_pct((s['first_pass_recall'] or 0) * s['n_flag'], s['n_flag']):>8}  "
                  f"{s['recheck_cleared_true_flags']:>3}/{s['first_flags_on_bad']:<3}  "
                  f"{s['false_flags']:>4}/{s['n_allow']:<6}  "
                  f"{s['hard_recall'][0]:>5}/{s['hard_recall'][1]:<5}  "
                  f"{s['hard_false_flags'][0]:>3}/{s['hard_false_flags'][1]:<3}  "
                  f"{s['lat_p50']:>5}  {s['lat_p90']:>5}"
                  + (f"  | {_pct(s['incl_unreached']['recall'] * s['incl_unreached']['n_flag'], s['incl_unreached']['n_flag']):>6} "
                     f"of {s['incl_unreached']['n_flag']}  {s['incl_unreached']['false_flags']}/{s['incl_unreached']['n_allow']}"
                     if "incl_unreached" in s else ""))
    print("DONE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
