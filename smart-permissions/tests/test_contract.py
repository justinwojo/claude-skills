#!/usr/bin/env python3
"""
Hook-contract tests for smart-permissions: what the two hooks do as seen
from outside, at the two real entry points.

Each case runs a hook as a subprocess exactly as hooks/hooks.json invokes it
(`/bin/sh -c` on the command line it declares, with CLAUDE_PLUGIN_ROOT set and
`python3` on PATH), in a sandbox with its own HOME (so its own config, decision
log, flag store and hold store), against a deterministic fake judge: a local
HTTP server speaking the OpenAI-compatible or Anthropic wire format that
returns scripted verdicts and records every request.

For every hook run it captures:
  - the exit status, stdout (parsed JSON or silence) and stderr;
  - every judge request: wire format, model, effort, a hash of the system
    prompt and the full user message (the evidence the judge saw);
  - the decision-log records the run appended, in order (timings dropped);
  - the files the run created, removed or changed under ~/.claude, the
    flag store and the hold store after it;
and normalises sandbox paths, ports, timings and timestamps.

Two layers of assertion:
  1. hand-written expectations per step (decision, judge calls, log events),
     which say what the case is about;
  2. a golden snapshot (tests/contract_golden.json) of everything captured,
     so a restructuring can be shown to change nothing observable.

Run:
    python3 tests/test_contract.py             # all cases
    python3 tests/test_contract.py -k hold     # cases whose id contains "hold"
    python3 tests/test_contract.py --update    # rewrite the golden snapshot
                                               # (review the diff before committing)
    SP_CONTRACT_PYTHON=/usr/bin/python3 python3 tests/test_contract.py
                                               # run the hooks on another Python

Exit code 0 = all checks pass, 1 = failures. Stdlib only.

Dangerous payloads are base64-encoded here, and replaced by a <payload:…>
placeholder in the snapshot, so neither file holds them in plain text.
"""

import base64
import datetime
import difflib
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS_JSON = os.path.join(PLUGIN_ROOT, 'hooks', 'hooks.json')
GOLDEN_PATH = os.path.join(PLUGIN_ROOT, 'tests', 'contract_golden.json')
# Every log record carries the release version. The snapshot holds '<version>'
# instead, so a version bump alone is no diff (a record with any other version is).
with open(os.path.join(os.path.dirname(PLUGIN_ROOT), '.claude-plugin', 'marketplace.json')) as f:
    RELEASE_VERSION = json.load(f)['metadata']['version']

passed = 0
failed = 0
errors = []


def check(name, actual, expected):
    """Assert a test result (test_hooks.py's style)."""
    global passed, failed
    if actual == expected:
        passed += 1
        print(f'  PASS  {name}')
    else:
        failed += 1
        msg = f'  FAIL  {name}: expected {expected!r}, got {actual!r}'
        print(msg)
        errors.append(msg)


def d(s):
    return base64.b64decode(s).decode()


# Dangerous strings, base64 so this file never holds them in plain text.
PAYLOADS = {
    'sudo': d('c3VkbyBhcHQgaW5zdGFsbCBmb28='),
    'rmrf-home': d('cm0gLXJmIH4='),
    'steer': d('WD0kKGNhdCBmKTsgcm0gLXJmIH4vY2FjaGUvJFg='),
    'rmrf': d('cm0gLXJm'),
}


# =====================================================================
#  How hooks.json invokes the hooks
# =====================================================================

def _hook_commands():
    with open(HOOKS_JSON) as f:
        hooks = json.load(f)['hooks']
    return {
        'pretool': hooks['PreToolUse'][0]['hooks'][0]['command'],
        'learner': hooks['PermissionRequest'][0]['hooks'][0]['command'],
    }


HOOK_COMMANDS = _hook_commands()

def _run_parent():
    """Where the sandboxes live: SP_CONTRACT_ROOT, else ~/.cache. Not the
    system temp folder: the rules treat /tmp and /var/folders as safe write
    paths, so a HOME inside one would settle calls by the wrong rule (a
    project write as "Safe path: /var/folders/" instead of "~/Dev/"). The
    snapshot assumes this; a temp-dir fallback shows up as golden diffs."""
    for parent in (os.environ.get('SP_CONTRACT_ROOT'), os.path.join(os.path.expanduser('~'), '.cache')):
        if parent:
            try:
                os.makedirs(parent, exist_ok=True)
                return parent
            except OSError:
                pass
    return None


# `python3` on the hooks' PATH is the interpreter running this suite (or
# SP_CONTRACT_PYTHON), through a one-entry bin dir in front of PATH.
RUN_ROOT = tempfile.mkdtemp(prefix='sp-contract-', dir=_run_parent())
_SHIM_BIN = os.path.join(RUN_ROOT, 'bin')
os.makedirs(_SHIM_BIN)
HOOK_PYTHON = os.environ.get('SP_CONTRACT_PYTHON') or sys.executable
os.symlink(HOOK_PYTHON, os.path.join(_SHIM_BIN, 'python3'))

# The learner's prompt timeout is at least a minute. To run its timeout path
# in milliseconds without touching the hook, a sitecustomize (only on the
# runs that ask for it) records each time.sleep and sleeps at most 50 ms.
_SITE_DIR = os.path.join(RUN_ROOT, 'site')
os.makedirs(_SITE_DIR)
with open(os.path.join(_SITE_DIR, 'sitecustomize.py'), 'w') as _f:
    _f.write(
        "import os, time\n"
        "_log = os.environ.get('SP_CONTRACT_SLEEP_LOG')\n"
        "if _log:\n"
        "    _real = time.sleep\n"
        "    def _sleep(s):\n"
        "        with open(_log, 'a') as f:\n"
        "            f.write(repr(float(s)) + '\\n')\n"
        "        _real(min(float(s), 0.05))\n"
        "    time.sleep = _sleep\n")


# =====================================================================
#  Fake judge
# =====================================================================

class FakeJudge:
    """A local HTTP judge. `script(responses)` sets what the next requests
    get, in order (the last one is not repeated: a request past the script
    gets HTTP 500 and is marked unexpected). A response is one of:
      {'safe': ...}         a verdict, wrapped in the wire format's envelope
      {'_status': 500}      an HTTP error
      {'_body': '...'}      a raw 200 body (malformed replies)
      {'_refusal': True}    a refusal in the wire format's terms
    """

    def __init__(self):
        judge = self
        self.lock = threading.Lock()
        self.responses = []
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get('Content-Length') or 0))
                try:
                    data = json.loads(body.decode())
                except ValueError:
                    data = {'_unparsed': body.decode('utf-8', 'replace')}
                with judge.lock:
                    resp = judge.responses.pop(0) if judge.responses else None
                    judge.requests.append({'path': self.path, 'headers': dict(self.headers),
                                           'body': data, 'unexpected': resp is None})
                anthropic = self.path.endswith('/messages')
                if resp is None:
                    resp = {'_status': 500}
                if '_status' in resp:
                    self._send(resp['_status'], b'{"error": "scripted"}')
                elif '_body' in resp:
                    self._send(200, resp['_body'].encode())
                elif resp.get('_refusal'):
                    env = ({'content': [], 'stop_reason': 'refusal'} if anthropic else
                           {'choices': [{'message': {'content': None, 'refusal': 'no'}}]})
                    self._send(200, json.dumps(env).encode())
                else:
                    text = json.dumps(resp)
                    env = ({'content': [{'type': 'text', 'text': text}], 'stop_reason': 'end_turn'}
                           if anthropic else {'choices': [{'message': {'content': text}}]})
                    self._send(200, json.dumps(env).encode())

            def _send(self, code, payload):
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def script(self, responses):
        with self.lock:
            self.responses = list(responses or [])
            self.requests = []

    def take(self):
        with self.lock:
            reqs, self.requests = self.requests, []
            left, self.responses = self.responses, []
        return reqs, left


JUDGE = FakeJudge()


def _closed_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


CLOSED_PORT = _closed_port()

FLAG = {'safe': False, 'category': 1, 'reason': 'deletes runner checkouts with unpushed commits',
        'resolver': 'agent', 'question': 'Are those commits pushed anywhere?', 'confident': True}
SAFE = {'safe': True, 'reason': 'ok'}
SURE = {'safe': True, 'confident': True, 'reason': 'ok'}


# =====================================================================
#  Sandbox and one hook run
# =====================================================================

def iso_ago(seconds):
    """A transcript timestamp `seconds` ago, as Claude Code writes them."""
    t = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=seconds)
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + f'{t.microsecond // 1000:03d}Z'


class Sandbox:
    """A HOME with ~/.claude, a project at ~/Dev/app (the cwd), a session
    transcript, and optional user config and project files."""

    def __init__(self, config=None, files=None):
        self.root = tempfile.mkdtemp(prefix='spc-', dir=RUN_ROOT)
        self.real = os.path.realpath(self.root)
        self.home = os.path.join(self.root, 'home')
        self.claude = os.path.join(self.home, '.claude')
        self.work = os.path.join(self.home, 'Dev', 'app')
        self.tmp = os.path.join(self.root, 'tmp')
        for p in (self.claude, self.work, self.tmp, os.path.join(self.root, 'docker')):
            os.makedirs(p, exist_ok=True)
        self.config = os.path.join(self.claude, 'smart-permissions-config.json')
        if config is not None:
            with open(self.config, 'w') as f:
                json.dump(config, f)
        self.transcript = os.path.join(self.claude, 'projects', '-app', 'sess-1.jsonl')
        os.makedirs(os.path.dirname(self.transcript))
        self.write_transcript([{'type': 'user', 'origin': {'kind': 'human'}, 'timestamp': iso_ago(600),
                                'message': {'role': 'user', 'content': 'Wrap up the benchmark in this project.'}}])
        for name, (text, mode) in (files or {}).items():
            path = os.path.join(self.work, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'w') as f:
                f.write(text)
            os.chmod(path, mode)

    def write_transcript(self, records, path=None):
        with open(path or self.transcript, 'w') as f:
            for r in records:
                f.write(json.dumps(r) + '\n')

    def say(self, text):
        """The agent writes `text` to its transcript."""
        with open(self.transcript, 'a') as f:
            f.write(json.dumps({'type': 'assistant', 'timestamp': iso_ago(0), 'message': {
                'role': 'assistant', 'content': [{'type': 'text', 'text': text}]}}) + '\n')

    def call(self, tool, tool_input, session=True, **extra):
        payload = {'hook_event_name': 'PreToolUse', 'tool_name': tool, 'tool_input': tool_input,
                   'cwd': self.work, 'transcript_path': self.transcript}
        if session:
            payload['session_id'] = 'sess-1'
        payload.update(extra)
        return payload

    def bash(self, command, **kw):
        return self.call('Bash', {'command': command}, **kw)

    # ---- state ----
    def state(self):
        """{path under ~/.claude: content hash}; hold files (named by a hash
        over the session and the sandbox cwd) as <hold>."""
        out = {}
        for base, dirs, names in os.walk(self.claude):
            rel_base = os.path.relpath(base, self.claude)
            if rel_base.split(os.sep)[0] == 'projects' or '__pycache__' in rel_base.split(os.sep):
                continue  # bytecode caches (a manual install's) are named per interpreter
            for n in names:
                p = os.path.join(base, n)
                rel = re.sub(r'[0-9a-f]{64}', '<hold>', os.path.relpath(p, self.claude))
                try:
                    with open(p, 'rb') as f:
                        out[rel] = hashlib.sha1(f.read()).hexdigest()
                except OSError:
                    out[rel] = 'unreadable'
        return out

    def log_records(self):
        recs = []
        try:
            with open(os.path.join(self.claude, 'hooks', 'smart-permissions-decisions.jsonl')) as f:
                recs = [json.loads(line) for line in f if line.strip()]
        except OSError:
            pass
        return recs

    def unknown_lines(self):
        try:
            with open(os.path.join(self.claude, 'hooks', 'unknown-permissions.log')) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def flags(self):
        try:
            with open(os.path.join(self.claude, 'hooks', 'smart-permissions-llm-flags.json')) as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def holds(self):
        d_ = os.path.join(self.claude, 'hooks', 'smart-permissions-holds')
        try:
            names = sorted(os.listdir(d_))
        except OSError:
            return None
        out = []
        for n in names:
            entry = {'file': '<hold>' + n[64:] if re.match(r'[0-9a-f]{64}', n) else n}
            if n.endswith('.json'):
                try:
                    with open(os.path.join(d_, n)) as f:
                        rec = json.load(f)
                    entry.update({k: rec.get(k) for k in ('state', 'tool', 'session', 'reason', 'question', 'v')})
                    entry['done'] = 'done' in rec
                except (OSError, ValueError):
                    entry['unreadable'] = True
            out.append(entry)
        return out


def call_key(tool, tool_input):
    canonical = json.dumps(tool_input, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256((tool + '\0' + canonical).encode('utf-8', 'replace')).hexdigest()


class Normaliser:
    def __init__(self, sb):
        self.subs = []
        for path, tag in ((sb.real, '<SB>'), (sb.root, '<SB>'),
                          (os.path.realpath(PLUGIN_ROOT), '<PLUGIN>'), (PLUGIN_ROOT, '<PLUGIN>'),
                          (os.path.realpath(RUN_ROOT), '<RUN>'), (RUN_ROOT, '<RUN>')):
            self.subs.append((path, tag))
            self.subs.append((path.replace('\\', '\\\\'), tag))
        for name, text in PAYLOADS.items():
            self.subs.append((text, f'<payload:{name}>'))
        self.subs.sort(key=lambda s: -len(s[0]))

    def text(self, s):
        if not isinstance(s, str):
            return s
        for old, new in self.subs:
            s = s.replace(old, new)
        s = re.sub(r'127\.0\.0\.1:\d+', '127.0.0.1:<port>', s)
        s = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?', '<TS>', s)
        s = re.sub(r'\b\d+(?:\.\d+)?s\b', '<N>s', s)
        s = re.sub(r'\[Errno -?\d+\]', '[Errno N]', s)
        s = re.sub(r'\b\d+ (min|minutes|seconds|s|h|hours) ago\b', r'<N> \1 ago', s)
        s = re.sub(r'\b\d{2}-\d{2} \d{2}:\d{2}\b', '<MM-DD HH:MM>', s)  # provenance call times
        return s

    def obj(self, o):
        if isinstance(o, str):
            return self.text(o)
        if isinstance(o, list):
            return [self.obj(x) for x in o]
        if isinstance(o, dict):
            return {self.text(k): self.obj(v) for k, v in o.items()}
        return o


def run(sb, hook, payload=None, raw=None, judge=None, provider='openai', env=None,
        attended=False, sleep_patch=False, judge_url=None):
    """Run one hook as hooks.json does; return the normalised snapshot."""
    e = {
        'HOME': sb.home,
        'PATH': _SHIM_BIN + os.pathsep + os.environ.get('PATH', '/usr/bin:/bin'),
        'TMPDIR': sb.tmp + os.sep,
        'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'CLAUDE_PLUGIN_ROOT': PLUGIN_ROOT,
        'CLAUDE_CODE_SESSION_ATTENDED': '1' if attended else '0',
        'CLAUDE_CODE_ENTRYPOINT': 'cli',
        'no_proxy': '*', 'NO_PROXY': '*',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        'DOCKER_CONFIG': os.path.join(sb.root, 'docker'),
    }
    if judge is not None:
        if provider == 'anthropic':
            e.update(SAFETY_HOOK_API_URL=judge_url or f'http://127.0.0.1:{JUDGE.port}/v1/messages',
                     SAFETY_HOOK_PROVIDER='anthropic', SAFETY_HOOK_MODEL='claude-mock-1')
        else:
            e.update(SAFETY_HOOK_API_URL=judge_url or f'http://127.0.0.1:{JUDGE.port}/v1/chat/completions',
                     SAFETY_HOOK_MODEL='mock-model')
        e['SAFETY_HOOK_API_KEY'] = 'test-key'
    sleep_log = os.path.join(sb.root, 'sleeps.log')
    if sleep_patch:
        e['PYTHONPATH'] = _SITE_DIR
        e['SP_CONTRACT_SLEEP_LOG'] = sleep_log
        if os.path.exists(sleep_log):
            os.remove(sleep_log)
    e.update(env or {})
    e = {k: v for k, v in e.items() if v is not None}

    before = sb.state()
    nlog = len(sb.log_records())
    nunknown = len(sb.unknown_lines())
    JUDGE.script(judge)
    stdin = raw if raw is not None else json.dumps(payload)
    t0 = time.monotonic()
    r = subprocess.run(['/bin/sh', '-c', HOOK_COMMANDS[hook]], input=stdin, env=e, cwd=sb.work,
                       capture_output=True, text=True, timeout=120)
    wall = time.monotonic() - t0
    reqs, unused = JUDGE.take()
    after = sb.state()
    n = Normaliser(sb)

    out = r.stdout.strip()
    try:
        stdout = json.loads(out) if out else None
    except ValueError:
        stdout = {'_not_json': out}
    hso = (stdout or {}).get('hookSpecificOutput', {}) if isinstance(stdout, dict) else {}
    decision = hso.get('permissionDecision') or (hso.get('decision') or {}).get('behavior')

    judge_calls = []
    for q in reqs:
        body = q['body']
        h = {k.lower(): v for k, v in q['headers'].items()}
        if q['path'].endswith('/messages'):
            system, user = body.get('system'), body['messages'][0]['content']
            effort = (body.get('output_config') or {}).get('effort')
            fmt = 'anthropic'
        else:
            system, user = body['messages'][0]['content'], body['messages'][1]['content']
            effort = body.get('reasoning_effort')
            fmt = 'openai'
        judge_calls.append({
            'format': fmt, 'path': q['path'], 'model': body.get('model'), 'effort': effort,
            'auth': ('bearer' if h.get('authorization') == 'Bearer test-key' else
                     'x-api-key' if h.get('x-api-key') == 'test-key' else None),
            'system_sha256': hashlib.sha256((system or '').encode()).hexdigest()[:16],
            'user': user, 'unexpected': q['unexpected'],
        })

    key = None
    if isinstance(payload, dict) and isinstance(payload.get('tool_input'), dict):
        key = call_key(payload.get('tool_name', ''), payload['tool_input'])
    flags = sb.flags()
    if flags is not None:
        flags = {('<this-call>' if k == key else '<other-call>'): (v.get('reason') if isinstance(v, dict) else v)
                 for k, v in flags.items()}

    log = []
    for rec in sb.log_records()[nlog:]:
        rec = dict(rec)
        for k in ('ts', 'duration_ms'):
            rec.pop(k, None)
        if 'llm_ms' in rec:
            rec['llm_ms'] = '<ms>'
        if rec.get('v') == RELEASE_VERSION:
            rec['v'] = '<version>'
        if rec.get('input_len') == len(rec.get('input') or '') and not rec.get('truncated'):
            rec['input_len'] = '=len(input)'  # the sandbox path length is not the contract
        log.append(rec)

    sleeps = None
    if sleep_patch:
        try:
            with open(sleep_log) as f:
                sleeps = [round(float(x)) for x in f if x.strip() and float(x) >= 1]
        except OSError:
            sleeps = []

    snap = {
        'hook': hook,
        'rc': r.returncode,
        'stdout': stdout,
        'stderr': r.stderr.splitlines(),
        'judge': judge_calls,
        'judge_unused_responses': len(unused),
        'log': log,
        'unknown_log': [re.sub(r'^\S+ \S+  ', '', line) for line in sb.unknown_lines()[nunknown:]],
        'files': {'created': sorted(set(after) - set(before)),
                  'removed': sorted(set(before) - set(after)),
                  'changed': sorted(k for k in set(after) & set(before) if after[k] != before[k])},
        'flags': flags,
        'holds': sb.holds(),
    }
    if sleeps is not None:
        snap['sleeps'] = sleeps
    snap = n.obj(snap)
    snap['_decision'] = decision  # convenience for expectations; not in the golden
    snap['_wall'] = wall
    return snap


# =====================================================================
#  Expectations
# =====================================================================

def expect(case, step_no, snap, out='?', judge=None, events=None, rc=0, stderr='', reason_has=None,
           judge_has=None, judge_lacks=None, flags=None, holds=None, sleeps=None):
    """Hand-written intent for one step. out: 'allow'|'deny'|'ask'|None
    (silence: Claude Code's own prompt). events: [(hook, decision, source)]
    or [(hook, decision, source, hold)] of the log records this run wrote."""
    tag = f'{case}#{step_no} {snap["hook"]}'
    check(f'{tag}: exit status', snap['rc'], rc)
    if out != '?':
        check(f'{tag}: output', snap['_decision'] if snap['stdout'] is not None else None, out)
        if out is None:
            check(f'{tag}: silent', snap['stdout'], None)
    if stderr is not None:
        if isinstance(stderr, str) and stderr.startswith('re:'):
            check(f'{tag}: stderr matches {stderr[3:]!r}',
                  bool(re.search(stderr[3:], '\n'.join(snap['stderr']))), True)
        else:
            check(f'{tag}: stderr', '\n'.join(snap['stderr']), stderr)
    if judge is not None:
        check(f'{tag}: judge calls', len(snap['judge']), judge)
        check(f'{tag}: no unexpected judge call', any(j['unexpected'] for j in snap['judge']), False)
    if events is not None:
        got = [tuple([r.get('hook'), r.get('decision'), r.get('source')] + ([r.get('hold')] if len(e) > 3 else []))
               for r, e in zip(snap['log'], events + [()] * len(snap['log']))]
        check(f'{tag}: log events', got, [tuple(e) for e in events])
    if reason_has:
        hso = (snap['stdout'] or {}).get('hookSpecificOutput', {})
        text = hso.get('permissionDecisionReason') or (hso.get('decision') or {}).get('message') or ''
        for s in ([reason_has] if isinstance(reason_has, str) else reason_has):
            check(f'{tag}: reason has {s[:50]!r}', s in text, True)
    for s in ([judge_has] if isinstance(judge_has, str) else judge_has or []):
        check(f'{tag}: judge saw {s[:50]!r}', any(s in j['user'] for j in snap['judge']), True)
    for s in ([judge_lacks] if isinstance(judge_lacks, str) else judge_lacks or []):
        check(f'{tag}: judge did not see {s[:50]!r}', any(s in j['user'] for j in snap['judge']), False)
    if flags is not None:
        check(f'{tag}: flag store', sorted((snap['flags'] or {}).keys()), sorted(flags))
    if holds is not None:
        check(f'{tag}: hold states', [h.get('state') for h in (snap['holds'] or []) if h['file'].endswith('.json')],
              holds)
    if sleeps is not None:
        check(f'{tag}: long sleeps', snap.get('sleeps'), sleeps)


# =====================================================================
#  Cases
# =====================================================================
# Each case returns its list of step snapshots. Keep ids stable: they key
# the golden snapshot.

CASES = []


def case(fn):
    CASES.append(fn)
    return fn


# ---- PreToolUse: rules ------------------------------------------------

@case
def p_rule_allow_bash(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('git status'), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    check(f'{c}: first run bootstraps the user config',
          'smart-permissions-config.json' in s['files']['created'], True)
    return [s]


@case
def p_rule_allow_read(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('Read', {'file_path': os.path.join(sb.work, 'README.md')}))
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_rule_allow_internal_tool(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('Agent', {'prompt': 'x'}))
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_rule_allow_webfetch(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('WebFetch', {'url': 'https://github.com/example-org/x', 'prompt': 'p'}))
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_rule_allow_write_project(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('Write', {'file_path': os.path.join(sb.work, 'out.txt'), 'content': 'x'}))
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_rule_allow_safe_mcp(c):
    sb = Sandbox(config={'safe_mcp_tools': ['mcp__bench__health']})
    s = run(sb, 'pretool', sb.call('mcp__bench__health', {}), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_rule_allow_foreign_cli(c):
    sb = Sandbox()
    s = run(sb, 'pretool', {'tool_name': 'run_terminal_command', 'tool_input': {'command': 'git status'},
                            'cwd': sb.work})
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    check(f'{c}: client tool logged', s['log'][0].get('client_tool') if s['log'] else None, 'run_terminal_command')
    return [s]


@case
def p_rule_deny_dangerous(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash(PAYLOADS['sudo']), judge=[SAFE])
    expect(c, 1, s, out='deny', judge=0, events=[('pretool', 'deny', 'rule')])
    return [s]


@case
def p_rule_deny_protected_delete(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash(PAYLOADS['rmrf-home']), judge=[SAFE])
    expect(c, 1, s, out='deny', judge=0, events=[('pretool', 'deny', 'rule')])
    return [s]


@case
def p_rule_deny_unguarded_steer(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash(PAYLOADS['steer']), judge=[SAFE])
    expect(c, 1, s, out='deny', judge=0, events=[('pretool', 'deny', 'rule')], reason_has='${X:?}')
    return [s]


@case
def p_rule_deny_sensitive_write(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('Write', {'file_path': os.path.join(sb.home, '.ssh', 'id_ed25519'),
                                             'content': 'x'}), judge=[SAFE])
    expect(c, 1, s, out='deny', judge=0, events=[('pretool', 'deny', 'rule')])
    return [s]


# ---- PreToolUse: asks — silent exit vs explicit developer prompt --------

@case
def p_ask_silent_no_judge(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'))
    expect(c, 1, s, out=None, judge=0, events=[('pretool', 'ask', 'llm')])
    check(f'{c}: unknown command logged for review', s['unknown_log'] != [], True)
    return [s]


@case
def p_ask_silent_mcp_no_judge(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('mcp__bench__run', {'command': 'dir C:\\Lab'}))
    expect(c, 1, s, out=None, judge=0, events=[('pretool', 'ask', 'llm')])
    return [s]


@case
def p_ask_explicit_c9_write(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.call('Write', {'file_path': os.path.join(sb.claude, 'settings.json'),
                                             'content': '{}'}), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule')])
    check(f'{c}: C9 is not put in the flag store', s['flags'], None)
    return [s]


@case
def p_ask_explicit_c9_bash(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash("echo '{}' > ~/.claude/settings.json"), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule')])
    return [s]


@case
def p_ask_c9_outranks_ordinary_ask(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash("frobnicate; echo '{}' > ~/.claude/settings.json"), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule')])
    # Inside Bash the permission-config write outranks the earlier unknown
    # command: the rules' own reason is already C9's.
    check(f'{c}: the C9 reason, not the earlier ask', (s['log'][0].get('reason') if s['log'] else None,
                                                     s['unknown_log']),
          ('Bash write to permission-config path', ['command   frobnicate']))
    return [s]


@case
def p_ask_explicit_hold_store_write(c):
    sb = Sandbox()
    store = os.path.join(sb.claude, 'hooks', 'smart-permissions-holds', 'x.json')
    s = run(sb, 'pretool', sb.call('Write', {'file_path': store, 'content': '{}'}), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule')])
    return [s]


# ---- PreToolUse: judge outcomes ---------------------------------------

@case
def p_judge_safe(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')],
           judge_has=['Tool: Bash', 'frobnicate --all', 'Local rules sent this call to you because',
                      'Wrap up the benchmark'])
    return [s]


@case
def p_judge_flag_recheck_clears(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[FLAG, SAFE])
    expect(c, 1, s, out='allow', judge=2, events=[('pretool', 'allow', 'llm-recheck')])
    check(f'{c}: the recheck runs at high effort with the first flag attached',
          (s['judge'][1]['effort'], 'deletes runner checkouts' in s['judge'][1]['user']) if len(s['judge']) > 1
          else None, ('high', True))
    return [s]


@case
def p_judge_flag_confirmed_no_session(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all', session=False), judge=[FLAG, FLAG])
    expect(c, 1, s, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')],
           flags=['<this-call>'], reason_has='deletes runner checkouts')
    check(f'{c}: not held, and why', s['log'][0].get('hold') if s['log'] else None,
          'not held: no session id to bind a hold to')
    return [s]


@case
def p_judge_flag_confirmed_holds_off(c):
    sb = Sandbox(config={'holds': False})
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[FLAG, FLAG])
    expect(c, 1, s, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')], flags=['<this-call>'])
    check(f'{c}: no hold field when holds are off', 'hold' in (s['log'][0] if s['log'] else {}), False)
    return [s]


@case
def p_judge_unavailable_http500(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[{'_status': 500}])
    expect(c, 1, s, out=None, judge=1, events=[('pretool', 'ask', 'llm')], stderr='re:^LLM error: HTTP Error 500')
    return [s]


@case
def p_judge_unavailable_refused(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[],
            judge_url=f'http://127.0.0.1:{CLOSED_PORT}/v1/chat/completions')
    expect(c, 1, s, out=None, judge=0, events=[('pretool', 'ask', 'llm')], stderr='re:^LLM error: ')
    return [s]


@case
def p_judge_malformed_body(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all', session=False), judge=[{'_body': '{"choices": ['}])
    expect(c, 1, s, out='ask', judge=1, events=[('pretool', 'ask', 'llm')], flags=['<this-call>'],
           stderr='re:malformed')
    return [s]


@case
def p_judge_malformed_verdict(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'),
            judge=[{'_body': json.dumps({'choices': [{'message': {'content': '{"safe": "false"}'}}]})}])
    expect(c, 1, s, out='ask', judge=1, events=[('pretool', 'ask', 'llm')], flags=['<this-call>'],
           stderr='re:unparseable')
    return [s]


@case
def p_judge_refusal(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[{'_refusal': True}])
    expect(c, 1, s, out='ask', judge=1, events=[('pretool', 'ask', 'llm')], flags=['<this-call>'],
           stderr='re:refused')
    return [s]


@case
def p_judge_anthropic_wire(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('frobnicate --all'), judge=[SAFE], provider='anthropic')
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')])
    check(f'{c}: Messages API with x-api-key',
          (s['judge'][0]['format'], s['judge'][0]['auth']) if s['judge'] else None, ('anthropic', 'x-api-key'))
    return [s]


# ---- PreToolUse: gates that route a rule allow to the judge -----------

SCRIPTS = {
    'teardown.sh': ('#!/bin/bash\nset -e\naz group delete -n rg-example-dev --yes\n', 0o755),
    'peek.sh': ('#!/bin/sh\nkubectl exec -n prod web-1 -- ls /srv\n', 0o755),
    'peekvar.sh': ('#!/bin/sh\nkubectl exec -n prod "$POD" -- ls /srv\n', 0o755),
    'build.sh': ('#!/bin/sh\nnpm test\n', 0o755),
}


@case
def p_rule_allow_plain_script(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('./build.sh'), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')])
    return [s]


@case
def p_gate_destroy_script_judged(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('./teardown.sh'), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')],
           judge_has=['Runs a local script that deletes', 'az group delete -n rg-example-dev'])
    check(f'{c}: no script text in the log', 'rg-example-dev' in json.dumps(s['log']), False)
    return [s]


@case
def p_gate_destroy_script_no_judge(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('./teardown.sh'))
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'llm')], flags=['<this-call>'])
    return [s]


@case
def p_gate_destroy_script_flagged_not_held(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('./teardown.sh'), judge=[FLAG, FLAG])
    expect(c, 1, s, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')], holds=None)
    check(f'{c}: never held', (s['log'][0].get('hold', '') if s['log'] else '').startswith(
        'not held: it runs a local script that deletes'), True)
    return [s]


@case
def p_gate_remote_script_not_confident(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('sh ./peek.sh'), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=1, events=[('pretool', 'ask', 'llm', 'remote-exec')],
           flags=['<this-call>'], reason_has='kubectl exec in peek.sh')
    return [s]


@case
def p_gate_remote_script_confident(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('sh ./peek.sh'), judge=[SURE])
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')])
    return [s]


@case
def p_gate_remote_gap_no_judge(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'pretool', sb.bash('./peekvar.sh'), judge=[SURE])
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule', 'remote-exec')], flags=['<this-call>'])
    return [s]


@case
def p_gate_remote_exec_user_allowed(c):
    sb = Sandbox(config={'safe_commands': ['kubectl exec *']})
    s = run(sb, 'pretool', sb.bash('kubectl exec app-prod-worker -- ls /app'), judge=[SAFE])
    expect(c, 1, s, out='ask', judge=1, events=[('pretool', 'ask', 'llm', 'remote-exec')],
           reason_has='Remote or production execution (kubectl exec)')
    return [s]


# ---- PreToolUse: MCP --------------------------------------------------

@case
def p_mcp_context_note(c):
    sb = Sandbox(config={'mcp_context': {'mcp__bench__*': 'bench is a disposable test VM; its files are scratch.'}})
    s = run(sb, 'pretool', sb.call('mcp__bench__run', {'command': 'dir C:\\Lab'}), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')],
           judge_has=['mcp_context in their config', 'bench is a disposable test VM'])
    return [s]


def _remote_cleanup_sandbox():
    sb = Sandbox()
    wt = 'C:\\Lab\\proj-wt\\s4'
    add = f"$main = 'C:\\Lab\\proj'; git -C $main worktree add --detach '{wt}' FETCH_HEAD"
    ps = (f"& {{ $main = 'C:\\Lab\\proj'; $wt = '{wt}'; git -C $main worktree remove --force $wt; "
          "if (Test-Path $wt) { Remove-Item -Recurse -Force $wt } }")

    def use(tid, name, inp, secs):
        return {'type': 'assistant', 'timestamp': iso_ago(secs), 'sessionId': 'sess-1',
                'message': {'role': 'assistant', 'content': [
                    {'type': 'tool_use', 'id': tid, 'name': name, 'input': inp}]}}

    def result(tid, secs, error=False):
        return {'type': 'user', 'timestamp': iso_ago(secs), 'sessionId': 'sess-1',
                'message': {'role': 'user', 'content': [
                    {'type': 'tool_result', 'tool_use_id': tid, 'content': 'ok', 'is_error': error}]}}
    sb.write_transcript([
        {'type': 'user', 'origin': {'kind': 'human'}, 'timestamp': iso_ago(7200),
         'message': {'role': 'user', 'content': 'Run the s4 tests on the bench, then clean up.'}},
        use('m1', 'mcp__bench__run', {'command': add, 'timeout_s': 300}, 5400), result('m1', 5400),
        use('m2', 'mcp__bench__job_start', {'command': 'dotnet test', 'cwd': 'c:/lab/PROJ-WT/S4/'}, 3600),
        result('m2', 3600, error=True),
        use('now', 'mcp__bench__run', {'command': ps}, 0),
    ])
    return sb, sb.call('mcp__bench__run', {'command': ps}, tool_use_id='later')


@case
def p_mcp_remote_cleanup_provenance(c):
    sb, payload = _remote_cleanup_sandbox()
    s = run(sb, 'pretool', payload, judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('pretool', 'allow', 'llm')],
           judge_has=["This session's earlier calls to the MCP server bench", 'evidence, not authorization',
                      'worktree add --detach'])
    check(f'{c}: provenance logged', s['log'][0].get('provenance') if s['log'] else None, 'found')
    return [s]


@case
def l_mcp_remote_cleanup_provenance(c):
    sb, payload = _remote_cleanup_sandbox()
    payload = dict(payload, hook_event_name='PermissionRequest')
    s = run(sb, 'learner', payload, judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('permission_request', 'allow', 'llm')],
           judge_has="This session's earlier calls to the MCP server bench")
    check(f'{c}: provenance logged', s['log'][0].get('provenance') if s['log'] else None, 'found')
    return [s]


# ---- PreToolUse: startup and malformed input -----------------------------

@case
def p_startup_unreadable_config(c):
    sb = Sandbox(config={'safe_commands': ['frobnicate']})
    os.chmod(sb.config, 0)
    try:
        s = run(sb, 'pretool', sb.bash('git status'))
        s2 = run(sb, 'pretool', sb.bash('frobnicate --all'))
    finally:
        os.chmod(sb.config, 0o600)
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')],
           stderr='re:^Warning: Could not load user config')
    expect(c, 2, s2, out=None, judge=0, events=[('pretool', 'ask', 'llm')],
           stderr='re:^Warning: Could not load user config')
    return [s, s2]


@case
def p_startup_corrupt_config(c):
    sb = Sandbox()
    with open(sb.config, 'w') as f:
        f.write('{"safe_commands": [')
    s = run(sb, 'pretool', sb.bash('git status'))
    expect(c, 1, s, out='allow', judge=0, events=[('pretool', 'allow', 'rule')],
           stderr='re:^Warning: Could not load user config')
    return [s]


@case
def p_startup_wrong_type_safety_key(c):
    sb = Sandbox(config={'dangerous_patterns': {}})
    s = run(sb, 'pretool', sb.bash(PAYLOADS['sudo']))
    expect(c, 1, s, out='deny', judge=0, events=[('pretool', 'deny', 'rule')],
           stderr="re:ignoring non-list value for safety key 'dangerous_patterns'")
    return [s]


@case
def p_startup_missing_defaults_fail_closed(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('git status'), env={'SMART_PERMISSIONS_DEFAULTS': os.path.join(sb.root, 'none.json')})
    expect(c, 1, s, out=None, judge=0, events=[('pretool', 'ask', 'llm')],
           stderr='re:^Warning: Could not load defaults')
    s2 = run(sb, 'learner', sb.bash('git status'), env={'SMART_PERMISSIONS_DEFAULTS': os.path.join(sb.root, 'none.json')})
    expect(c, 2, s2, out=None, judge=0, events=[('permission_request', 'ask', 'learner')],
           stderr='re:^Warning: Could not load defaults')
    return [s, s2]


@case
def p_input_not_json(c):
    sb = Sandbox()
    s = run(sb, 'pretool', raw='this is not json{')
    expect(c, 1, s, out='ask', judge=0, events=[('pretool', 'ask', 'rule')], reason_has='Could not parse hook input')
    return [s]


@case
def p_input_null_tool_input(c):
    sb = Sandbox()
    s = run(sb, 'pretool', {'tool_name': 'Bash', 'tool_input': None, 'cwd': sb.work})
    expect(c, 1, s, out=None, judge=0)
    return [s]


@case
def p_input_deep_nesting(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash('(' * 1200 + 'ls' + ')' * 1200))
    expect(c, 1, s, out=None, judge=0, events=[('pretool', 'ask', 'llm')])
    check(f'{c}: an ambiguous parse, not a crash', s['log'][0].get('rule_reason') if s['log'] else None,
          'Ambiguous parse — unbalanced quotes or incomplete heredoc')
    return [s]


# ---- PermissionRequest alone ---------------------------------------------

def lcall(sb, command, **kw):
    """A Bash call as the PermissionRequest hook gets it."""
    return dict(sb.bash(command, **kw), hook_event_name='PermissionRequest')


@case
def l_rule_deny(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, PAYLOADS['sudo']), judge=[SAFE])
    expect(c, 1, s, out='deny', judge=0, events=[('permission_request', 'deny', 'learner')])
    check(f'{c}: interrupt false', ((s['stdout'] or {}).get('hookSpecificOutput', {}).get('decision') or {})
          .get('interrupt'), False)
    return [s]


@case
def l_ask_user_question(c):
    sb = Sandbox()
    s = run(sb, 'learner', sb.call('AskUserQuestion', {'questions': []}), judge=[SAFE], attended=True,
            sleep_patch=True)
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')], sleeps=[])
    return [s]


@case
def l_rule_allow_still_consults(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, 'git status'), judge=[SAFE])
    expect(c, 1, s, out='allow', judge=1, events=[('permission_request', 'allow', 'llm')])
    return [s]


@case
def l_no_judge_falls_through(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'))
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')])
    return [s]


@case
def l_judge_flag_confirmed(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'), judge=[FLAG, FLAG])
    expect(c, 1, s, out=None, judge=2, events=[('permission_request', 'ask', 'llm-recheck')], flags=[])
    return [s]


@case
def l_judge_unavailable(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'), judge=[{'_status': 500}])
    expect(c, 1, s, out=None, judge=1, events=[('permission_request', 'ask', 'llm')], stderr='re:^LLM error')
    return [s]


@case
def l_c9_no_judge(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, "echo '{}' > ~/.claude/settings.json"), judge=[SAFE])
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')])
    return [s]


@case
def l_ambiguous_parse_no_judge(c):
    sb = Sandbox()
    s = run(sb, 'learner', lcall(sb, "echo 'unbalanced"), judge=[SAFE])
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')])
    return [s]


@case
def l_remote_gap_no_judge(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'learner', lcall(sb, './peekvar.sh'), judge=[SURE])
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'rule')])
    return [s]


@case
def l_remote_not_confident(c):
    sb = Sandbox(files=SCRIPTS)
    s = run(sb, 'learner', lcall(sb, 'sh ./peek.sh'), judge=[SAFE])
    expect(c, 1, s, out=None, judge=1, events=[('permission_request', 'ask', 'llm')])
    return [s]


@case
def l_input_not_json(c):
    sb = Sandbox()
    s = run(sb, 'learner', raw='}{ bad')
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')])
    return [s]


# ---- PermissionRequest: prompt timeout ------------------------------------

@case
def l_prompt_timeout_parks(c):
    sb = Sandbox(config={'prompt_timeout_minutes': 0.01})  # clamps to the 1-minute floor
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'), attended=True, sleep_patch=True)
    expect(c, 1, s, out='deny', judge=0,
           events=[('permission_request', 'ask', 'learner'),
                   ('permission_request', 'deny', 'prompt-timeout', 'prompt-timeout')],
           reason_has=['needed the developer', 'within 1 minutes', 'Parked for the developer',
                       'Why it could not be auto-approved: LLM not configured'],
           sleeps=[60])
    return [s]


@case
def l_prompt_timeout_answered_first(c):
    sb = Sandbox(config={'prompt_timeout_minutes': 1})
    p = lcall(sb, 'frobnicate --all')
    sb.write_transcript([
        {'type': 'assistant', 'timestamp': iso_ago(5), 'message': {'content': [
            {'type': 'tool_use', 'id': 'tu1', 'name': 'Bash', 'input': p['tool_input']}]}},
        {'type': 'user', 'timestamp': iso_ago(1), 'message': {'content': [
            {'type': 'tool_result', 'tool_use_id': 'tu1', 'content': 'ok'}]}}])
    s = run(sb, 'learner', p, attended=True, sleep_patch=True)
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')], sleeps=[60])
    return [s]


@case
def l_prompt_timeout_off(c):
    sb = Sandbox(config={'prompt_timeout_minutes': 0})
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'), attended=True, sleep_patch=True)
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')], sleeps=[])
    return [s]


@case
def l_prompt_timeout_unattended(c):
    sb = Sandbox(config={'prompt_timeout_minutes': 1})
    s = run(sb, 'learner', lcall(sb, 'frobnicate --all'), attended=False, sleep_patch=True)
    expect(c, 1, s, out=None, judge=0, events=[('permission_request', 'ask', 'learner')], sleeps=[])
    return [s]


# ---- Sequences: PreToolUse → PermissionRequest for the same call ----------

@case
def seq_flag_carried_to_learner(c):
    sb = Sandbox(config={'prompt_timeout_minutes': 1})
    p = sb.bash('frobnicate --all', session=False)
    s1 = run(sb, 'pretool', p, judge=[FLAG, FLAG])
    expect(c, 1, s1, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')], flags=['<this-call>'])
    s2 = run(sb, 'learner', dict(p, hook_event_name='PermissionRequest'), judge=[SAFE])
    expect(c, 2, s2, out=None, judge=0, events=[('permission_request', 'ask', 'llm-recheck')])
    # attended: the same flagged call parked after the timeout, its flag the reason
    s3 = run(sb, 'learner', dict(p, hook_event_name='PermissionRequest'), judge=[SAFE], attended=True,
             sleep_patch=True)
    expect(c, 3, s3, out='deny', judge=0,
           events=[('permission_request', 'ask', 'llm-recheck'),
                   ('permission_request', 'deny', 'prompt-timeout', 'prompt-timeout')],
           reason_has='deletes runner checkouts', sleeps=[60])
    return [s1, s2, s3]


@case
def seq_silent_ask_then_learner_no_judge(c):
    sb = Sandbox()
    p = sb.bash('frobnicate --all')
    s1 = run(sb, 'pretool', p)
    expect(c, 1, s1, out=None, judge=0, events=[('pretool', 'ask', 'llm')])
    s2 = run(sb, 'learner', dict(p, hook_event_name='PermissionRequest'))
    expect(c, 2, s2, out=None, judge=0, events=[('permission_request', 'ask', 'learner')])
    return [s1, s2]


@case
def seq_unavailable_then_learner_allows(c):
    sb = Sandbox()
    p = sb.bash('frobnicate --all')
    s1 = run(sb, 'pretool', p, judge=[{'_status': 500}])
    expect(c, 1, s1, out=None, judge=1, events=[('pretool', 'ask', 'llm')], stderr='re:^LLM error')
    s2 = run(sb, 'learner', dict(p, hook_event_name='PermissionRequest'), judge=[SAFE])
    expect(c, 2, s2, out='allow', judge=1, events=[('permission_request', 'allow', 'llm')])
    return [s1, s2]


@case
def seq_remote_ask_carried_to_learner(c):
    sb = Sandbox(files=SCRIPTS)
    p = sb.bash('sh ./peek.sh')
    s1 = run(sb, 'pretool', p, judge=[SAFE])
    expect(c, 1, s1, out='ask', judge=1, events=[('pretool', 'ask', 'llm', 'remote-exec')], flags=['<this-call>'])
    s2 = run(sb, 'learner', dict(p, hook_event_name='PermissionRequest'), judge=[SURE])
    expect(c, 2, s2, out=None, judge=0, events=[('permission_request', 'ask', 'llm-recheck')])
    return [s1, s2]


# ---- Sequences: hold → retry -----------------------------------------------

HOLD_CMD = 'frobnicate --purge cache-warm'


@case
def seq_hold_cleared_once(c):
    sb = Sandbox()
    sb.say('Before the hold: PREHOLD-MARKER')
    time.sleep(0.01)
    s1 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[FLAG, FLAG])
    expect(c, 1, s1, out='deny', judge=2, events=[('pretool', 'deny', 'llm-hold', 'held')], holds=['held'],
           flags=None, reason_has=['Held by smart-permissions (a question, not a refusal)',
                                   'Are those commits pushed anywhere?'])
    sb.say('I checked: git log origin/main has all three commits (abc1, abc2, abc3).')
    s2 = run(sb, 'pretool', sb.call('Bash', {'command': HOLD_CMD, 'description': 'cosmetic'}), judge=[SURE])
    expect(c, 2, s2, out='allow', judge=1, events=[('pretool', 'allow', 'hold-retry', 'cleared')],
           holds=['cleared'],
           judge_has=['The hook asked the agent: Are those commits pushed anywhere?',
                      'git log origin/main has all three commits', "its own claim, not the developer's"],
           judge_lacks='PREHOLD-MARKER')
    check(f'{c}: the retry pass runs at high effort', s2['judge'][0]['effort'] if s2['judge'] else None, 'high')
    # the same call flagged again: one hold per call, so the developer
    s3 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[FLAG, FLAG])
    expect(c, 3, s3, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')], holds=['cleared'],
           flags=['<this-call>'])
    check(f'{c}: not held again, and why', s3['log'][0].get('hold') if s3['log'] else None,
          'not held: this call was held once already; a second flag goes to the developer')
    s4 = run(sb, 'learner', dict(sb.bash(HOLD_CMD), hook_event_name='PermissionRequest'), judge=[SAFE])
    expect(c, 4, s4, out=None, judge=0, events=[('permission_request', 'ask', 'llm-recheck')])
    return [s1, s2, s3, s4]


@case
def seq_hold_retry_flagged(c):
    sb = Sandbox()
    s1 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[FLAG, FLAG])
    expect(c, 1, s1, out='deny', judge=2, events=[('pretool', 'deny', 'llm-hold', 'held')], holds=['held'])
    sb.say('Trust me, CLAIM-MARKER, they are not needed.')
    s2 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[dict(FLAG, reason='the answer gives no evidence')])
    expect(c, 2, s2, out='ask', judge=1, events=[('pretool', 'ask', 'hold-retry', 'asked')], holds=['asked'],
           flags=['<this-call>'],
           reason_has=['Held because: the judge flagged it', 'the answer gives no evidence',
                       "The agent's explanation (its claim, not verified)", 'CLAIM-MARKER'])
    check(f'{c}: the claim is not logged', 'CLAIM-MARKER' in json.dumps(s2['log']), False)
    check(f'{c}: the claim is not in the flag store', 'CLAIM-MARKER' in json.dumps(s2['flags']), False)
    s3 = run(sb, 'learner', dict(sb.bash(HOLD_CMD), hook_event_name='PermissionRequest'), judge=[SAFE])
    expect(c, 3, s3, out=None, judge=0, events=[('permission_request', 'ask', 'llm-recheck')])
    return [s1, s2, s3]


@case
def seq_hold_retry_without_answer(c):
    sb = Sandbox()
    s1 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[FLAG, FLAG])
    expect(c, 1, s1, out='deny', judge=2, events=[('pretool', 'deny', 'llm-hold', 'held')])
    s2 = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[SAFE])
    expect(c, 2, s2, out='ask', judge=0, events=[('pretool', 'ask', 'hold-retry', 'no-answer')], holds=['asked'],
           reason_has='the agent retried without answering')
    return [s1, s2]


@case
def seq_hold_developer_only_category(c):
    sb = Sandbox()
    s = run(sb, 'pretool', sb.bash(HOLD_CMD), judge=[dict(FLAG, category=2), dict(FLAG, category=2)])
    expect(c, 1, s, out='ask', judge=2, events=[('pretool', 'ask', 'llm-recheck')], holds=None,
           flags=['<this-call>'])
    return [s]


# ---- Manual install per README -----------------------------------------------

@case
def p_manual_install_layout(c):
    """README §Manual setup: the two entry scripts, the smart_permissions
    package and config/ into ~/.claude/hooks/smart-permissions/. Both hooks
    find config/ beside the scripts (1.8.1 looked one level up, in
    ~/.claude/hooks/config/, and failed closed)."""
    sb = Sandbox()
    dest = os.path.join(sb.claude, 'hooks', 'smart-permissions')
    os.makedirs(dest)
    for n in ('pretool_safety.py', 'permission_learner.py'):
        shutil.copy(os.path.join(PLUGIN_ROOT, 'scripts', n), dest)
    shutil.copytree(os.path.join(PLUGIN_ROOT, 'scripts', 'smart_permissions'),
                    os.path.join(dest, 'smart_permissions'),
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copytree(os.path.join(PLUGIN_ROOT, 'config'), os.path.join(dest, 'config'))
    old = dict(HOOK_COMMANDS)
    HOOK_COMMANDS['pretool'] = f'python3 {dest}/pretool_safety.py'
    HOOK_COMMANDS['learner'] = f'python3 {dest}/permission_learner.py'
    try:
        s1 = run(sb, 'pretool', sb.bash('git status'))
        s2 = run(sb, 'learner', lcall(sb, 'git status'), judge=[SAFE])
    finally:
        HOOK_COMMANDS.update(old)
    expect(c, 1, s1, out='allow', judge=0, events=[('pretool', 'allow', 'rule')], stderr='')
    expect(c, 2, s2, out='allow', judge=1, events=[('permission_request', 'allow', 'llm')], stderr='')
    return [s1, s2]


# =====================================================================
#  Runner
# =====================================================================

def _golden_view(steps):
    return [{k: v for k, v in s.items() if not k.startswith('_')} for s in steps]


def main(argv):
    update = '--update' in argv
    keys = [argv[i + 1] for i, a in enumerate(argv) if a == '-k' and i + 1 < len(argv)]
    try:
        with open(GOLDEN_PATH) as f:
            golden = json.load(f)
    except (OSError, ValueError):
        golden = {'cases': {}}
    print('Smart Permissions Hook Contract Suite')
    print(f'hooks run on: {HOOK_PYTHON} ({subprocess.run([HOOK_PYTHON, "-V"], capture_output=True, text=True).stdout.strip()})')
    print('=' * 50)
    t0 = time.monotonic()
    seen = {}
    for fn in CASES:
        cid = fn.__name__
        if keys and not any(k in cid for k in keys):
            continue
        print(f'\n--- {cid} ---')
        try:
            steps = fn(cid)
        except Exception as e:  # a broken case fails, the rest still run
            import traceback
            traceback.print_exc()
            check(f'{cid}: ran without an exception', repr(e), None)
            continue
        view = _golden_view(steps)
        seen[cid] = view
        if update:
            continue
        want = golden['cases'].get(cid)
        if want is None:
            check(f'{cid}: has a golden snapshot (run --update)', False, True)
        elif want != view:
            a = json.dumps(want, indent=1, sort_keys=True).splitlines()
            b = json.dumps(view, indent=1, sort_keys=True).splitlines()
            diff = list(difflib.unified_diff(a, b, 'golden', 'now', lineterm='', n=2))
            print('\n'.join('      ' + line for line in diff[:60]))
            check(f'{cid}: matches the golden snapshot', False, True)
        else:
            check(f'{cid}: matches the golden snapshot', True, True)
    if update:
        golden['cases'].update(seen)
        golden['_about'] = ('Hook-contract snapshot written by tests/test_contract.py --update. '
                            'Sandbox paths, ports, timings and timestamps are normalised.')
        with open(GOLDEN_PATH, 'w') as f:
            json.dump(golden, f, indent=1, sort_keys=True, ensure_ascii=False)
            f.write('\n')
        print(f'\nwrote {len(seen)} case snapshot(s) to {os.path.relpath(GOLDEN_PATH)}')
    elif not keys:
        stale = sorted(set(golden['cases']) - set(seen))
        check('no golden snapshot without a case', stale, [])
    print('\n' + '=' * 50)
    print(f'Results: {passed} passed, {failed} failed ({time.monotonic() - t0:.1f}s)')
    if errors:
        print('\nFailures:')
        for e in errors:
            print(e)
    return 1 if failed else 0


if __name__ == '__main__':
    try:
        code = main(sys.argv[1:])
    finally:
        JUDGE.server.shutdown()
        shutil.rmtree(RUN_ROOT, ignore_errors=True)
    sys.exit(code)
