<div align="center">

# cachedrift

**Your cache hit rate died on a Tuesday. Nobody noticed until the invoice.**

*Static analyzer for the code patterns that silently kill LLM prompt caching.*

[![CI](https://github.com/ZidoCode/cachedrift/actions/workflows/ci.yml/badge.svg)](https://github.com/ZidoCode/cachedrift/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cachedrift?cacheSeconds=300)](https://pypi.org/project/cachedrift/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#)

```bash
pip install cachedrift
```

</div>

---

Prompt caching cuts LLM input costs by up to 90% — **if** the request prefix is
byte-identical between calls. One nondeterministic byte and every call silently
pays full price. No error. HTTP 200. Perfect answer. Just a bigger invoice.

cachedrift scans your source for the recurring shapes of that bug — before you
deploy, not after the bill:

```text
$ cachedrift src/
cachedrift 0.1.0 — 42 file(s) scanned
findings: 2 (fail=2 warn=0 info=0)
  [FAIL] CD01 src/agent.py:42 — Time call feeding a prompt — the prefix changes every request
         system = f"You are helpful. Today is {datetime.now()}"
  [FAIL] CD03 src/tools.py:87 — Tools/prompt built from a set — iteration order is not deterministic
         for t in {parse, search, write}:
```

## The problem nobody measures

In March 2026 Anthropic quietly changed the default prompt-cache TTL from one
hour to five minutes. Spend reports of **15–20×** showed up for weeks before
anyone understood why. The postmortem's list of "the four prefix drifts" reads
like a bug catalog: re-encoded images, `tool_choice` flips, session-id reseeding,
dict-ordered system prompts. Every one of them is **findable statically**. None
of them were — until now.

Runtime tools (cachebench, tracer wrappers) tell you your hit rate *after* it
collapsed. cachedrift flags the drift *in the code that causes it*.

## The rules

| Rule | Severity | Pattern | Why the cache dies |
|------|----------|---------|-------------------|
| CD01 | **fail** | `datetime.now()` / `time.time()` / `Date.now` in a prompt | New timestamp = new prefix = new cache entry, every call |
| CD02 | **fail** | `uuid4()` / `random()` / `Math.random` in a prompt | Unique id per call — guaranteed miss |
| CD03 | **fail** | Tool loop over a **set literal** | Set iteration order is not stable across runs |
| CD04 | warn | Tool list iterated without `sorted()` | If ordering ever changes, the prefix breaks |
| CD05 | **fail** | `tool_choice` assigned a variable | Flipping auto/any/forced rewrites the cache key |
| CD06 | warn | `b64encode(open(...))` inline | Re-encoding may produce different bytes per read |
| CD07 | **fail** | `strftime`/ISO stamp concatenated into a string | Cache-buster baked into the template |
| CD08 | warn | `json.dumps(...)` without `sort_keys=True` | Dict order shifts across processes → prefix shifts |
| CD09 | info | `.strip()` / `.rstrip()` on a prompt | Whitespace churn is a prefix change |
| CD10 | info | `model = os.environ.get(...)` | Silent model swaps move you to a different cache pool |

Exit codes: `0` clean · `1` warnings · `2` failures · `3` usage error.

## Install & use

```bash
pip install cachedrift

cachedrift .                          # scan cwd
cachedrift src/ --format json         # CI-ready JSON
cachedrift src/ --min-severity fail   # only the hard failures
cachedrift src/ --rules CD01 CD07     # pick rules
cachedrift src/ --fail-on warn        # stricter CI gate
```

CI gate that blocks cache-killers:

```yaml
- run: pip install cachedrift
- run: cachedrift src/ --min-severity warn --fail-on warn
```

## Why static, why zero-dep

- **Deterministic** — same tree, same findings. No model decides anything.
- **Offline** — no API keys, no network, no telemetry.
- **Fast** — 400k-character adversarial lines scan in milliseconds; the regexes
  are bounded and regression-tested against catastrophic backtracking.
- **Auditable** — one file, ~350 lines. Read it in fifteen minutes.

## API

```python
import cachedrift as cd

findings = cd.scan_text("agent.py", 'msg = f"now {datetime.now()}"')
for f in findings:
    print(f.rule, f.severity, f.line, f.message)
```

## Honest limits

Static analysis sees shapes, not intent. A timestamp that genuinely belongs in
the prompt is a finding you suppress, not a false positive to debug. CD04/CD08/CD09
are heuristics — verify, don't panic. Pair cachedrift (prevention) with a runtime
hit-ratio tracker (detection) for full coverage.

---

<div align="center">

**If cachedrift saved you from a silent 10× bill, [drop a star](https://github.com/ZidoCode/cachedrift) — it's the only metric that keeps this free.**

Part of the [ZidoCode](https://github.com/ZidoCode) agent-audit suite —
zero-dependency, offline, deterministic tools that audit what AI agents actually do.

</div>
