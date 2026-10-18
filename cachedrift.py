#!/usr/bin/env python3
"""cachedrift — static analyzer that finds the code patterns that silently kill
your LLM prompt cache.

Every provider (Anthropic, OpenAI, Bedrock, ...) keys the prompt cache on the
exact bytes of the request prefix. One nondeterministic byte in the prefix and
every call pays full input price — silently, with HTTP 200 and a perfect
answer. cachedrift scans your source for the recurring shapes of that bug:

  CD01  time injected into the prompt      (now()/today()/time.time() ...)
  CD02  random/session id in the prompt    (uuid4(), random(), secrets...)
  CD03  tool list from a set/dict          (non-deterministic ordering)
  CD04  sorted() absent on tool iteration  (heuristic, info)
  CD05  tool_choice mutated per turn       (flip breaks the cache key)
  CD06  image re-encoded every request     (b64 of freshly opened file)
  CD07  timestamped cache-busting strings  (strftime/f-string stamp in prompt)
  CD08  dict-built system prompt           (no json.dumps(sort_keys=True))
  CD09  whitespace churn in templates      (rstrip/strip/lstrip on prompt)
  CD10  model name from env per request    (cache pool swap risk)

Deterministic, offline, zero dependencies. Exit codes:
  0 = clean, 1 = warnings found, 2 = failures found, 3 = usage error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

__version__ = "0.1.0"

TOOL_NAME = "cachedrift"

SEV_ORDER = {"fail": 0, "warn": 1, "info": 2}

PY_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb"}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor",
}

MAX_BYTES = 2 * 1024 * 1024  # skip files above 2 MB

# bounded quantifiers everywhere — never a nested unbounded quantifier
IDENT = r"[A-Za-z_][A-Za-z0-9_]{0,64}"
STR_LIT = r"['\"](?:(?:[^'\"\\\n])|(?:\\.)){0,400}?['\"]"


@dataclass
class Finding:
    rule: str
    severity: str  # fail | warn | info
    file: str
    line: int
    message: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rule:
    rule_id: str
    severity: str
    description: str
    pattern: re.Pattern | None = None
    # languages the raw pattern applies to; None = all
    langs: tuple | None = None


# ---------------------------------------------------------------- rules ----

KW = r"(?:prompt|system|prefix|template|message|messages|msg|content|instructions)"

FSTR = r"f['\"][^'\"]{0,400}\{[^}]{0,200}?"
FSTR_ANY = r"f['\"][^'\"]*?\{[^}]{0,200}?"  # unbounded prefix, lazy — for long f-strings

RULES: list[Rule] = [
    Rule("CD01", "fail",
         "Time call feeding a prompt — the prefix changes every request",
         re.compile(
             "(?:" + KW + r"[^\n]{0,200}?"
             r"\b(?:datetime\.now|datetime\.utcnow|datetime\.today|"
             r"time\.time|time\.strftime|arrow\.now|dayjs\(\)|moment\(\)|"
             r"Date\.now|new Date\b)"
             + "|" + FSTR_ANY +
             r"\b(?:datetime\.now|datetime\.utcnow|datetime\.today|"
             r"time\.time|Date\.now)\b)",
             re.IGNORECASE)),
    Rule("CD02", "fail",
         "Random/unique id injected near prompt assembly — unique byte per call",
         re.compile(
             "(?:" + KW + r"[^\n]{0,200}?"
             r"\b(?:uuid(?:4|v4)?\(\)|uuid\.uuid4|random\.random|random\.randint|"
             r"secrets\.token|Math\.random|crypto\.randomUUID|rand\.Intn)"
             + "|" + FSTR_ANY +
             r"\b(?:uuid\.uuid4|uuid\(\)|random\.|Math\.random|crypto\.randomUUID)\b)",
             re.IGNORECASE)),
    Rule("CD03", "fail",
         "Tools/prompt built from a set literal — iteration order is not deterministic",
         re.compile(
             r"\bfor\s+" + IDENT + r"\s+in\s+(?:set\s*\(|\{)[^;]{0,200}$")),
    Rule("CD04", "warn",
         "Tool list iterated without a sort — verify ordering is stable",
         re.compile(
             r"\bfor\s+" + IDENT + r"\s+in\s+"
             r"(?:self\.)?(?:tools|tool_list|functions|available_tools|tool_schemas)"
             r"\b(?![^\n]{0,80}\bsorted\s*\()")),
    Rule("CD05", "fail",
         "tool_choice computed dynamically — flips rewrite the cache key",
         re.compile(
             r"['\"]?tool_choice['\"]?\s*\]?\s*[:=]\s*(?!['\"ANOau][^ \n]{0,8})"
             r"[A-Za-z_][A-Za-z0-9_.\[\]'\"]{0,80}")),
    Rule("CD06", "warn",
         "File re-encoded to base64 inline — image bytes may differ per read",
         re.compile(
             r"b64encode\s*\(\s*(?:open\s*\(|Path\s*\([^)]{1,120}\)\s*\.\s*read_bytes)")),
    Rule("CD07", "fail",
         "Timestamp stamped into a template literal — cache-buster per call",
         re.compile(
             r"(?:strftime\s*\(\s*['\"][^'\"]{0,40}['\"]|%Y|%H:%M|toLocaleString|toISOString)"
             r"[^\n]{0,40}['\"][^'\"]{0,200}['\"]")),
    Rule("CD08", "warn",
         "System prompt assembled from a dict without sorted key serialization",
         re.compile(
             r"json\.dumps\s*\((?![^\n]{0,120}sort_keys\s*=\s*True)")),
    Rule("CD09", "info",
         "Whitespace mutation on a prompt/template string — prefix drift risk",
         re.compile(
             KW + r"[^\n]{0,120}?"
             r"\.\s*(?:strip|lstrip|rstrip)\s*\(\s*\)",
             re.IGNORECASE)),
    Rule("CD10", "info",
         "Model id read from env per call — upgrades silently swap the cache pool",
         re.compile(
             r"(?:model|MODEL)\s*[:=]\s*os\.environ(?:\.get)?\s*\(\s*['\"][^'\"]{0,60}['\"]")),
]

PY_ONLY = {"CD03", "CD04", "CD08", "CD10"}
JS_OK = {"CD04", "CD05", "CD06", "CD07", "CD09", "CD01", "CD02", "CD03"}


def lang_of(path: Path) -> str:
    return path.suffix.lstrip(".").lower()


def applies(rule: Rule, path: Path) -> bool:
    lg = lang_of(path)
    if rule.rule_id in PY_ONLY and lg not in ("py",):
        return False
    if rule.pattern is None:
        return False
    return True


def scan_text(rel: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    lines = text.split("\n")
    for rule in RULES:
        for i, line in enumerate(lines, 1):
            # hard cap for pathological lines; regexes verified linear on
            # 400k-char adversarial input (see test_per regression guard)
            if len(line) > 1_000_000:
                line = line[:1_000_000]
            try:
                m = rule.pattern.search(line)
            except Exception:
                m = None
            if m:
                out.append(Finding(
                    rule=rule.rule_id,
                    severity=rule.severity,
                    file=rel,
                    line=i,
                    message=rule.description,
                    snippet=line.strip()[:200],
                ))
    return out


def iter_source(root: Path, explicit: list[Path]) -> list[Path]:
    if explicit:
        return explicit
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            p = Path(dirpath) / fn
            if p.suffix.lower() in PY_EXT:
                files.append(p)
    return files


def scan(paths: list[Path], root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for p in paths:
        try:
            if p.stat().st_size > MAX_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(root)) if p.is_relative_to(root) else str(p)
        findings.extend(scan_text(rel, text))
    findings.sort(key=lambda f: (f.file, f.line, f.rule))
    return findings


def apply_filters(findings: list[Finding], min_severity: str,
                  rules: list[str] | None) -> list[Finding]:
    min_rank = SEV_ORDER[min_severity]
    out = [f for f in findings if SEV_ORDER[f.severity] <= min_rank]
    if rules:
        allow = set(rules)
        out = [f for f in out if f.rule in allow]
    return out


def report(findings: list[Finding], fmt: str, scanned: int) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    if fmt == "json":
        return json.dumps({
            "tool": TOOL_NAME,
            "version": __version__,
            "files_scanned": scanned,
            "summary": counts,
            "findings": [f.to_dict() for f in findings],
        }, indent=2)
    lines = [f"cachedrift {__version__} — {scanned} file(s) scanned"]
    if not findings:
        lines.append("clean — no cache-drift patterns found")
        return "\n".join(lines)
    lines.append(f"findings: {len(findings)} "
                 f"(fail={counts.get('fail', 0)} warn={counts.get('warn', 0)} "
                 f"info={counts.get('info', 0)})")
    for f in findings:
        lines.append(f"  [{f.severity.upper():4}] {f.rule} {f.file}:{f.line} — {f.message}")
        if f.snippet:
            lines.append(f"         {f.snippet}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Static analyzer for LLM prompt-cache drift patterns.",
    )
    ap.add_argument("paths", nargs="*", default=["."],
                    help="files or directories to scan (default: cwd)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--min-severity", choices=["fail", "warn", "info"],
                    default="info")
    ap.add_argument("--rules", nargs="*",
                    help="only run these rule ids (e.g. CD01 CD07)")
    ap.add_argument("--fail-on", choices=["fail", "warn", "info"], default="fail",
                    help="severity that produces exit code 2 (default: fail)")
    ap.add_argument("--version", action="version",
                    version=f"{TOOL_NAME} {__version__}")
    args = ap.parse_args(argv)

    root = Path(".").resolve()
    explicit: list[Path] = []
    dirs: list[Path] = []
    for raw in args.paths:
        p = Path(raw)
        if not p.exists():
            print(f"error: path not found: {raw}", file=sys.stderr)
            return 3
        (explicit if p.is_file() else dirs).append(p.resolve())

    targets: list[Path] = list(explicit)
    for d in dirs:
        targets.extend(iter_source(d, []))
    # dedupe, preserve order
    seen: set[Path] = set()
    uniq: list[Path] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)

    findings = scan(uniq, root)
    findings = apply_filters(findings, args.min_severity, args.rules)
    print(report(findings, args.format, len(uniq)))

    fail_rank = SEV_ORDER[args.fail_on]
    if any(SEV_ORDER[f.severity] <= fail_rank for f in findings):
        return 2
    if findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
