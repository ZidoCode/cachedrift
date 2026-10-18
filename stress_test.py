#!/usr/bin/env python3
"""Stress harness for cachedrift — 50 adversarial transcripts, zero-crash gate."""

import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

TOOL = str(Path(__file__).parent / "cachedrift.py")

JUNKS = [
    lambda n: "x" * n,
    lambda n: ("prompt " * (n // 7))[:n],
    lambda n: ('f"t {' * (n // 6))[:n],
    lambda n: ("a?" * (n // 2))[:n],
    lambda n: ("{" + "a" * 50 + "}" * 2) * (n // 104),
    lambda n: ("'\\\"'" * (n // 4))[:n],
    lambda n: (chr(0x4F60) + chr(0x1F680)) * (n // 2),  # CJK + emoji
]

PAYLOADS = [
    'msg = f"now {datetime.now()}"',
    'msg = f"session {uuid.uuid4()}"',
    "for t in tools:\n    pass",
    "body['tool_choice'] = choice",
    "p = json.dumps(cfg)",
    'prefix = "s " + ts.strftime("%Y-%m-%d") + " e"',
    "system_prompt.strip()",
    "model = os.environ.get('MODEL')",
    "data = b64encode(open(f, 'rb').read())",
    'system = "totally clean prompt"',
]


def build_case(i: int, d: Path) -> Path:
    rng = random.Random(i)
    f = d / f"s{i:02d}.py"
    n_junk = rng.randint(0, 6)
    n_pay = rng.randint(0, 4)
    lines = []
    for _ in range(n_junk):
        j = rng.choice(JUNKS)
        lines.append("# " + j(rng.randint(1, 120_000)))
    for _ in range(n_pay):
        lines.append(rng.choice(PAYLOADS))
    f.write_text("\n".join(lines) + "\n", encoding="utf-8", errors="ignore")
    return f


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cd-stress-"))
    crashes = 0
    slow = 0
    try:
        for i in range(50):
            case_dir = tmp / f"case{i:02d}"
            case_dir.mkdir()
            build_case(i, case_dir)
            t0 = time.time()
            r = subprocess.run(
                [sys.executable, TOOL, str(case_dir), "--format", "json"],
                capture_output=True, text=True, timeout=30,
            )
            dt = time.time() - t0
            if r.returncode not in (0, 1, 2):
                crashes += 1
                print(f"case {i:02d}: CRASH rc={r.returncode} "
                      f"stderr={r.stderr[-300:]}")
            if dt > 10:
                slow += 1
                print(f"case {i:02d}: SLOW {dt:.1f}s")
            # JSON validity when rc in (0,1,2)
            try:
                data = json.loads(r.stdout)
                assert "findings" in data and "files_scanned" in data
            except Exception as e:
                crashes += 1
                print(f"case {i:02d}: BAD JSON {e} stdout={r.stdout[:200]}")
        # edge modes
        edges = []
        empty = tmp / "empty"; empty.mkdir()
        edges.append(("empty dir", [str(empty)]))
        edges.append(("missing path", ["/nonexistent-zz"]))
        edges.append(("no args", []))
        edges.append(("single clean file", []))
        clean = tmp / "clean.py"; clean.write_text("x = 1\n")
        edges[-1] = ("single clean file", [str(clean)])
        for name, args in edges:
            r = subprocess.run([sys.executable, TOOL] + args,
                               capture_output=True, text=True, timeout=30,
                               cwd=str(tmp))
            print(f"edge {name}: rc={r.returncode}")
            if name != "missing path" and r.returncode not in (0, 1, 2):
                crashes += 1
            if name == "missing path" and r.returncode != 3:
                crashes += 1
        print(f"\nRESULT: 50 cases + 4 edges — crashes={crashes} slow={slow}")
        return 0 if crashes == 0 and slow == 0 else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
