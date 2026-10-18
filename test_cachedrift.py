#!/usr/bin/env python3
"""Stress + correctness tests for cachedrift. Zero dependencies."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import cachedrift as cd  # noqa: E402

TOOL = str(Path(__file__).parent / "cachedrift.py")


def run_cli(args, cwd=None, timeout=30):
    return subprocess.run(
        [sys.executable, TOOL] + args,
        capture_output=True, text=True, timeout=timeout, cwd=cwd,
    )


class TestRules(unittest.TestCase):
    def _scan_line(self, line, lang="py"):
        with tempfile.NamedTemporaryFile(
                "w", suffix="." + lang, delete=False) as f:
            f.write(line + "\n")
            path = f.name
        try:
            return cd.scan([Path(path)], Path(path).parent)
        finally:
            os.unlink(path)

    def _rules_of(self, line, lang="py"):
        return sorted({f.rule for f in self._scan_line(line, lang)})

    def test_clean_prompt(self):
        self.assertEqual(self._rules_of('system = "You are helpful."'), [])

    def test_cd01_time_in_prompt(self):
        rules = self._rules_of('prompt = f"Today is {datetime.now()}"')
        self.assertIn("CD01", rules)

    def test_cd01_js_date(self):
        rules = self._rules_of(
            'const system = `Now: ${new Date().toISOString()}`;', "js")
        self.assertIn("CD01", rules)

    def test_cd02_uuid_in_prompt(self):
        rules = self._rules_of(
            'msg = f"session {uuid.uuid4()} started"')
        self.assertIn("CD02", rules)

    def test_cd03_set_iteration(self):
        rules = self._rules_of(
            "for t in {\"a\", \"b\"}:\n    register(t)")
        self.assertIn("CD03", rules)

    def test_cd04_unsorted_tools(self):
        rules = self._rules_of("for t in tools:\n    dump(t)")
        self.assertIn("CD04", rules)

    def test_cd04_sorted_tools_ok(self):
        # 'sorted(' appears later on the line → info-level heuristic suppressed
        findings = [f for f in self._scan_line(
            "for t in sorted(tools, key=lambda x: x.name):\n    pass")]
        self.assertNotIn("CD04", [f.rule for f in findings])

    def test_cd05_dynamic_tool_choice(self):
        rules = self._rules_of("body['tool_choice'] = choice")
        self.assertIn("CD05", rules)

    def test_cd05_static_tool_choice_ok(self):
        rules = self._rules_of("body['tool_choice'] = 'auto'")
        self.assertNotIn("CD05", rules)

    def test_cd06_b64_inline(self):
        rules = self._rules_of(
            "data = base64.b64encode(open(p, 'rb').read())")
        self.assertIn("CD06", rules)

    def test_cd07_strftime_in_template(self):
        rules = self._rules_of(
            'prefix = "snapshot " + ts.strftime("%Y-%m-%d %H:%M") + " state"')
        self.assertIn("CD07", rules)

    def test_cd08_json_dumps_unsorted(self):
        rules = self._rules_of("payload = json.dumps(config)")
        self.assertIn("CD08", rules)

    def test_cd08_sorted_ok(self):
        rules = self._rules_of("payload = json.dumps(config, sort_keys=True)")
        self.assertNotIn("CD08", rules)

    def test_cd09_strip_on_prompt(self):
        rules = self._rules_of("system_prompt.strip()")
        self.assertIn("CD09", rules)

    def test_cd10_model_from_env(self):
        rules = self._rules_of("model = os.environ.get('LLM_MODEL')")
        self.assertIn("CD10", rules)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cd-cli-")
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", self.tmp], timeout=10))

    def _write(self, name, text):
        p = Path(self.tmp) / name
        p.write_text(text)
        return p

    def test_clean_dir_rc0(self):
        self._write("ok.py", 'system = "hello"\n')
        r = run_cli([self.tmp])
        self.assertEqual(r.returncode, 0)

    def test_dirty_dir_rc2(self):
        self._write("bad.py",
                    'msg = f"now {datetime.now()}"\n')
        r = run_cli([self.tmp])
        self.assertEqual(r.returncode, 2)

    def test_warn_only_rc1(self):
        self._write("w.py", "for t in tools:\n    pass\n")
        r = run_cli([self.tmp, "--min-severity", "warn"])
        self.assertEqual(r.returncode, 1)

    def test_fail_on_warn(self):
        self._write("w.py", "for t in tools:\n    pass\n")
        r = run_cli([self.tmp, "--fail-on", "warn"])
        self.assertEqual(r.returncode, 2)

    def test_json_output(self):
        self._write("bad.py", 'p = f"t {time.time()}"\n')
        r = run_cli([self.tmp, "--format", "json"])
        data = json.loads(r.stdout)
        self.assertEqual(data["tool"], "cachedrift")
        self.assertGreater(len(data["findings"]), 0)
        self.assertIn("files_scanned", data)

    def test_rules_filter(self):
        self._write("mixed.py",
                    'a = f"t {time.time()}"\n'
                    "for t in tools:\n    pass\n")
        r = run_cli([self.tmp, "--rules", "CD04"])
        self.assertNotIn("CD01", r.stdout)
        self.assertIn("CD04", r.stdout)

    def test_missing_path_rc3(self):
        r = run_cli(["/nonexistent-zz/qq"])
        self.assertEqual(r.returncode, 3)

    def test_version(self):
        r = run_cli(["--version"])
        self.assertIn("cachedrift", r.stdout)

    def test_skip_dirs(self):
        os.makedirs(Path(self.tmp) / "node_modules", exist_ok=True)
        self._write("node_modules/bad.py", 'p = f"t {time.time()}"\n')
        r = run_cli([self.tmp])
        self.assertEqual(r.returncode, 0)
        self.assertIn("clean", r.stdout)


class TestRobustness(unittest.TestCase):
    """Adversarial inputs: huge lines, unicode, binary-ish, deep nesting."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cd-stress-")
        self.addCleanup(lambda: subprocess.run(
            ["rm", "-rf", self.tmp], timeout=10))

    def _run(self, args=None):
        return run_cli(args or [self.tmp], timeout=60)

    def test_giant_line(self):
        junk = "x" * 400_000
        Path(self.tmp, "big.py").write_text(
            f"prompt = f\"{junk} {{datetime.now()}}\"\n")
        t0 = time.time()
        r = self._run()
        self.assertLess(time.time() - t0, 30, "giant line must not hang")
        self.assertEqual(r.returncode, 2)

    def test_many_lines(self):
        lines = ['system = f"log {time.strftime(chr(37) + chr(89))}"\n'] * 20_000
        Path(self.tmp, "many.py").write_text("".join(lines))
        t0 = time.time()
        r = self._run()
        self.assertLess(time.time() - t0, 30)
        self.assertEqual(r.returncode, 2)

    def test_unicode(self):
        Path(self.tmp, "u.py").write_text(
            "prompt = '你的 agent 读取了 40 个文件 🚀'\n"
            "msg = f\"{uuid.uuid4()} — 权限\"\n", encoding="utf-8")
        r = self._run()
        self.assertEqual(r.returncode, 2)

    def test_binary_ish(self):
        Path(self.tmp, "b.py").write_bytes(
            bytes(range(256)) * 40 + b"prompt = f't {time.time()}'\n")
        r = self._run()
        self.assertEqual(r.returncode, 2)

    def test_empty_file_and_dir(self):
        Path(self.tmp, "empty.py").write_text("")
        os.makedirs(Path(self.tmp) / "sub")
        r = self._run()
        self.assertEqual(r.returncode, 0)

    def test_no_args_defaults_cwd(self):
        r = run_cli([], cwd=self.tmp)
        self.assertEqual(r.returncode, 0)

    def test_single_file_arg(self):
        p = Path(self.tmp, "one.py")
        p.write_text("for t in tools:\n    pass\n")
        r = run_cli([str(p)])
        self.assertEqual(r.returncode, 1)


class TestPerfRegression(unittest.TestCase):
    """PATH-style regexes must stay bounded: ReDoS regression guard."""

    def test_adversarial_backtracking(self):
        # pathological 'a?' chains around rule keywords
        evil = ("prompt" + "a" * 50_000) + " datetime.now()"
        with tempfile.NamedTemporaryFile("w", suffix=".py",
                                         delete=False) as f:
            f.write(evil + "\n")
            path = f.name
        self.addCleanup(lambda: os.unlink(path))
        t0 = time.time()
        cd.scan([Path(path)], Path(path).parent)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 5.0,
                        f"possible ReDoS: {elapsed:.2f}s on 50k adversarial")


if __name__ == "__main__":
    unittest.main(verbosity=2)
