"""Test suite for secscan. Standard library only: python3 -m unittest discover tests"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secscan import cli, knowledge, pyast, report as report_mod, rules, scanner
from secscan.news import NewsProvider


def write(tmp: Path, name: str, content: str) -> Path:
    path = tmp / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def scan_source(content: str, filename: str = "app.py") -> list:
    """Scan one in-memory file and return its findings."""
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        path = write(tmp, filename, content)
        lang = scanner.detect_language(path)
        assert lang is not None, f"no language for {filename}"
        return scanner.scan_file(path, lang, tmp).findings


def rule_ids(findings) -> set:
    return {f.rule_id for f in findings}


def classes(findings) -> set:
    return {f.vuln_class for f in findings}


# ---------------------------------------------------------------------------
class TestIntegrity(unittest.TestCase):
    """The rule set and knowledge base must stay internally consistent."""

    def test_every_rule_has_a_known_class(self):
        for r in rules.RULES:
            self.assertIn(r.vuln_class, knowledge.VULN_CLASSES, f"{r.id} -> {r.vuln_class}")

    def test_rule_ids_unique(self):
        ids = [r.id for r in rules.RULES] + [s.id for s in rules.SECRET_PATTERNS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule id")

    def test_all_regexes_compile(self):
        for r in rules.RULES:
            r.compiled()
            r.compiled_negate()

    def test_scores_in_range(self):
        for vc in knowledge.all_classes():
            for axis in (vc.impact, vc.exploitability, vc.prevalence):
                self.assertTrue(1 <= axis <= 5, f"{vc.key} axis out of range")

    def test_every_class_has_prose_for_all_four_axes(self):
        for vc in knowledge.all_classes():
            self.assertGreater(len(vc.impact_note), 40, vc.key)
            self.assertGreater(len(vc.exploitability_note), 40, vc.key)
            self.assertGreater(len(vc.prevalence_note), 40, vc.key)
            self.assertGreater(len(vc.remediation), 40, vc.key)

    def test_news_items_well_formed(self):
        for vc in knowledge.all_classes():
            for item in vc.news:
                self.assertRegex(item.date, r"^\d{4}-\d{2}$", vc.key)
                self.assertTrue(item.url.startswith("https://"), item.url)
                self.assertTrue(item.source and item.headline and item.summary, vc.key)

    def test_ast_checks_set_matches_emitted_rule_ids(self):
        import re
        src = (Path(__file__).resolve().parents[1] / "secscan" / "pyast.py").read_text()
        body = src.split("class PythonAnalyzer", 1)[1]
        emitted = set(re.findall(r'"(AST-PY-[A-Z]+)"', body))
        self.assertEqual(emitted, set(pyast.AST_CHECKS),
                         "AST_CHECKS must list exactly the checks the analyzer emits")

    def test_ast_covered_set_matches_supersedes_declarations(self):
        import re
        src = (Path(__file__).resolve().parents[1] / "secscan" / "pyast.py").read_text()
        body = src.split("class PythonAnalyzer", 1)[1]
        declared = set()
        for match in re.finditer(r"supersedes=\(([^)]*)\)", body):
            declared.update(re.findall(r'"([A-Z][A-Z0-9\-]+)"', match.group(1)))
        self.assertEqual(declared, set(pyast.AST_COVERED_RULES),
                         "AST_COVERED_RULES must exactly match the supersedes declarations")

    def test_ast_rules_reference_real_rule_ids(self):
        known = {r.id for r in rules.RULES}
        src = Path(__file__).resolve().parents[1] / "secscan" / "pyast.py"
        text = src.read_text()
        import re
        for match in re.finditer(r'supersedes=\(([^)]*)\)', text):
            for rid in re.findall(r'"([A-Z][A-Z0-9\-]+)"', match.group(1)):
                self.assertIn(rid, known, f"pyast supersedes unknown rule {rid}")


# ---------------------------------------------------------------------------
class TestTruePositives(unittest.TestCase):

    def test_sql_injection_fstring(self):
        f = scan_source('def q(cur, n):\n    cur.execute(f"SELECT * FROM t WHERE n = \'{n}\'")\n')
        self.assertIn("sql-injection", classes(f))

    def test_sql_injection_concatenation(self):
        f = scan_source('def q(cur, n):\n    cur.execute("SELECT * FROM t WHERE id = " + n)\n')
        self.assertIn("sql-injection", classes(f))

    def test_command_injection_shell_true(self):
        f = scan_source('import subprocess\ndef r(x):\n    subprocess.run("ls " + x, shell=True)\n')
        self.assertIn("command-injection", classes(f))

    def test_pickle_and_yaml(self):
        f = scan_source('import pickle, yaml\npickle.loads(b)\nyaml.load(s)\n')
        self.assertIn("deserialization", classes(f))
        self.assertGreaterEqual(len([x for x in f if x.vuln_class == "deserialization"]), 2)

    def test_weak_hash_and_tls(self):
        f = scan_source('import hashlib, requests\nhashlib.md5(b"x")\nrequests.get(u, verify=False)\n')
        self.assertIn("weak-crypto", classes(f))
        self.assertIn("tls-verification-disabled", classes(f))

    def test_javascript_rules(self):
        f = scan_source(
            'const q = await db.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n'
            'el.innerHTML = userInput;\n'
            'const token = Math.random().toString(36);\n',
            "app.js")
        self.assertIn("sql-injection", classes(f))
        self.assertIn("xss", classes(f))
        self.assertIn("weak-random", classes(f))

    def test_c_memory_and_format(self):
        f = scan_source('void f(char *u){ char b[8]; strcpy(b, u); printf(b); }\n', "m.c")
        self.assertIn("buffer-overflow", classes(f))
        self.assertIn("format-string", classes(f))

    def test_php_and_ruby(self):
        f = scan_source('<?php echo $_GET["name"]; unserialize($_POST["d"]); ?>\n', "i.php")
        self.assertIn("xss", classes(f))
        self.assertIn("deserialization", classes(f))
        f = scan_source('def run(x)\n  `ping #{x}`\nend\n', "r.rb")
        self.assertIn("command-injection", classes(f))


# ---------------------------------------------------------------------------
class TestFalsePositiveResistance(unittest.TestCase):
    """The scanner must stay quiet on code that is actually correct."""

    def test_parameterised_sql_is_clean(self):
        f = scan_source('def q(cur, n):\n    cur.execute("SELECT * FROM t WHERE n = %s", (n,))\n')
        self.assertNotIn("sql-injection", classes(f))

    def test_subprocess_argument_list_is_clean(self):
        f = scan_source('import subprocess\nsubprocess.run(["ls", "-l", path])\n')
        self.assertNotIn("command-injection", classes(f))

    def test_md5_marked_not_for_security_is_clean(self):
        f = scan_source('import hashlib\nhashlib.md5(b"x", usedforsecurity=False)\n')
        self.assertNotIn("weak-crypto", classes(f))

    def test_yaml_safe_load_is_clean(self):
        f = scan_source('import yaml\nyaml.safe_load(s)\nyaml.load(s, Loader=yaml.SafeLoader)\n')
        self.assertNotIn("deserialization", classes(f))

    def test_vulnerability_inside_a_comment_is_ignored(self):
        f = scan_source('# we used to call eval(user_input) here\n# subprocess.run(x, shell=True)\nx = 1\n')
        self.assertEqual(classes(f), set())

    def test_hash_inside_a_string_is_not_a_comment(self):
        f = scan_source('msg = "# subprocess.run(cmd, shell=True)"\n')
        self.assertEqual(classes(f), set())

    def test_import_line_is_not_a_use(self):
        f = scan_source('from flask import render_template_string\nx = 1\n')
        self.assertNotIn("template-injection", classes(f))

    def test_url_in_js_is_not_a_comment(self):
        f = scan_source('const a = "https://x.test/p"; eval(z);\n', "a.js")
        self.assertIn("code-injection", classes(f))

    def test_defusedxml_import_suppresses_xxe(self):
        clean = scan_source('from defusedxml.ElementTree import parse\nparse(f)\n')
        self.assertNotIn("xxe", classes(clean))
        unsafe = scan_source('import xml.etree.ElementTree as ET\nET.parse(f)\n')
        self.assertIn("xxe", classes(unsafe))


# ---------------------------------------------------------------------------
class TestSuppression(unittest.TestCase):

    def test_nosec_suppresses_the_line(self):
        f = scan_source('import subprocess\nsubprocess.run(c, shell=True)  # nosec\n')
        self.assertEqual(classes(f), set())

    def test_targeted_suppression_only_hits_named_rule(self):
        src = 'import subprocess, hashlib\nsubprocess.run(c, shell=True)  # secscan:ignore AST-PY-SHELL\nhashlib.md5(b"")\n'
        f = scan_source(src)
        self.assertNotIn("command-injection", classes(f))
        self.assertIn("weak-crypto", classes(f))


# ---------------------------------------------------------------------------
class TestTaintTracking(unittest.TestCase):

    def test_request_derived_value_is_marked_tainted(self):
        src = ('from flask import request\n'
               '@app.route("/x")\n'
               'def x():\n'
               '    n = request.args.get("n")\n'
               '    cur.execute(f"SELECT * FROM t WHERE n = \'{n}\'")\n')
        f = [x for x in scan_source(src) if x.vuln_class == "sql-injection"]
        self.assertTrue(f and f[0].tainted, "request-derived SQL should be tainted")
        self.assertIn("request.args", f[0].taint_reason)

    def test_taint_raises_exploitability(self):
        tainted_src = ('from flask import request\n'
                       'p = request.args.get("p")\n'
                       'open("/data/" + p)\n')
        t = [x for x in scan_source(tainted_src) if x.vuln_class == "path-traversal"]
        self.assertTrue(t)
        base = knowledge.get("path-traversal").exploitability
        self.assertGreaterEqual(t[0].exploitability, base)

    def test_route_handler_parameters_are_tainted(self):
        src = ('@app.route("/u/<name>")\n'
               'def u(name):\n'
               '    import subprocess\n'
               '    subprocess.run("id " + name, shell=True)\n')
        f = [x for x in scan_source(src) if x.vuln_class == "command-injection"]
        self.assertTrue(f and f[0].tainted)

    def test_local_input_is_distinguished_from_remote(self):
        """argv is untrusted, but not in the same way a stranger's request is."""
        local = [x for x in scan_source('import sys\nopen(sys.argv[1] + ".txt")\n')
                 if x.vuln_class == "path-traversal"]
        self.assertTrue(local, "argv-derived path should still be reported")
        self.assertEqual(local[0].taint_trust, "local")
        self.assertEqual(local[0].severity, "low")
        self.assertIn("privileges", local[0].exploitability_note)

        remote = [x for x in scan_source(
            'from flask import request\np = request.args.get("p")\nopen("/d/" + p)\n')
            if x.vuln_class == "path-traversal"]
        self.assertTrue(remote)
        self.assertEqual(remote[0].taint_trust, "remote")
        self.assertIn(remote[0].severity, ("critical", "high"))

    def test_remote_taint_wins_over_local_in_one_expression(self):
        src = ('import sys\nfrom flask import request\n'
               'open(sys.argv[1] + request.args.get("p"))\n')
        f = [x for x in scan_source(src) if x.vuln_class == "path-traversal"]
        self.assertTrue(f)
        self.assertEqual(f[0].taint_trust, "remote")

    def test_literal_only_call_is_lower_confidence(self):
        f = [x for x in scan_source('import subprocess\nsubprocess.run("ls -l", shell=True)\n')
             if x.vuln_class == "command-injection"]
        self.assertTrue(f)
        self.assertEqual(f[0].confidence, "medium")
        self.assertFalse(f[0].tainted)


# ---------------------------------------------------------------------------
class TestSecrets(unittest.TestCase):

    def test_real_looking_key_is_reported(self):
        f = scan_source('AWS_KEY = "AKIA4XQ7ZM2NPBWLKC3D"\n')
        self.assertIn("hardcoded-secret", classes(f))
        self.assertEqual([x for x in f][0].confidence, "high")

    def test_placeholders_are_ignored(self):
        for value in ('"xxxxxxxxxxxx"', '"CHANGEME"', '"<your-api-key>"',
                      '"${API_KEY}"', 'os.environ["API_KEY"]', '"your-token-here"'):
            f = scan_source(f'api_key = {value}\n')
            self.assertNotIn("hardcoded-secret", classes(f), f"false positive on {value}")

    def test_documentation_example_key_is_downgraded(self):
        f = [x for x in scan_source('K = "AKIAIOSFODNN7EXAMPLE"\n') if x.vuln_class == "hardcoded-secret"]
        self.assertTrue(f)
        self.assertEqual(f[0].confidence, "low")
        self.assertIn("not a live", f[0].message)

    def test_low_entropy_generic_value_is_ignored(self):
        f = scan_source('password = "aaaaaaaaaaaa"\n')
        self.assertNotIn("hardcoded-secret", classes(f))

    def test_db_url_with_password_is_reported(self):
        f = scan_source('DSN = "postgres://u:S3cretPassw0rd@db.internal:5432/app"\n')
        self.assertIn("hardcoded-secret", classes(f))

    def test_secret_value_is_redacted_in_output(self):
        secret = "hT9vKq2LpXn4RwZ6bYs8Dm1AcVg0FjUeQi5NoPtR"
        f = [x for x in scan_source(f'AWS_SECRET_ACCESS_KEY = "{secret}"\n')
             if x.vuln_class == "hardcoded-secret"]
        self.assertTrue(f)
        self.assertNotIn(secret, f[0].message, "full secret must not be echoed in the message")


# ---------------------------------------------------------------------------
class TestScoring(unittest.TestCase):

    def test_severity_thresholds(self):
        f = scanner.Finding(rule_id="X", rule_name="x", vuln_class="sql-injection",
                            path="a.py", line=1, column=0, snippet="", message="",
                            confidence="high", language="python")
        scanner.score(f)
        self.assertEqual(f.severity, "critical")
        self.assertAlmostEqual(f.risk_score, 10.0)

    def test_test_code_is_downgraded(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = write(tmp, "tests/test_thing.py",
                         'import subprocess\nsubprocess.run("ls " + x, shell=True)\n')
            f = scanner.scan_file(path, "python", tmp).findings
            self.assertTrue(f)
            self.assertTrue(f[0].in_test_code)
            self.assertIn(f[0].severity, ("info", "low"))

    def test_test_heuristic_can_be_disabled(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            path = write(tmp, "tests/test_thing.py",
                         'import subprocess\nsubprocess.run("ls " + x, shell=True)\n')
            f = scanner.scan_file(path, "python", tmp, test_heuristic=False).findings
            self.assertFalse(f[0].in_test_code)
            self.assertIn(f[0].severity, ("critical", "high"))

    def test_low_confidence_never_reports_critical(self):
        f = scanner.Finding(rule_id="X", rule_name="x", vuln_class="sql-injection",
                            path="a.py", line=1, column=0, snippet="", message="",
                            confidence="low", language="python")
        scanner.score(f)
        self.assertNotEqual(f.severity, "critical")

    def test_exploitability_note_explains_the_adjustment(self):
        f = scanner.Finding(rule_id="X", rule_name="x", vuln_class="sql-injection",
                            path="a.py", line=1, column=0, snippet="", message="",
                            confidence="high", language="python", tainted=True,
                            taint_reason="derives from request.args")
        scanner.score(f)
        self.assertIn("request.args", f.exploitability_note)


# ---------------------------------------------------------------------------
class TestRenderers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmpdir.name)
        write(tmp, "app.py",
              'import subprocess, hashlib\n'
              'from flask import request\n'
              'def h():\n'
              '    n = request.args.get("n")\n'
              '    subprocess.run("ping " + n, shell=True)\n'
              '    cur.execute(f"SELECT * FROM t WHERE n = \'{n}\'")\n'
              'KEY = "AKIA4XQ7ZM2NPBWLKC3D"\n')
        cls.report = scanner.scan([tmp])
        cls.provider = NewsProvider(offline=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmpdir.cleanup()

    def test_scan_found_issues(self):
        self.assertGreaterEqual(len(self.report.findings), 3)

    def test_json_is_valid_and_complete(self):
        data = json.loads(report_mod.render_json(self.report, self.provider))
        self.assertIn("findings", data)
        self.assertIn("vulnerability_classes", data)
        for f in data["findings"]:
            for key in ("impact", "exploitability", "prevalence", "risk_score",
                        "severity", "cwe", "news", "remediation"):
                self.assertIn(key, f)
        for vc in data["vulnerability_classes"].values():
            self.assertIn("note", vc["impact"])
            self.assertIn("note", vc["exploitability"])
            self.assertIn("note", vc["prevalence"])

    def test_sarif_is_valid(self):
        doc = json.loads(report_mod.render_sarif(self.report, self.provider))
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertTrue(run["tool"]["driver"]["rules"])
        self.assertTrue(run["results"])
        rule_ids_present = {r["id"] for r in run["tool"]["driver"]["rules"]}
        for res in run["results"]:
            self.assertIn(res["ruleId"], rule_ids_present)
            self.assertIn(res["level"], ("error", "warning", "note"))
            self.assertGreaterEqual(res["locations"][0]["physicalLocation"]["region"]["startLine"], 1)

    def test_markdown_contains_all_four_axes(self):
        md = report_mod.render_markdown(self.report, self.provider)
        self.assertIn("Consequences if exploited", md)
        self.assertIn("Ease of exploitation", md)
        self.assertIn("How common", md)
        self.assertIn("How to fix", md)

    def test_html_escapes_content(self):
        html = report_mod.render_html(self.report, self.provider)
        self.assertIn("<!doctype html>", html)
        self.assertNotIn("<script>", html.lower())
        self.assertIn("prefers-color-scheme", html)

    def test_terminal_renders_without_error(self):
        import io
        buf = io.StringIO()
        report_mod.render_terminal(self.report, self.provider, stream=buf, color=False)
        text = buf.getvalue()
        self.assertIn("SECURITY", text.replace(" ", "")[:400].upper())
        self.assertIn("IF EXPLOITED", text)
        self.assertIn("EASE OF ATTACK", text)
        self.assertIn("HOW COMMON", text)


# ---------------------------------------------------------------------------
class TestNewsProvider(unittest.TestCase):

    def test_offline_provider_serves_curated_items(self):
        p = NewsProvider(offline=True)
        items = p.items_for(knowledge.get("sql-injection"))
        self.assertTrue(items)
        self.assertIn("MOVEit", " ".join(i.headline for i in items))

    def test_offline_provider_makes_no_network_call(self):
        p = NewsProvider(offline=True)
        self.assertIsNone(p.signal(knowledge.get("sql-injection")))
        self.assertIn("offline", p.status)

    def test_provenance_is_disclosed(self):
        p = NewsProvider(offline=True)
        self.assertIn("curated", p.provenance())


# ---------------------------------------------------------------------------
class TestCLI(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmpdir.name)
        write(self.tmp, "bad.py",
              'import subprocess\nsubprocess.run("ls " + x, shell=True)\n')

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_exit_zero_without_fail_on(self):
        out = self.tmp / "r.json"
        code = cli.main([str(self.tmp), "--offline", "--format", "json", "-o", str(out)])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out.read_text())["findings"])

    def test_fail_on_returns_one(self):
        code = cli.main([str(self.tmp), "--offline", "--format", "json",
                         "-o", str(self.tmp / "r.json"), "--fail-on", "high"])
        self.assertEqual(code, 1)

    def test_min_severity_filters(self):
        out = self.tmp / "r.json"
        cli.main([str(self.tmp), "--offline", "--format", "json", "-o", str(out),
                  "--min-severity", "critical"])
        crit = json.loads(out.read_text())["findings"]
        self.assertTrue(all(f["severity"] == "critical" for f in crit))

    def test_only_and_ignore_selectors(self):
        out = self.tmp / "r.json"
        cli.main([str(self.tmp), "--offline", "--format", "json", "-o", str(out),
                  "--ignore", "command-injection"])
        data = json.loads(out.read_text())
        self.assertFalse([f for f in data["findings"] if f["vuln_class"] == "command-injection"])

    def test_baseline_round_trip(self):
        base = self.tmp / "baseline.json"
        self.assertEqual(cli.main([str(self.tmp), "--offline", "--write-baseline", str(base)]), 0)
        out = self.tmp / "r.json"
        cli.main([str(self.tmp), "--offline", "--format", "json", "-o", str(out),
                  "--baseline", str(base)])
        self.assertEqual(json.loads(out.read_text())["findings"], [],
                         "baselined findings should be suppressed")

    def test_new_finding_survives_baseline(self):
        base = self.tmp / "baseline.json"
        cli.main([str(self.tmp), "--offline", "--write-baseline", str(base)])
        write(self.tmp, "worse.py", 'import pickle\npickle.loads(data)\n')
        out = self.tmp / "r.json"
        cli.main([str(self.tmp), "--offline", "--format", "json", "-o", str(out),
                  "--baseline", str(base)])
        found = json.loads(out.read_text())["findings"]
        self.assertTrue(any(f["vuln_class"] == "deserialization" for f in found))

    def test_missing_path_is_an_error(self):
        self.assertEqual(cli.main(["/no/such/path/xyz", "--offline"]), 2)

    def test_explain_known_class(self):
        self.assertEqual(cli.main(["--explain", "ssrf", "--offline"]), 0)

    def test_explain_unknown_class(self):
        self.assertEqual(cli.main(["--explain", "definitely-not-a-class", "--offline"]), 2)

    def test_list_modes(self):
        self.assertEqual(cli.main(["--list-classes"]), 0)
        self.assertEqual(cli.main(["--list-rules"]), 0)


# ---------------------------------------------------------------------------
class TestDiscovery(unittest.TestCase):

    def test_default_excludes_are_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write(tmp, "node_modules/lib/x.js", "eval(a);")
            write(tmp, ".venv/lib/y.py", "eval(a)")
            write(tmp, "src/ok.py", "eval(a)")
            found = {p.name for p, _ in scanner.discover([tmp])}
            self.assertIn("ok.py", found)
            self.assertNotIn("x.js", found)
            self.assertNotIn("y.py", found)

    def test_gitignore_is_respected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            write(tmp, ".gitignore", "generated/\n*.gen.py\n")
            write(tmp, "generated/a.py", "eval(a)")
            write(tmp, "b.gen.py", "eval(a)")
            write(tmp, "c.py", "eval(a)")
            found = {p.name for p, _ in scanner.discover([tmp])}
            self.assertEqual(found, {"c.py"})

    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            p = tmp / "x.py"
            p.write_bytes(b"import os\x00\x01\x02 eval(x)")
            res = scanner.scan_file(p, "python", tmp)
            self.assertEqual(res.findings, [])
            self.assertIn("binary", res.error or "")

    def test_unparseable_python_still_gets_regex_coverage(self):
        f = scan_source('def broken(:\n    eval(x)\n')
        self.assertIn("code-injection", classes(f))


# ---------------------------------------------------------------------------
class TestDemoApp(unittest.TestCase):
    """The shipped demo app must keep exercising a broad set of rules."""

    def test_demo_app_findings(self):
        demo = Path(__file__).resolve().parents[1] / "demo" / "vulnerable_shop"
        if not demo.is_dir():
            self.skipTest("demo app not present")
        rep = scanner.scan([demo], test_heuristic=False)
        found = {f.vuln_class for f in rep.findings}
        for expected in ("sql-injection", "command-injection", "path-traversal",
                         "deserialization", "ssrf", "xss", "hardcoded-secret",
                         "weak-crypto", "jwt-verification", "template-injection",
                         "buffer-overflow", "open-redirect", "debug-exposure"):
            self.assertIn(expected, found, f"demo app should trigger {expected}")
        self.assertGreaterEqual(rep.counts()["critical"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
