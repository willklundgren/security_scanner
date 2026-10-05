"""Tests for the MCP tool functions. They run without the MCP SDK installed."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from secscan import mcp_server as srv

DEMO = ROOT / "demo" / "vulnerable_shop"


class TestScanPath(unittest.TestCase):

    def test_demo_totals_match_cli(self):
        out = srv.scan_path(str(DEMO), test_heuristic=False)
        self.assertEqual(out["total"], 38)
        self.assertEqual(sum(out["counts"].values()), 38)
        self.assertEqual(out["root"], str(DEMO.resolve()))

    def test_pagination(self):
        first = srv.scan_path(str(DEMO), test_heuristic=False, limit=10)
        self.assertEqual(len(first["findings"]), 10)
        self.assertEqual(first["next_offset"], 10)
        last = srv.scan_path(str(DEMO), test_heuristic=False, limit=10, offset=30)
        self.assertEqual(len(last["findings"]), 8)
        self.assertIsNone(last["next_offset"])

    def test_rows_are_compact(self):
        row = srv.scan_path(str(DEMO), test_heuristic=False, limit=1)["findings"][0]
        self.assertEqual(set(row), {"fingerprint", "rule_id", "vuln_class", "severity", "risk",
                                    "confidence", "location", "tainted", "message"})
        self.assertEqual(row["severity"], "critical")  # sorted most severe first

    def test_filters(self):
        out = srv.scan_path(str(DEMO), test_heuristic=False, only="sql-injection")
        self.assertGreater(out["total"], 0)
        self.assertTrue(all(f["vuln_class"] == "sql-injection" for f in out["findings"]))
        high = srv.scan_path(str(DEMO), test_heuristic=False, min_severity="high")
        self.assertTrue(all(f["severity"] in ("critical", "high") for f in high["findings"]))

    def test_bad_input(self):
        with self.assertRaises(srv.ToolError):
            srv.scan_path(str(DEMO / "missing"))
        with self.assertRaises(srv.ToolError):
            srv.scan_path(str(DEMO), min_severity="urgent")


class TestGetFinding(unittest.TestCase):

    def setUp(self):
        out = srv.scan_path(str(DEMO), test_heuristic=False, only="sql-injection", limit=1)
        self.row = out["findings"][0]
        self.root = out["root"]
        self.path, line = self.row["location"].rsplit(":", 1)
        self.line = int(line)

    def test_round_trip_by_fingerprint(self):
        d = srv.get_finding(self.root, self.path, self.row["fingerprint"], test_heuristic=False)
        self.assertEqual(d["fingerprint"], self.row["fingerprint"])
        self.assertEqual(d["line"], self.line)
        self.assertIn("remediation", d)
        self.assertNotIn("news", d)
        self.assertIn(f"{self.line:>5}>", d["context"]["source"])

    def test_python_finding_includes_enclosing_function(self):
        d = srv.get_finding(self.root, self.path, self.row["fingerprint"], test_heuristic=False)
        fn = d["enclosing_function"]
        self.assertIsNotNone(fn)
        self.assertTrue(fn["start_line"] <= self.line <= fn["end_line"])
        self.assertIn(f"def {fn['name']}", fn["source"])

    def test_unknown_fingerprint(self):
        with self.assertRaises(srv.ToolError):
            srv.get_finding(self.root, self.path, "0" * 16)
        with self.assertRaises(srv.ToolError):
            srv.get_finding(self.root, self.path, "not-a-fingerprint")

    def test_path_must_stay_inside_root(self):
        with self.assertRaises(srv.ToolError):
            srv.get_finding(self.root, "../../secscan/cli.py", self.row["fingerprint"])


class TestExplainClass(unittest.TestCase):

    def test_exact_and_fuzzy(self):
        d = srv.explain_class("sql-injection")
        self.assertEqual(d["cwe"].split(":")[0], "CWE-89")
        self.assertEqual(set(d["impact"]), {"score", "note"})
        self.assertEqual(srv.explain_class("SSRF")["key"], "ssrf")  # case-insensitive match

    def test_unknown(self):
        with self.assertRaises(srv.ToolError):
            srv.explain_class("no-such-class")


class TestVerdicts(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_record_upsert_and_summary(self):
        fp = "a" * 16
        srv.record_verdict(str(self.tmp), fp, "needs_review", "unclear", path="app.py")
        srv.record_verdict(str(self.tmp), fp, "confirmed", "request.args reaches execute at app.py:9")
        srv.record_verdict(str(self.tmp), "b" * 16, "false_positive", "constant input, app.py:3")
        summary = srv.triage_summary(str(self.tmp))
        self.assertEqual(summary["counts"], {"confirmed": 1, "false_positive": 1, "needs_review": 0})
        self.assertEqual(summary["verdicts"][fp]["verdict"], "confirmed")
        on_disk = json.loads((self.tmp / srv.TRIAGE_FILE).read_text())
        self.assertEqual(on_disk["schema"], "secscan-triage/1.0")

    def test_rejects_bad_input(self):
        with self.assertRaises(srv.ToolError):
            srv.record_verdict(str(self.tmp), "a" * 16, "probably", "x")
        with self.assertRaises(srv.ToolError):
            srv.record_verdict(str(self.tmp), "a" * 16, "confirmed", "  ")
        with self.assertRaises(srv.ToolError):
            srv.record_verdict(str(self.tmp), "xyz", "confirmed", "x")

    def test_refuses_to_clobber_foreign_file(self):
        (self.tmp / srv.TRIAGE_FILE).write_text("[1, 2, 3]")
        with self.assertRaises(srv.ToolError):
            srv.record_verdict(str(self.tmp), "a" * 16, "confirmed", "x")

    def test_empty_summary(self):
        self.assertEqual(srv.triage_summary(str(self.tmp))["verdicts"], {})


@unittest.skipUnless(importlib.util.find_spec("mcp"), "MCP SDK not installed")
class TestServerRegistration(unittest.TestCase):

    def test_all_tools_registered(self):
        import asyncio
        tools = asyncio.run(srv.build_server().list_tools())
        self.assertEqual({t.name for t in tools}, {fn.__name__ for fn in srv.TOOLS})


if __name__ == "__main__":
    unittest.main()
