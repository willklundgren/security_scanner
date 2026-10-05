"""MCP server exposing secscan to agents.

Run over stdio:  python -m secscan.mcp_server   (needs the optional extra: pip install 'secscan[mcp]')

The tools are designed for a lead agent that fans work out to verifier subagents:

  scan_path       compact, paginated list of findings, each carrying a fingerprint
  get_finding     one finding in full, plus the code around it, looked up by fingerprint
  explain_class   the four-axis briefing for a vulnerability class
  record_verdict  a verifier's call on one finding, stored in <root>/.secscan-triage.json
  triage_summary  every verdict recorded so far

Subagents share no conversation, so the fingerprint is the handle passed between them. It
is a hash of rule, file and normalised code (see Finding.fingerprint), so it survives line
drift between the scan and the lookup. get_finding rescans a single file rather than
relying on server-side state, so any agent can call it at any time.

The functions below are plain Python and importable without the MCP SDK; main() registers
them. Everything runs locally: no code, paths or findings leave the machine.
"""

from __future__ import annotations

import ast
import functools
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List, Optional

from . import cli, scanner
from .news import NewsProvider
from .scanner import SEVERITY_ORDER

TRIAGE_FILE = ".secscan-triage.json"
VERDICTS = ("confirmed", "false_positive", "needs_review")
_FINGERPRINT = re.compile(r"^[0-9a-f]{16}$")
_MAX_FUNCTION_LINES = 120


class ToolError(ValueError):
    """Bad tool input. The message is shown to the calling agent so it can retry."""


def _root(root: str) -> Path:
    p = Path(root).expanduser().resolve()
    if not p.exists():
        raise ToolError(f"path not found: {root}")
    return p.parent if p.is_file() else p


def _compact(f: scanner.Finding) -> Dict[str, object]:
    return {
        "fingerprint": f.fingerprint(),
        "rule_id": f.rule_id,
        "vuln_class": f.vuln_class,
        "severity": f.severity,
        "risk": f.risk_score,
        "confidence": f.confidence,
        "location": f"{f.path}:{f.line}",
        "tainted": f.tainted,
        "message": f.message,
    }


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

def scan_path(path: str, min_severity: str = "info", min_confidence: str = "low",
              only: str = "", baseline: str = "", include_tests: bool = True,
              test_heuristic: bool = True, limit: int = 50, offset: int = 0) -> Dict[str, object]:
    """Scan a file or directory and return a compact, paginated list of findings.

    Each finding carries a `fingerprint`; pass it with `root` and the file path to
    get_finding for full detail. `only` is a comma-separated list of vulnerability
    classes or rule ids. `baseline` is a path to a secscan baseline file whose findings
    are hidden. Set test_heuristic=False when production code lives under paths that
    look like tests or examples. Findings are sorted most severe first.
    """
    target = Path(path).expanduser()
    if not target.exists():
        raise ToolError(f"path not found: {path}")
    if min_severity not in SEVERITY_ORDER:
        raise ToolError(f"min_severity must be one of {', '.join(SEVERITY_ORDER)}")
    if min_confidence not in ("high", "medium", "low"):
        raise ToolError("min_confidence must be one of high, medium, low")

    report = scanner.scan([target], include_tests=include_tests, test_heuristic=test_heuristic)
    filters = SimpleNamespace(only=only, ignore="", min_severity=min_severity,
                              min_confidence=min_confidence)
    accepted = cli.load_baseline(baseline) if baseline else set()
    findings = cli.apply_filters(report.findings, filters, accepted)

    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    page = findings[offset:offset + limit]
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] += 1
    return {
        "root": report.root,
        "files_scanned": report.files_scanned,
        "total": len(findings),
        "counts": counts,
        "offset": offset,
        "next_offset": offset + len(page) if offset + len(page) < len(findings) else None,
        "findings": [_compact(f) for f in page],
    }


def get_finding(root: str, path: str, fingerprint: str, context_lines: int = 15,
                test_heuristic: bool = True) -> Dict[str, object]:
    """Return one finding in full: its four-axis scores and notes, remediation, the
    surrounding source lines, and (for Python) the enclosing function's source.

    `root` is the directory that was scanned (scan_path returns it), `path` is the
    finding's file relative to root (the part of `location` before the colon), and
    `fingerprint` comes from scan_path.
    """
    if not _FINGERPRINT.match(fingerprint):
        raise ToolError("fingerprint must be 16 lowercase hex characters, as returned by scan_path")
    base = _root(root)
    file = (base / path).resolve()
    # The agent supplies both parts; keep lookups inside the scanned tree.
    if base != file and base not in file.parents:
        raise ToolError(f"{path} is outside {base}")
    if not file.is_file():
        raise ToolError(f"file not found: {path}")
    lang = scanner.detect_language(file)
    if lang is None:
        raise ToolError(f"secscan does not scan this file type: {path}")

    result = scanner.scan_file(file, lang, base, test_heuristic=test_heuristic)
    match = next((f for f in result.findings if f.fingerprint() == fingerprint), None)
    if match is None:
        raise ToolError(f"no finding {fingerprint} in {path}; the code may have changed, "
                        "so re-run scan_path")

    detail = match.to_dict()
    detail.pop("news", None)  # explain_class carries the news; keep this payload small
    lines = file.read_text(encoding="utf-8", errors="replace").splitlines()
    ctx = max(0, min(context_lines, 60))
    start, end = max(1, match.line - ctx), min(len(lines), match.line + ctx)
    detail["context"] = {
        "start_line": start,
        "end_line": end,
        "source": "\n".join(f"{n:>5}{'>' if n == match.line else ' '} {lines[n - 1]}"
                            for n in range(start, end + 1)),
    }
    if lang == "python":
        detail["enclosing_function"] = _enclosing_function(lines, match.line)
    return detail


def explain_class(key: str, offline: bool = True) -> Dict[str, object]:
    """The briefing for one vulnerability class (e.g. 'sql-injection', or a unique part of
    its name): impact, exploitability and prevalence with reasoning, remediation,
    references and recent incidents. offline=False adds live CISA KEV data (only the
    CWE id is sent to the feed)."""
    vc, matches = cli.resolve_class(key)
    if vc is None:
        hint = f" Did you mean: {', '.join(matches)}?" if matches else ""
        raise ToolError(f"unknown vulnerability class '{key}'.{hint}")
    provider = NewsProvider(offline=offline)
    return {
        "key": vc.key,
        "title": vc.title,
        "cwe": vc.cwe,
        "owasp": vc.owasp,
        "cwe_top25_rank_2024": vc.cwe_top25_rank,
        "impact": {"score": vc.impact, "note": vc.impact_note},
        "exploitability": {"score": vc.exploitability, "note": vc.exploitability_note},
        "prevalence": {"score": vc.prevalence, "note": vc.prevalence_note},
        "taint_driven": vc.taint_driven,
        "remediation": vc.remediation,
        "references": list(vc.references),
        "in_the_news": provider.headline_stat(vc),
        "news": [{"date": i.date, "headline": i.headline, "summary": i.summary, "url": i.url}
                 for i in provider.items_for(vc, limit=4)],
        "news_provenance": provider.provenance(),
    }


def record_verdict(root: str, fingerprint: str, verdict: str, reason: str,
                   path: str = "") -> Dict[str, object]:
    """Record a verifier's verdict on one finding in <root>/.secscan-triage.json.

    verdict is one of: confirmed, false_positive, needs_review. `reason` should cite
    file:line evidence. Recording again for the same fingerprint replaces the old verdict.
    """
    if not _FINGERPRINT.match(fingerprint):
        raise ToolError("fingerprint must be 16 lowercase hex characters, as returned by scan_path")
    if verdict not in VERDICTS:
        raise ToolError(f"verdict must be one of {', '.join(VERDICTS)}")
    if not reason.strip():
        raise ToolError("reason is required: say why, with file:line evidence")

    file = _root(root) / TRIAGE_FILE
    data = _load_triage(file)
    data["verdicts"][fingerprint] = {
        "verdict": verdict,
        "reason": reason.strip(),
        "path": path,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    file.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return {"recorded": fingerprint, "verdict": verdict, "file": str(file)}


def triage_summary(root: str) -> Dict[str, object]:
    """Every verdict recorded under root so far, with counts per verdict."""
    file = _root(root) / TRIAGE_FILE
    data = _load_triage(file)
    counts = {v: 0 for v in VERDICTS}
    for entry in data["verdicts"].values():
        counts[entry["verdict"]] = counts.get(entry["verdict"], 0) + 1
    return {"file": str(file), "counts": counts, "verdicts": data["verdicts"]}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_triage(file: Path) -> Dict[str, object]:
    if file.exists():
        try:
            data = json.loads(file.read_text())
            if isinstance(data.get("verdicts"), dict):
                return data
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        raise ToolError(f"{file} exists but is not a secscan triage file; move it aside")
    return {
        "schema": "secscan-triage/1.0",
        "note": "Agent verdicts on secscan findings, keyed by fingerprint.",
        "verdicts": {},
    }


def _enclosing_function(lines: List[str], line: int) -> Optional[Dict[str, object]]:
    """Innermost def containing `line`, or None at module level or on a parse error."""
    try:
        tree = ast.parse("\n".join(lines))
    except SyntaxError:
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= line <= end and (best is None or node.lineno > best.lineno):
                best = node
    if best is None:
        return None
    start = min([best.lineno] + [d.lineno for d in best.decorator_list])
    end = best.end_lineno or best.lineno
    truncated = end - start + 1 > _MAX_FUNCTION_LINES
    end = min(end, start + _MAX_FUNCTION_LINES - 1)
    return {
        "name": best.name,
        "start_line": start,
        "end_line": end,
        "truncated": truncated,
        "source": "\n".join(lines[start - 1:end]),
    }


TOOLS = (scan_path, get_finding, explain_class, record_verdict, triage_summary)
INSTRUCTIONS = (
    "secscan finds security flaws statically and explains each one. Call scan_path first; "
    "pass each finding's fingerprint, the scan root and its file path to get_finding for "
    "detail. Verifiers record one verdict per finding with record_verdict."
)


def _reporting_errors(fn, sdk_error):
    """Re-raise ToolError as the SDK's ToolError: the SDK only shows the agent the text of
    its own error type, and these messages tell the agent how to correct its call."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ToolError as exc:
            raise sdk_error(str(exc)) from exc
    return wrapper


def build_server():
    try:
        from mcp.server.mcpserver import MCPServer
        from mcp.server.mcpserver.exceptions import ToolError as SdkToolError
        from mcp.types import ToolAnnotations
    except ImportError:
        raise SystemExit("secscan: the MCP server needs the optional extra: "
                         "pip install 'secscan[mcp]' (Python 3.10+, mcp 2.x)")
    server = MCPServer("secscan", instructions=INSTRUCTIONS)
    for fn in TOOLS:
        server.add_tool(
            _reporting_errors(fn, SdkToolError),
            annotations=ToolAnnotations(
                read_only_hint=fn is not record_verdict,
                idempotent_hint=True,
                open_world_hint=fn is explain_class,  # only with offline=False
            ),
        )
    return server


def main() -> None:
    build_server().run()  # stdio


if __name__ == "__main__":
    main()
