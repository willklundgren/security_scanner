"""Command-line interface for secscan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

from . import knowledge, report as report_mod, scanner
from .knowledge import VULN_CLASSES
from .news import NewsProvider
from .rules import RULES, SECRET_PATTERNS
from .scanner import SEVERITY_ORDER, Finding, ScanReport

VERSION = "1.0.0"

EPILOG = """\
examples:
  secscan .                             scan the current directory
  secscan src/ --min-severity high      only high and critical findings
  secscan . --format html -o report.html
  secscan . --format sarif -o out.sarif --fail-on high     (CI gate)
  secscan . --only sql-injection,command-injection
  secscan --explain ssrf                read the briefing for one class
  secscan . --write-baseline .secscan-baseline.json        (accept today's findings)
  secscan . --baseline .secscan-baseline.json              (report only what's new)

exit codes:
  0  no findings at or above --fail-on          1  findings at or above --fail-on
  2  usage or runtime error
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secscan",
        description="Scan a codebase for security vulnerabilities and explain, for each one, "
                    "what it would cost you, how easily it could be exploited, how common it is, "
                    "and what it has been doing in the news.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", default=["."],
                   help="files or directories to scan (default: current directory)")

    out = p.add_argument_group("output")
    out.add_argument("-f", "--format", default="text",
                     choices=["text", "json", "markdown", "md", "html", "sarif"],
                     help="output format (default: text)")
    out.add_argument("-o", "--output", metavar="FILE",
                     help="write the report to FILE instead of stdout")
    out.add_argument("--detail", choices=["auto", "full", "compact"], default="auto",
                     help="text format: how much explanation to print per finding "
                          "(auto = full for the first finding of each type)")
    out.add_argument("--max-findings", type=int, default=40, metavar="N",
                     help="text format: cap findings printed; 0 means no cap (default: 40)")
    out.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    out.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    out.add_argument("-v", "--verbose", action="store_true", help="list files that failed to parse")

    filt = p.add_argument_group("filtering")
    filt.add_argument("--min-severity", default="info",
                      choices=["critical", "high", "medium", "low", "info"],
                      help="hide findings below this severity (default: info)")
    filt.add_argument("--min-confidence", default="low", choices=["high", "medium", "low"],
                      help="hide findings below this confidence (default: low)")
    filt.add_argument("--only", metavar="LIST",
                      help="comma-separated vulnerability classes or rule ids to include")
    filt.add_argument("--ignore", metavar="LIST",
                      help="comma-separated vulnerability classes or rule ids to exclude")
    filt.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="path glob to skip (repeatable)")
    filt.add_argument("--no-gitignore", action="store_true",
                      help="do not read .gitignore patterns")
    filt.add_argument("--no-secrets", action="store_true",
                      help="skip hardcoded-secret detection")
    filt.add_argument("--skip-tests", action="store_true",
                      help="drop findings in test/fixture/example paths entirely")
    filt.add_argument("--no-test-heuristic", action="store_true",
                      help="do not downgrade findings just because the path looks like "
                           "tests/fixtures/examples (use when such paths ship to production)")
    filt.add_argument("--max-file-size", type=int, default=2_000_000, metavar="BYTES",
                      help="skip files larger than this (default: 2000000)")

    nw = p.add_argument_group("news enrichment")
    nw.add_argument("--offline", action="store_true",
                    help="never touch the network; use the curated dataset only")
    nw.add_argument("--refresh-news", action="store_true",
                    help="force a refresh of the cached CISA KEV catalog")
    nw.add_argument("--no-news", action="store_true",
                    help="omit the news section from text output")
    nw.add_argument("--nvd", action="store_true",
                    help="also query the NVD API for recent CVE volume per weakness type")
    nw.add_argument("--news-days", type=int, default=365, metavar="N",
                    help="window for 'recently added to CISA KEV' (default: 365)")

    ci = p.add_argument_group("CI integration")
    ci.add_argument("--fail-on", default=None,
                    choices=["critical", "high", "medium", "low", "info", "never"],
                    help="exit 1 if any finding is at or above this severity")
    ci.add_argument("--baseline", metavar="FILE",
                    help="suppress findings recorded in this baseline file")
    ci.add_argument("--write-baseline", metavar="FILE",
                    help="write current findings to FILE as an accepted baseline and exit 0")

    info = p.add_argument_group("information")
    info.add_argument("--list-rules", action="store_true", help="list all detection rules and exit")
    info.add_argument("--list-classes", action="store_true",
                      help="list all vulnerability classes and their scores, then exit")
    info.add_argument("--explain", metavar="CLASS",
                      help="print the full briefing for one vulnerability class and exit")
    info.add_argument("--version", action="version", version=f"secscan {VERSION}")
    return p


# ---------------------------------------------------------------------------
# Informational modes
# ---------------------------------------------------------------------------

def cmd_list_rules() -> int:
    by_class: dict = {}
    for r in RULES:
        by_class.setdefault(r.vuln_class, []).append(r)
    from .pyast import AST_CHECKS
    print(f"\n{len(RULES)} pattern rules + {len(SECRET_PATTERNS)} secret patterns "
          f"+ {len(AST_CHECKS)} Python AST checks\n")
    for key in sorted(by_class):
        vc = knowledge.get(key)
        print(f"{vc.title}  ({vc.cwe})")
        for r in sorted(by_class[key], key=lambda x: x.id):
            langs = "any" if "*" in r.languages else ",".join(r.languages)
            print(f"  {r.id:<16} {r.confidence:<7} [{langs}]  {r.name}")
        print()
    print("secret patterns")
    for s in SECRET_PATTERNS:
        print(f"  {s.id:<16} {s.confidence:<7} {s.name}")
    print()
    return 0


def cmd_list_classes() -> int:
    print(f"\n{'class':<26}{'CWE':<10}{'impact':>7}{'ease':>6}{'common':>8}   title")
    print("─" * 92)
    for vc in sorted(knowledge.all_classes(), key=lambda v: -(v.impact + v.exploitability + v.prevalence)):
        print(f"{vc.key:<26}{vc.cwe:<10}{vc.impact:>5}/5{vc.exploitability:>4}/5"
              f"{vc.prevalence:>6}/5   {vc.title}")
    print("\nUse --explain <class> for the full briefing.\n")
    return 0


def resolve_class(key: str) -> Tuple[Optional[knowledge.VulnClass], List[str]]:
    """Exact key, else a unique substring match on key or title. Returns (class, candidates)."""
    vc = VULN_CLASSES.get(key)
    if vc is not None:
        return vc, [key]
    matches = [k for k in VULN_CLASSES if key.lower() in k or key.lower() in VULN_CLASSES[k].title.lower()]
    if len(matches) == 1:
        return VULN_CLASSES[matches[0]], matches
    return None, matches


def cmd_explain(key: str, provider: NewsProvider) -> int:
    vc, matches = resolve_class(key)
    if vc is None:
        print(f"Unknown class '{key}'."
              + (f" Did you mean: {', '.join(matches)}?" if matches else ""), file=sys.stderr)
        print("Run --list-classes to see them all.", file=sys.stderr)
        return 2

    import textwrap
    w = report_mod.term_width()

    def block(label: str, value: Optional[int], text: str) -> None:
        head = f"{label}" + (f"  {report_mod.bar(value)} {value}/5" if value is not None else "")
        print(f"\n  {head}")
        for line in textwrap.wrap(text, width=w - 6):
            print(f"    {line}")

    print(f"\n  {vc.title}   [{vc.key}]")
    print(f"  {vc.cwe} · {vc.owasp}" + (f" · 2024 CWE Top 25 rank #{vc.cwe_top25_rank}"
                                        if vc.cwe_top25_rank else ""))
    block("CONSEQUENCES IF EXPLOITED", vc.impact, vc.impact_note)
    block("EASE OF EXPLOITATION", vc.exploitability, vc.exploitability_note)
    block("HOW COMMON", vc.prevalence, vc.prevalence_note)

    stat = provider.headline_stat(vc)
    items = provider.items_for(vc, limit=4)
    if stat or items:
        print("\n  IN THE NEWS")
        if stat:
            for line in textwrap.wrap(stat + ".", width=w - 6):
                print(f"    {line}")
            print()
        for i in items:
            print(f"    {i.date}  {i.headline}")
            for line in textwrap.wrap(i.summary, width=w - 10):
                print(f"      {line}")
            print(f"      {i.source} — {i.url}\n")
    block("HOW TO FIX", None, vc.remediation)
    if vc.references:
        print("\n  REFERENCES")
        for r in vc.references:
            print(f"    {r}")
    print(f"\n  {provider.provenance()}\n")
    return 0


# ---------------------------------------------------------------------------
# Filtering / baseline
# ---------------------------------------------------------------------------

def parse_list(value: Optional[str]) -> Set[str]:
    if not value:
        return set()
    return {v.strip().lower() for v in value.split(",") if v.strip()}


def matches_selector(f: Finding, selectors: Set[str]) -> bool:
    return f.vuln_class.lower() in selectors or f.rule_id.lower() in selectors


def apply_filters(findings: List[Finding], args: argparse.Namespace,
                  baseline: Set[str]) -> List[Finding]:
    only = parse_list(args.only)
    ignore = parse_list(args.ignore)
    min_sev = SEVERITY_ORDER[args.min_severity]
    conf_order = {"low": 0, "medium": 1, "high": 2}
    min_conf = conf_order[args.min_confidence]

    out: List[Finding] = []
    for f in findings:
        if only and not matches_selector(f, only):
            continue
        if ignore and matches_selector(f, ignore):
            continue
        if SEVERITY_ORDER[f.severity] < min_sev:
            continue
        if conf_order[f.confidence] < min_conf:
            continue
        if baseline and f.fingerprint() in baseline:
            continue
        out.append(f)
    return out


def load_baseline(path: str) -> Set[str]:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"secscan: could not read baseline {path}: {exc}", file=sys.stderr)
        return set()
    return set(data.get("fingerprints", []))


def write_baseline(path: str, findings: Sequence[Finding]) -> None:
    from datetime import datetime, timezone
    payload = {
        "schema": "secscan-baseline/1.0",
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Findings accepted as known. Delete an entry to surface it again.",
        "fingerprints": sorted({f.fingerprint() for f in findings}),
        "detail": sorted({f"{f.fingerprint()}  {f.rule_id}  {f.path}:{f.line}" for f in findings}),
    }
    Path(path).write_text(json.dumps(payload, indent=2))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        return cmd_list_rules()
    if args.list_classes:
        return cmd_list_classes()

    provider = NewsProvider(
        offline=args.offline,
        refresh=args.refresh_news,
        window_days=args.news_days,
        use_nvd=args.nvd,
    )

    if args.explain:
        return cmd_explain(args.explain, provider)

    roots = [Path(p) for p in (args.paths or ["."])]
    missing = [str(p) for p in roots if not p.exists()]
    if missing:
        print(f"secscan: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    show_progress = not args.quiet and args.format == "text" and sys.stderr.isatty()

    def progress(done: int, total: int, path: Path) -> None:
        if show_progress:
            name = str(path)[-50:]
            sys.stderr.write(f"\r\033[2K  scanning {done}/{total}  {name}")
            sys.stderr.flush()

    try:
        result = scanner.scan(
            roots,
            excludes=args.exclude,
            use_gitignore=not args.no_gitignore,
            include_secrets=not args.no_secrets,
            include_tests=not args.skip_tests,
            max_bytes=args.max_file_size,
            test_heuristic=not args.no_test_heuristic,
            progress=progress if show_progress else None,
        )
    except KeyboardInterrupt:
        print("\nsecscan: interrupted", file=sys.stderr)
        return 2
    if show_progress:
        sys.stderr.write("\r\033[2K")
        sys.stderr.flush()

    if args.write_baseline:
        write_baseline(args.write_baseline, result.findings)
        print(f"secscan: wrote baseline with {len(result.findings)} accepted findings "
              f"to {args.write_baseline}")
        return 0

    baseline = load_baseline(args.baseline) if args.baseline else set()
    filtered = apply_filters(result.findings, args, baseline)
    shown = ScanReport(
        root=result.root, findings=filtered, files_scanned=result.files_scanned,
        lines_scanned=result.lines_scanned, errors=result.errors,
        duration_s=result.duration_s, languages=result.languages,
    )

    fmt = args.format
    if fmt == "text":
        cap = None if args.max_findings == 0 else args.max_findings
        stream = sys.stdout
        if args.output:
            stream = open(args.output, "w", encoding="utf-8")
        try:
            report_mod.render_terminal(
                shown, provider, stream=stream,
                color=False if (args.no_color or args.output) else None,
                detail=args.detail, max_findings=cap, show_news=not args.no_news,
            )
        finally:
            if args.output:
                stream.close()
                print(f"secscan: wrote {args.output}")
    else:
        text = report_mod.RENDERERS[fmt](shown, provider)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            print(f"secscan: wrote {args.output} "
                  f"({len(filtered)} findings, {fmt})")
        else:
            print(text)

    if args.verbose and result.errors:
        print("\nfiles with parse problems:", file=sys.stderr)
        for path, err in result.errors:
            print(f"  {path}: {err}", file=sys.stderr)

    if args.fail_on and args.fail_on != "never":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold for f in filtered):
            return 1
    return 0


def entrypoint() -> None:
    sys.exit(main())
