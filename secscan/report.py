"""Report rendering: terminal, Markdown, HTML, JSON and SARIF."""

from __future__ import annotations

import html as html_mod
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, TextIO

from . import knowledge
from .knowledge import CURATED_AS_OF, VulnClass
from .news import NewsProvider
from .scanner import Finding, ScanReport

SEVERITY_COLORS = {
    "critical": "\033[97;41m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
    "info": "\033[90m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
GREEN = "\033[32m"
GREY = "\033[90m"

SEVERITY_LABEL = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}


class Style:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET


def use_color(force: Optional[bool], stream: TextIO) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR") is not None:
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def bar(value: int, width: int = 5) -> str:
    value = max(0, min(width, value))
    return "█" * value + "·" * (width - value)


def term_width(default: int = 100) -> int:
    try:
        return max(60, min(120, shutil.get_terminal_size().columns))
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def render_terminal(report: ScanReport, provider: NewsProvider,
                    stream: TextIO = sys.stdout, color: Optional[bool] = None,
                    detail: str = "auto", max_findings: Optional[int] = None,
                    show_news: bool = True) -> None:
    s = Style(use_color(color, stream))
    w = term_width()
    out = stream.write

    counts = report.counts()
    total = len(report.findings)

    out("\n" + s("  S E C U R I T Y   S C A N", BOLD, CYAN) + "\n")
    out(s(f"  {report.root}", GREY) + "\n")
    langs = ", ".join(f"{k} ({v})" for k, v in list(report.languages.items())[:6])
    out(s(f"  {report.files_scanned} files · {report.lines_scanned:,} lines · "
          f"{report.duration_s}s · {langs}", GREY) + "\n\n")

    # Severity summary bar
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts[sev]
        if n:
            parts.append(s(f" {SEVERITY_LABEL[sev]} {n} ", SEVERITY_COLORS[sev], BOLD))
        else:
            parts.append(s(f" {SEVERITY_LABEL[sev]} 0 ", DIM))
    out("  " + " ".join(parts) + "\n")

    if not total:
        out("\n  " + s("No issues found by the rules in this build.", GREEN) +
            s(" That is not proof the code is safe - see the coverage note below.\n", GREY))
        _render_footer(out, s, report, provider)
        return

    shown = report.findings if max_findings is None else report.findings[:max_findings]
    seen_classes: Dict[str, int] = {}

    current_sev = None
    idx = 0
    for f in shown:
        idx += 1
        if f.severity != current_sev:
            current_sev = f.severity
            title = f" {SEVERITY_LABEL[current_sev]} "
            line = "─" * max(0, w - len(title) - 6)
            out("\n" + s("  ┌─" + title, SEVERITY_COLORS[current_sev], BOLD) +
                s(line, GREY) + "\n")

        first_of_class = f.vuln_class not in seen_classes
        if first_of_class:
            seen_classes[f.vuln_class] = idx
        full = detail == "full" or (detail == "auto" and first_of_class)
        _render_finding(out, s, f, idx, full, provider, w,
                        first_ref=seen_classes[f.vuln_class], show_news=show_news)

    if max_findings is not None and total > max_findings:
        out("\n  " + s(f"… {total - max_findings} more findings not shown "
                       f"(use --max-findings 0 for all, or --format markdown for a file).", GREY) + "\n")

    _render_class_summary(out, s, report, provider, w)
    _render_footer(out, s, report, provider)


def _render_finding(out, s: Style, f: Finding, idx: int, full: bool,
                    provider: NewsProvider, w: int, first_ref: int,
                    show_news: bool) -> None:
    vc = f.vclass
    sev_tag = s(f"{SEVERITY_LABEL[f.severity]}", SEVERITY_COLORS[f.severity], BOLD)
    head = (f"  {s(f'[{idx}]', BOLD)} {sev_tag} {s(vc.title, BOLD)} "
            f"{s('·', GREY)} {vc.cwe} {s('·', GREY)} risk {f.risk_score}/10")
    out("\n" + head + "\n")

    loc = f"{f.path}:{f.line}"
    flags = [f"rule {f.rule_id}", f"confidence {f.confidence}"]
    if f.tainted:
        flags.append("reachable from local input (caller-controlled)"
                     if f.taint_trust == "local" else "reachable from untrusted input")
    if f.in_test_code:
        flags.append("test/example code")
    out(f"      {s(loc, CYAN)}  {s('(' + ', '.join(flags) + ')', GREY)}\n")
    if f.snippet:
        out(f"      {s('│', GREY)} {s(f.snippet[:w - 10], DIM)}\n")
    out(f"      {f.message}\n")

    if not full:
        out(f"      {s(f'↑ impact/exploitability/prevalence and news shown at [{first_ref}]', GREY)}\n")
        if f.fix_hint:
            out(f"      {s('fix:', GREEN)} {f.fix_hint}\n")
        return

    out("\n")
    _axis(out, s, "IF EXPLOITED", f.impact, vc.impact_note, w)
    _axis(out, s, "EASE OF ATTACK", f.exploitability, f.exploitability_note, w)
    _axis(out, s, "HOW COMMON", f.prevalence, vc.prevalence_note, w)

    if show_news:
        stat = provider.headline_stat(vc)
        items = provider.items_for(vc, limit=2)
        if stat or items:
            out(f"      {s('IN THE NEWS', BOLD)}\n")
            if stat:
                out(_wrap(f"{stat}.", w, indent=22, first_prefix="      " + " " * 16) + "\n")
            for item in items:
                out(f"{' ' * 22}{s(item.date, BOLD)}  {item.headline}\n")
                out(_wrap(item.summary, w, indent=24, first_prefix=" " * 24, dim=s) + "\n")
                out(f"{' ' * 24}{s(item.source + ' — ' + item.url, GREY)}\n")

    fix = vc.remediation + (" " + f.fix_hint if f.fix_hint else "")
    out(f"      {s('HOW TO FIX', GREEN)}\n")
    out(_wrap(fix, w, indent=22, first_prefix=" " * 22) + "\n")
    if vc.references:
        out(f"{' ' * 22}{s(vc.references[0], GREY)}\n")


def _axis(out, s: Style, label: str, value: int, note: str, w: int) -> None:
    out(f"      {s(label.ljust(15), BOLD)} {bar(value)} {value}/5\n")
    out(_wrap(note, w, indent=22, first_prefix=" " * 22) + "\n")


def _wrap(text: str, w: int, indent: int, first_prefix: str = "",
          dim: Optional[Style] = None) -> str:
    import textwrap
    width = max(40, w - indent - 2)
    lines = textwrap.wrap(text, width=width) or [""]
    out_lines = [first_prefix + lines[0]]
    for line in lines[1:]:
        out_lines.append(" " * indent + line)
    body = "\n".join(out_lines)
    return dim(body, GREY) if dim else body


def _render_class_summary(out, s: Style, report: ScanReport,
                          provider: NewsProvider, w: int) -> None:
    by_class = report.by_class()
    if len(by_class) < 2:
        return
    out("\n\n  " + s("SUMMARY BY VULNERABILITY TYPE", BOLD) + "\n")
    out("  " + s("─" * (w - 4), GREY) + "\n")
    hdr = f"  {'type':<34}{'CWE':<10}{'n':>4}{'worst':>8}{'impact':>8}{'ease':>6}{'common':>8}"
    out(s(hdr, GREY) + "\n")
    for key, items in by_class.items():
        vc = knowledge.get(key)
        worst = max(items, key=lambda f: f.risk_score)
        line = (f"  {vc.title[:33]:<34}{vc.cwe:<10}{len(items):>4}"
                f"{worst.risk_score:>8}{worst.impact:>6}/5{worst.exploitability:>4}/5"
                f"{worst.prevalence:>6}/5")
        out(s(line, SEVERITY_COLORS[worst.severity] if worst.severity in ("critical", "high") else "") + "\n")


def _render_footer(out, s: Style, report: ScanReport, provider: NewsProvider) -> None:
    out("\n  " + s("─" * 60, GREY) + "\n")
    out("  " + s(provider.provenance(), GREY) + "\n")
    out("  " + s("Scoring: risk = 0.5·impact + 0.3·exploitability + 0.2·prevalence, scaled to 10.", GREY) + "\n")
    out("  " + s("Coverage: this is static pattern-and-AST analysis. It cannot see runtime "
                 "configuration,", GREY) + "\n")
    out("  " + s("business-logic flaws, authorisation gaps, or vulnerable dependencies. "
                 "A clean scan is not an audit.", GREY) + "\n")
    if report.errors:
        out("  " + s(f"{len(report.errors)} file(s) could not be fully parsed "
                     f"(run with --verbose to list).", GREY) + "\n")
    out("\n")


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(report: ScanReport, provider: NewsProvider) -> str:
    classes: Dict[str, dict] = {}
    for key in {f.vuln_class for f in report.findings}:
        vc = knowledge.get(key)
        sig = provider.signal(vc)
        classes[key] = {
            "title": vc.title,
            "cwe": vc.cwe,
            "owasp": vc.owasp,
            "cwe_top25_rank_2024": vc.cwe_top25_rank,
            "impact": {"score": vc.impact, "note": vc.impact_note},
            "exploitability": {"score": vc.exploitability, "note": vc.exploitability_note},
            "prevalence": {"score": vc.prevalence, "note": vc.prevalence_note},
            "remediation": vc.remediation,
            "references": list(vc.references),
            "news": [
                {"date": i.date, "headline": i.headline, "summary": i.summary,
                 "source": i.source, "url": i.url}
                for i in provider.items_for(vc, limit=4)
            ],
            "live_exploitation_signal": (
                {
                    "cisa_kev_matching_cves": sig.kev_total,
                    "cisa_kev_added_last_%d_days" % sig.window_days: sig.kev_recent,
                    "nvd_cves_last_120_days": sig.nvd_recent_count,
                    "source": sig.source_note,
                } if sig and sig.has_data else None
            ),
        }
    payload = {
        "schema": "secscan/1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": report.root,
        "stats": {
            "files_scanned": report.files_scanned,
            "lines_scanned": report.lines_scanned,
            "duration_seconds": report.duration_s,
            "languages": report.languages,
            "counts_by_severity": report.counts(),
            "total_findings": len(report.findings),
        },
        "news_provenance": provider.provenance(),
        "vulnerability_classes": classes,
        "findings": [f.to_dict() for f in report.findings],
        "parse_errors": [{"path": p, "error": e} for p, e in report.errors],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_markdown(report: ScanReport, provider: NewsProvider) -> str:
    L: List[str] = []
    counts = report.counts()
    L.append(f"# Security scan — `{report.root}`")
    L.append("")
    L.append(f"*{report.files_scanned} files, {report.lines_scanned:,} lines, "
             f"{report.duration_s}s — generated "
             f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        L.append(f"| {SEVERITY_LABEL[sev]} | {counts[sev]} |")
    L.append("")

    if not report.findings:
        L.append("No issues found by the rules in this build.")
    by_class = report.by_class()
    if by_class:
        L.append("## Summary by vulnerability type")
        L.append("")
        L.append("| Type | CWE | Findings | Worst risk | Impact | Ease | Common |")
        L.append("|---|---|---:|---:|---:|---:|---:|")
        for key, items in by_class.items():
            vc = knowledge.get(key)
            worst = max(items, key=lambda f: f.risk_score)
            L.append(f"| {vc.title} | {vc.cwe} | {len(items)} | {worst.risk_score}/10 | "
                     f"{worst.impact}/5 | {worst.exploitability}/5 | {worst.prevalence}/5 |")
        L.append("")

    for key, items in by_class.items():
        vc = knowledge.get(key)
        L.append(f"## {vc.title} ({vc.cwe})")
        L.append("")
        L.append(f"**OWASP:** {vc.owasp}" +
                 (f" · **2024 CWE Top 25 rank:** #{vc.cwe_top25_rank}" if vc.cwe_top25_rank else ""))
        L.append("")
        worst = max(items, key=lambda f: f.risk_score)
        L.append(f"**Consequences if exploited ({vc.impact}/5).** {vc.impact_note}")
        L.append("")
        L.append(f"**Ease of exploitation ({worst.exploitability}/5).** {worst.exploitability_note}")
        L.append("")
        L.append(f"**How common ({vc.prevalence}/5).** {vc.prevalence_note}")
        L.append("")
        stat = provider.headline_stat(vc)
        news = provider.items_for(vc, limit=3)
        if stat or news:
            L.append("**In the news.**" + (f" {stat}." if stat else ""))
            L.append("")
            for i in news:
                L.append(f"- *{i.date}* — [{i.headline}]({i.url}) ({i.source}). {i.summary}")
            L.append("")
        L.append(f"**How to fix.** {vc.remediation}")
        L.append("")
        L.append(f"### Findings ({len(items)})")
        L.append("")
        for f in items:
            flags = [f"`{f.rule_id}`", f"confidence: {f.confidence}"]
            if f.tainted:
                flags.append("reachable from local input (caller-controlled)"
                             if f.taint_trust == "local" else "**reachable from untrusted input**")
            if f.in_test_code:
                flags.append("test/example code")
            L.append(f"- **{SEVERITY_LABEL[f.severity]} · risk {f.risk_score}/10** — "
                     f"`{f.path}:{f.line}` ({', '.join(flags)})")
            if f.snippet:
                L.append(f"  ```{f.language}")
                L.append(f"  {f.snippet}")
                L.append("  ```")
            L.append(f"  {f.message}")
            if f.fix_hint:
                L.append(f"  *Fix:* {f.fix_hint}")
        L.append("")

    L.append("---")
    L.append("")
    L.append(provider.provenance())
    L.append("")
    L.append("Scoring: `risk = 0.5·impact + 0.3·exploitability + 0.2·prevalence`, scaled to 10. "
             "Impact and prevalence are properties of the vulnerability class; exploitability is "
             "adjusted per finding based on whether untrusted input demonstrably reaches it.")
    L.append("")
    L.append("**Coverage.** Static pattern and AST analysis only. It does not see runtime "
             "configuration, business-logic and authorisation flaws, or vulnerable dependencies. "
             "A clean scan is not an audit.")
    return "\n".join(L)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

HTML_CSS = """
:root{--bg:#fbfbfa;--fg:#1c1c1a;--muted:#6b6b66;--line:#e3e3df;--card:#fff;
--crit:#8b1a1a;--high:#b3541e;--med:#8a6d1f;--low:#3b5a8a;--info:#6b6b66;--accent:#2f5d50;}
@media (prefers-color-scheme:dark){:root{--bg:#16161a;--fg:#e8e8e4;--muted:#9a9a94;
--line:#2c2c32;--card:#1e1e23;--crit:#ff8a80;--high:#ffb27a;--med:#e8d07a;--low:#9ec1ff;--info:#9a9a94;--accent:#7fd1b9;}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;}
.wrap{max-width:1000px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:40px 0 8px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:15px;margin:20px 0 6px}
.sub{color:var(--muted);font-size:13px;margin-bottom:24px}
.pills{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0 8px}
.pill{padding:6px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid var(--line)}
.pill.critical{background:var(--crit);color:#fff;border-color:transparent}
.pill.high{color:var(--high);border-color:var(--high)}
.pill.medium{color:var(--med);border-color:var(--med)}
.pill.low{color:var(--low);border-color:var(--low)}
.pill.info{color:var(--info)}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin:14px 0}
.card.critical{border-left:4px solid var(--crit)}.card.high{border-left:4px solid var(--high)}
.card.medium{border-left:4px solid var(--med)}.card.low{border-left:4px solid var(--low)}
.card.info{border-left:4px solid var(--info)}
.loc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;color:var(--accent)}
.tags{color:var(--muted);font-size:12px}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px 12px;
overflow-x:auto;font-size:12.5px;margin:10px 0}
.axes{display:grid;grid-template-columns:150px 1fr;gap:6px 14px;margin:14px 0;align-items:start}
.axlabel{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);font-weight:700;padding-top:2px}
.meter{display:inline-block;font-family:ui-monospace,monospace;letter-spacing:2px;color:var(--accent)}
.axnote{font-size:13.5px;color:var(--fg)}
.news{border-left:2px solid var(--line);padding-left:14px;margin:8px 0}
.news .date{font-weight:700;font-size:12px;color:var(--muted)}
.news a{color:var(--accent)}
table{border-collapse:collapse;width:100%;font-size:13.5px;margin:10px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
td.num,th.num{text-align:right}
.fix{background:color-mix(in srgb,var(--accent) 8%,transparent);border-radius:6px;padding:10px 12px;font-size:13.5px;margin-top:10px}
footer{margin-top:50px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);font-size:12.5px}
"""


def render_html(report: ScanReport, provider: NewsProvider) -> str:
    e = html_mod.escape
    counts = report.counts()
    P: List[str] = []
    P.append("<!doctype html><html><head><meta charset='utf-8'>")
    P.append("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    P.append(f"<title>Security scan — {e(os.path.basename(report.root))}</title>")
    P.append(f"<style>{HTML_CSS}</style></head><body><div class='wrap'>")
    P.append(f"<h1>Security scan</h1>")
    P.append(f"<div class='sub'><code>{e(report.root)}</code> · {report.files_scanned} files · "
             f"{report.lines_scanned:,} lines · {report.duration_s}s · generated "
             f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</div>")

    P.append("<div class='pills'>")
    for sev in ("critical", "high", "medium", "low", "info"):
        P.append(f"<span class='pill {sev}'>{SEVERITY_LABEL[sev]} {counts[sev]}</span>")
    P.append("</div>")

    by_class = report.by_class()
    if by_class:
        P.append("<h2>Summary by vulnerability type</h2><table><tr>"
                 "<th>Type</th><th>CWE</th><th class='num'>Findings</th>"
                 "<th class='num'>Worst risk</th><th class='num'>Impact</th>"
                 "<th class='num'>Ease</th><th class='num'>Common</th></tr>")
        for key, items in by_class.items():
            vc = knowledge.get(key)
            worst = max(items, key=lambda f: f.risk_score)
            P.append(f"<tr><td><a href='#{e(key)}'>{e(vc.title)}</a></td><td>{e(vc.cwe)}</td>"
                     f"<td class='num'>{len(items)}</td><td class='num'>{worst.risk_score}</td>"
                     f"<td class='num'>{worst.impact}/5</td><td class='num'>{worst.exploitability}/5</td>"
                     f"<td class='num'>{worst.prevalence}/5</td></tr>")
        P.append("</table>")

    for key, items in by_class.items():
        vc = knowledge.get(key)
        worst = max(items, key=lambda f: f.risk_score)
        P.append(f"<h2 id='{e(key)}'>{e(vc.title)} <span class='tags'>{e(vc.cwe)} · {e(vc.owasp)}"
                 + (f" · 2024 CWE Top 25 #{vc.cwe_top25_rank}" if vc.cwe_top25_rank else "")
                 + "</span></h2>")
        P.append("<div class='axes'>")
        P.append(f"<div class='axlabel'>If exploited</div><div class='axnote'>"
                 f"<span class='meter'>{bar(vc.impact)}</span> {vc.impact}/5 — {e(vc.impact_note)}</div>")
        P.append(f"<div class='axlabel'>Ease of attack</div><div class='axnote'>"
                 f"<span class='meter'>{bar(worst.exploitability)}</span> {worst.exploitability}/5 — "
                 f"{e(worst.exploitability_note)}</div>")
        P.append(f"<div class='axlabel'>How common</div><div class='axnote'>"
                 f"<span class='meter'>{bar(vc.prevalence)}</span> {vc.prevalence}/5 — {e(vc.prevalence_note)}</div>")
        P.append("</div>")

        stat = provider.headline_stat(vc)
        news = provider.items_for(vc, limit=3)
        if stat or news:
            P.append("<h3>In the news</h3>")
            if stat:
                P.append(f"<p class='axnote'>{e(stat)}.</p>")
            for i in news:
                P.append(f"<div class='news'><span class='date'>{e(i.date)}</span> "
                         f"<a href='{e(i.url)}' rel='noopener noreferrer' target='_blank'>{e(i.headline)}</a>"
                         f"<div class='axnote'>{e(i.summary)}</div>"
                         f"<div class='tags'>{e(i.source)}</div></div>")

        P.append(f"<div class='fix'><strong>How to fix.</strong> {e(vc.remediation)}</div>")
        P.append(f"<h3>Findings ({len(items)})</h3>")
        for f in items:
            tags = [f.rule_id, f"confidence: {f.confidence}"]
            if f.tainted:
                tags.append("reachable from local input (caller-controlled)"
                            if f.taint_trust == "local" else "reachable from untrusted input")
            if f.in_test_code:
                tags.append("test/example code")
            P.append(f"<div class='card {f.severity}'>")
            P.append(f"<div><strong>{SEVERITY_LABEL[f.severity]}</strong> · risk {f.risk_score}/10 · "
                     f"<span class='loc'>{e(f.path)}:{f.line}</span></div>")
            P.append(f"<div class='tags'>{e(' · '.join(tags))}</div>")
            if f.snippet:
                P.append(f"<pre>{e(f.snippet)}</pre>")
            P.append(f"<div class='axnote'>{e(f.message)}</div>")
            if f.tainted and f.taint_reason:
                P.append(f"<div class='tags'>Reachability: the value {e(f.taint_reason)}.</div>")
            if f.fix_hint:
                P.append(f"<div class='fix'>{e(f.fix_hint)}</div>")
            P.append("</div>")

    P.append(f"<footer><p>{e(provider.provenance())}</p>"
             "<p>Scoring: risk = 0.5·impact + 0.3·exploitability + 0.2·prevalence, scaled to 10. "
             "Impact and prevalence are properties of the vulnerability class; exploitability is "
             "adjusted per finding based on whether untrusted input demonstrably reaches it.</p>"
             "<p><strong>Coverage.</strong> Static pattern and AST analysis only — no runtime "
             "configuration, business-logic or authorisation review, and no dependency-CVE check. "
             "A clean scan is not an audit.</p></footer>")
    P.append("</div></body></html>")
    return "\n".join(P)


# ---------------------------------------------------------------------------
# SARIF (for GitHub code scanning / CI)
# ---------------------------------------------------------------------------

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
               "low": "note", "info": "note"}


def render_sarif(report: ScanReport, provider: NewsProvider) -> str:
    rules: Dict[str, dict] = {}
    results: List[dict] = []
    for f in report.findings:
        vc = f.vclass
        if f.rule_id not in rules:
            news = provider.items_for(vc, limit=2)
            news_md = "".join(f"\n- {i.date}: [{i.headline}]({i.url})" for i in news)
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_name.replace(" ", ""),
                "shortDescription": {"text": f.rule_name},
                "fullDescription": {"text": vc.impact_note},
                "help": {
                    "text": vc.remediation,
                    "markdown": (f"**{vc.title}** ({vc.cwe})\n\n"
                                 f"**If exploited ({vc.impact}/5):** {vc.impact_note}\n\n"
                                 f"**Ease of exploitation ({vc.exploitability}/5):** {vc.exploitability_note}\n\n"
                                 f"**How common ({vc.prevalence}/5):** {vc.prevalence_note}\n\n"
                                 f"**Fix:** {vc.remediation}"
                                 + (f"\n\n**In the news:**{news_md}" if news_md else "")),
                },
                "properties": {
                    "tags": ["security", vc.cwe, vc.owasp.split(" - ")[0]],
                    "security-severity": str(round(f.risk_score, 1)),
                    "precision": {"high": "high", "medium": "medium", "low": "low"}[f.confidence],
                },
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
            }
        results.append({
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{vc.title}: {f.message}"},
            "partialFingerprints": {"secscan/v1": f.fingerprint()},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {
                        "startLine": max(1, f.line),
                        "startColumn": max(1, f.column + 1),
                        "snippet": {"text": f.snippet},
                    },
                }
            }],
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "secscan",
                "informationUri": "https://github.com/",
                "version": "1.0.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2)


RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "md": render_markdown,
    "html": render_html,
    "sarif": render_sarif,
}
