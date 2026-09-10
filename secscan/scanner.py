"""Scan engine: file discovery, comment stripping, rule matching, scoring."""

from __future__ import annotations

import fnmatch
import hashlib
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import knowledge, pyast
from .rules import (CONFIDENCE_ORDER, RULES, SECRET_PATTERNS, Rule,
                    SecretPattern, rules_for_language)

# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

EXT_LANG: Dict[str, str] = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".go": "go", ".rb": "ruby", ".php": "php", ".pl": "perl",
    ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hpp": "cpp",
    ".cs": "csharp", ".swift": "swift", ".rs": "rust",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".html": "html", ".htm": "html", ".vue": "vue", ".svelte": "svelte",
    ".jinja": "jinja", ".j2": "jinja", ".erb": "html", ".ejs": "html",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".toml": "toml",
    ".tf": "terraform", ".env": "env", ".ini": "ini", ".cfg": "ini",
    ".sql": "sql", ".xml": "xml", ".gradle": "java", ".dockerfile": "docker",
}

SPECIAL_FILENAMES: Dict[str, str] = {
    "dockerfile": "docker", "makefile": "make", ".env": "env",
    ".env.local": "env", ".env.production": "env", "docker-compose.yml": "yaml",
}

DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "node_modules", "vendor", "bower_components",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "venv", ".venv", "env", ".env.d", "virtualenv", "site-packages",
    "dist", "build", "target", "out", ".next", ".nuxt", ".gradle",
    "coverage", "htmlcov", ".idea", ".vscode", "migrations",
    "*.min.js", "*.min.css", "*.bundle.js", "*.map", "*.lock",
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
)

TEST_MARKERS = re.compile(
    r"(^|/)(tests?|spec|specs|__tests__|fixtures?|examples?|samples?|demo|mocks?|testdata|benchmarks?)(/|$)"
    r"|(^|/)(test_[^/]+|[^/]+_test|[^/]+\.spec|[^/]+\.test)\.[a-z]+$",
    re.IGNORECASE,
)

SUPPRESS_RE = re.compile(
    r"(?:#|//|/\*|--)\s*(?:nosec|nosecscan|secscan\s*:\s*ignore|noqa\s*:\s*S\d*)"
    r"(?:\s*[:\-]?\s*(?P<ids>[A-Z0-9\-,\s]+))?",
    re.IGNORECASE,
)

BINARY_HINT = b"\x00"


def detect_language(path: Path) -> Optional[str]:
    name = path.name.lower()
    if name in SPECIAL_FILENAMES:
        return SPECIAL_FILENAMES[name]
    if name.startswith(".env"):
        return "env"
    return EXT_LANG.get(path.suffix.lower())


class Ignorer:
    """Default excludes + user globs + (optionally) .gitignore patterns."""

    def __init__(self, root: Path, extra: Sequence[str] = (), use_gitignore: bool = True):
        self.root = root
        self.patterns: List[str] = list(DEFAULT_EXCLUDES) + list(extra)
        if use_gitignore:
            self.patterns.extend(self._read_gitignore(root))

    @staticmethod
    def _read_gitignore(root: Path) -> List[str]:
        pats: List[str] = []
        gi = root / ".gitignore"
        if not gi.is_file():
            return pats
        try:
            for raw in gi.read_text(errors="ignore").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                pats.append(line.rstrip("/").lstrip("/"))
        except OSError:
            pass
        return pats

    def ignored(self, path: Path) -> bool:
        try:
            rel = path.relative_to(self.root).as_posix()
        except ValueError:
            rel = path.as_posix()
        parts = rel.split("/")
        for pat in self.patterns:
            if "/" in pat:
                if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
                    return True
            else:
                if any(fnmatch.fnmatch(p, pat) for p in parts):
                    return True
        return False


def discover(roots: Sequence[Path], excludes: Sequence[str] = (),
             use_gitignore: bool = True, max_bytes: int = 2_000_000
             ) -> List[Tuple[Path, str]]:
    """Return [(path, language)] for every scannable file under roots."""
    out: List[Tuple[Path, str]] = []
    seen: Set[Path] = set()
    for root in roots:
        root = root.resolve()
        base = root if root.is_dir() else root.parent
        ignorer = Ignorer(base, excludes, use_gitignore)
        candidates: Iterable[Path]
        if root.is_file():
            candidates = [root]
        else:
            candidates = (p for p in root.rglob("*") if p.is_file())
        for path in candidates:
            if path in seen or ignorer.ignored(path):
                continue
            lang = detect_language(path)
            if lang is None:
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            seen.add(path)
            out.append((path, lang))
    return sorted(out)


# ---------------------------------------------------------------------------
# Comment stripping (keeps offsets stable so line numbers stay correct)
# ---------------------------------------------------------------------------

C_LIKE = {"javascript", "typescript", "java", "kotlin", "scala", "go", "c", "cpp",
          "csharp", "php", "swift", "rust", "vue", "svelte"}
HASH_LIKE = {"python", "ruby", "shell", "yaml", "perl", "terraform", "docker",
             "make", "ini", "env"}


def strip_comments(text: str, lang: str) -> str:
    """Blank out comment bodies, preserving length and newlines.

    Comments are a major source of false positives ('# TODO: we used to do
    exec(user_input) here').  Blanking rather than deleting keeps every line
    number and column offset valid.
    """
    if lang in C_LIKE:
        line_tokens = ("//",)
        block = ("/*", "*/")
        quotes = "\"'`"
    elif lang in HASH_LIKE:
        line_tokens = ("#",)
        block = None
        quotes = "\"'"
    else:
        return text

    out = list(text)
    i, n = 0, len(text)
    in_str: Optional[str] = None
    triple = False
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if triple and text.startswith(in_str * 3, i):
                i += 3
                in_str, triple = None, False
                continue
            if not triple and ch == in_str:
                in_str = None
            elif not triple and ch == "\n":
                in_str = None  # unterminated string; recover at EOL
            i += 1
            continue
        if ch in quotes:
            if lang == "python" and text.startswith(ch * 3, i):
                in_str, triple = ch, True
                i += 3
                continue
            in_str, triple = ch, False
            i += 1
            continue
        if block and text.startswith(block[0], i):
            end = text.find(block[1], i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
            continue
        if any(text.startswith(t, i) for t in line_tokens):
            # Avoid treating '://' inside an unquoted URL as a comment.
            if lang in C_LIKE and i > 0 and text[i - 1] == ":":
                i += 1
                continue
            # Ruby '#{...}' is string interpolation, not a comment - and it is
            # exactly where injected values live, so blanking it hides bugs.
            if lang == "ruby" and text.startswith("#{", i):
                i += 2
                continue
            end = text.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
            continue
        i += 1
    return "".join(out)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# How far a precise AST finding reaches to suppress the regex match for the same
# issue (calls wrapped across lines report at different line numbers).
SUPERSEDE_WINDOW = 3

IMPORT_LINE_RE = re.compile(r"^\s*(from\s+[\w.]+\s+)?import\s")


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    vuln_class: str
    path: str
    line: int
    column: int
    snippet: str
    message: str
    confidence: str
    language: str
    tainted: bool = False
    taint_reason: str = ""
    # "remote" (a stranger over the network) or "local" (whoever runs the
    # process). Both are untrusted; only one of them is a stranger.
    taint_trust: str = ""
    in_test_code: bool = False
    fix_hint: str = ""
    # Hard ceiling on severity, set when we can prove the finding is not what
    # the raw pattern implies (a vendor's documentation key, say).
    severity_cap: Optional[str] = None

    # Scored in score() below.
    impact: int = 0
    exploitability: int = 0
    prevalence: int = 0
    risk_score: float = 0.0
    severity: str = "info"
    exploitability_note: str = ""

    @property
    def vclass(self) -> knowledge.VulnClass:
        return knowledge.VULN_CLASSES[self.vuln_class]

    def fingerprint(self) -> str:
        """Stable across line-number drift: rule + file + normalised code."""
        norm = re.sub(r"\s+", " ", self.snippet.strip())
        h = hashlib.sha256(f"{self.rule_id}|{self.path}|{norm}".encode()).hexdigest()
        return h[:16]

    def to_dict(self) -> Dict[str, object]:
        d = asdict(self)
        vc = self.vclass
        d["cwe"] = vc.cwe
        d["owasp"] = vc.owasp
        d["title"] = vc.title
        d["fingerprint"] = self.fingerprint()
        d["impact_note"] = vc.impact_note
        d["prevalence_note"] = vc.prevalence_note
        d["remediation"] = vc.remediation + (f" {self.fix_hint}" if self.fix_hint else "")
        d["news"] = [
            {"date": i.date, "headline": i.headline, "summary": i.summary,
             "source": i.source, "url": i.url}
            for i in vc.news
        ]
        return d


def score(f: Finding) -> Finding:
    """Attach impact / exploitability / prevalence and derive severity.

    Impact and prevalence come from the vulnerability class - they are
    properties of the flaw type.  Exploitability is adjusted per finding,
    because reachability is what actually varies between two instances of the
    same bug.
    """
    vc = f.vclass
    f.impact = vc.impact
    f.prevalence = vc.prevalence
    exploit = vc.exploitability
    notes: List[str] = [vc.exploitability_note]

    if f.tainted and f.taint_trust != "local":
        exploit = min(5, exploit + 1)
        notes.append(
            f"Here, untrusted data reaches the sink directly - the value {f.taint_reason}, "
            "so no additional conditions are needed."
        )
    elif f.tainted and f.taint_trust == "local" and vc.taint_driven:
        notes.append(
            f"The value {f.taint_reason} - it is supplied by whoever starts the process, "
            "not by a remote stranger. Someone who chooses your command line already holds "
            "this process's privileges, so this is only a vulnerability where the program "
            "runs with privileges its caller lacks (setuid/setgid, a service invoked with "
            "caller-influenced arguments, or a build step fed untrusted input)."
        )
        if vc.taint_driven and f.severity_cap is None:
            f.severity_cap = "low"
    if f.in_test_code:
        exploit = max(1, exploit - 2)
        notes.append(
            "This instance sits in test/example code, which is usually not deployed - "
            "confirm before spending remediation effort on it."
        )
    if f.confidence == "low":
        notes.append(
            "Pattern-matched with low confidence: verify the data really is "
            "attacker-influenced before treating this as exploitable."
        )

    f.exploitability = exploit
    f.exploitability_note = " ".join(notes)

    # Weighted toward consequence, then reachability, then how often it shows up.
    raw = 0.5 * f.impact + 0.3 * f.exploitability + 0.2 * f.prevalence  # 1..5
    f.risk_score = round(raw * 2, 1)  # 2..10

    if f.in_test_code:
        f.severity = "info" if f.risk_score < 8 else "low"
    elif f.risk_score >= 8.5:
        f.severity = "critical"
    elif f.risk_score >= 7.0:
        f.severity = "high"
    elif f.risk_score >= 5.0:
        f.severity = "medium"
    else:
        f.severity = "low"

    # A low-confidence guess should not present as a top-priority item.
    if f.confidence == "low" and f.severity == "critical":
        f.severity = "high"
    if f.severity_cap and SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[f.severity_cap]:
        f.severity = f.severity_cap
    return f


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------

PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:\s*)(?:x{3,}|y{3,}|\*{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|%\([^)]*\)s|\{\{[^}]*\}\}|"
    r"changeme|change_me|placeholder|example|examplekey|dummy|sample|your[-_ ]?[\w-]*|"
    r"none|null|nil|true|false|test|testing|foo|bar|baz|password|secret|redacted|"
    r"insert[-_ ]?\w*|todo|n/?a|\d+|env\..*|process\.env.*|os\.environ.*)\s*$"
)
ENV_LOOKUP_RE = re.compile(r"(?i)(os\.environ|os\.getenv|process\.env|System\.getenv|ENV\[|config\(|secrets\.|vault)")

# Credentials that appear verbatim in vendor documentation and tutorials. They
# are real-looking by construction, so format-based detection cannot tell them
# apart - but reporting them as live secrets is the fastest way to train a team
# to ignore the scanner. Detected, reported, downgraded, and labelled.
KNOWN_EXAMPLE_SECRETS = {
    "AKIAIOSFODNN7EXAMPLE": "AWS documentation example access key",
    "ASIAIOSFODNN7EXAMPLE": "AWS documentation example session key",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS documentation example secret key",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKE": "AWS documentation example secret key",
    "sk_live_4eC39HqLyjWDarjtT1zdp7dc": "Stripe documentation example key",
    "sk_test_4eC39HqLyjWDarjtT1zdp7dc": "Stripe documentation test key",
    "AIzaSyDOCKERTESTKEYFAKE1234567890abcde": "Google documentation example key",
}
EXAMPLE_MARKER_RE = re.compile(r"(?i)(example|sample|dummy|specimen|docs?[-_]?key|fake)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    if PLACEHOLDER_RE.match(value):
        return True
    if len(set(value)) <= 3:
        return True
    if ENV_LOOKUP_RE.search(value):
        return True
    return False


def scan_secrets(text: str, path: str, language: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = text.splitlines()
    for pat in SECRET_PATTERNS:
        rx = re.compile(pat.pattern)
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1] if line_no <= len(lines) else ""
            if looks_like_placeholder(value):
                continue
            if pat.min_entropy and shannon_entropy(value) < pat.min_entropy:
                continue
            redacted = value[:4] + "…" + value[-2:] if len(value) > 12 else "…"
            known = KNOWN_EXAMPLE_SECRETS.get(value)
            if known is None and EXAMPLE_MARKER_RE.search(value) and pat.id != "SEC-GENERIC":
                known = "contains an 'example'/'sample' marker"
            if known:
                message = (f"{pat.name} matched, but this value is {known}, not a live "
                           "credential. Left in the report because a real key in the same "
                           "place would look identical - confirm, then remove it so it stops "
                           "masking genuine leaks.")
                confidence = "low"
                fix_hint = "Replace the placeholder with a loud non-credential (e.g. 'REPLACE_ME') or delete the line."
                cap = "low"
            else:
                message = (f"{pat.name} appears to be committed in source (value starts "
                           f"'{redacted}'). Anything in version control should be assumed "
                           "compromised and rotated.")
                confidence = pat.confidence
                fix_hint = ("Check how long it has been exposed before deciding urgency: "
                            "`git log -S '<value>' --oneline` shows the commit that "
                            "introduced it.")
                cap = None
            findings.append(Finding(
                rule_id=pat.id,
                rule_name=pat.name,
                vuln_class="hardcoded-secret",
                path=path,
                line=line_no,
                column=m.start() - (text.rfind("\n", 0, m.start()) + 1),
                snippet=snippet.strip()[:200],
                message=message,
                confidence=confidence,
                language=language,
                fix_hint=fix_hint,
                severity_cap=cap,
            ))
    return findings


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------

def suppressed_lines(text: str) -> Dict[int, Set[str]]:
    """Map line number -> set of suppressed rule ids ('*' means all)."""
    out: Dict[int, Set[str]] = {}
    for idx, line in enumerate(text.splitlines(), start=1):
        m = SUPPRESS_RE.search(line)
        if not m:
            continue
        ids = m.group("ids")
        if ids and ids.strip():
            out[idx] = {i.strip().upper() for i in ids.split(",") if i.strip()}
        else:
            out[idx] = {"*"}
    return out


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------

# Markers that a nearby value came from a remote request...
REMOTE_INPUT_MARKERS = re.compile(
    r"(?i)\b(request\.|req\.(query|params|body|headers)|params\[|\$_(GET|POST|REQUEST|COOKIE)|"
    r"getParameter|FormData|body\.|query\.|@RequestParam|@PathVariable|c\.Query|r\.URL\.Query)"
)
# ...and markers that it came from the person running the program.
LOCAL_INPUT_MARKERS = re.compile(
    r"(?i)(\binput\(|sys\.argv|process\.argv|os\.environ|os\.getenv|process\.env|\bARGV\b)"
)


@dataclass
class FileResult:
    path: str
    language: str
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None
    lines: int = 0


def scan_file(path: Path, language: str, root: Path,
              include_secrets: bool = True, test_heuristic: bool = True) -> FileResult:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        return FileResult(str(path), language, error=f"unreadable: {exc}")
    if BINARY_HINT in raw[:4096]:
        return FileResult(str(path), language, error="binary file, skipped")
    text = raw.decode("utf-8", errors="replace")
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = str(path)

    result = FileResult(rel, language, lines=text.count("\n") + 1)
    lines = text.splitlines()
    is_test = test_heuristic and bool(TEST_MARKERS.search(rel.replace(os.sep, "/")))
    suppressions = suppressed_lines(text)
    code = strip_comments(text, language)

    findings: List[Finding] = []

    # 1. Python AST pass (precise) -----------------------------------------
    # A superseding AST finding may sit a few lines from the regex match when a
    # call is wrapped across lines, so supersession uses a small line window.
    superseded: Set[Tuple[int, str]] = set()
    if language == "python":
        ast_findings, err = pyast.analyze(text)
        if err:
            result.error = err
        for af in ast_findings:
            snippet = lines[af.line - 1].strip() if 0 < af.line <= len(lines) else ""
            findings.append(Finding(
                rule_id=af.rule_id,
                rule_name=knowledge.VULN_CLASSES[af.vuln_class].title,
                vuln_class=af.vuln_class,
                path=rel, line=af.line, column=af.col,
                snippet=snippet[:200],
                message=af.message,
                confidence=af.confidence,
                language=language,
                tainted=af.tainted,
                taint_reason=af.taint_reason,
                taint_trust=af.taint_trust,
                in_test_code=is_test,
                fix_hint=af.fix_hint,
            ))
            for rid in af.supersedes:
                superseded.add((af.line, rid))

    # 2. Regex rules --------------------------------------------------------
    # Where the AST pass covers a rule and the file parsed cleanly, the AST
    # result is authoritative: it understands call structure, keyword arguments
    # and string literals, so running the text pattern as well only adds noise
    # (a shell=True mentioned inside a string, say). If parsing failed we fall
    # back to the regexes, which is the whole point of keeping both.
    ast_authoritative = language == "python" and result.error is None
    for rule in rules_for_language(language):
        if ast_authoritative and rule.id in pyast.AST_COVERED_RULES:
            continue
        rx = rule.compiled()
        neg = rule.compiled_negate()
        for m in rx.finditer(code):
            line_no = code.count("\n", 0, m.start()) + 1
            if any((line_no + delta, rule.id) in superseded
                   for delta in range(-SUPERSEDE_WINDOW, SUPERSEDE_WINDOW + 1)):
                continue
            line_text = lines[line_no - 1] if line_no <= len(lines) else ""
            # An import statement naming a dangerous function is not a use of it.
            if language == "python" and IMPORT_LINE_RE.match(line_text):
                continue
            if neg and neg.search(line_text):
                continue
            # Give the negation a small window: config often spans lines.
            if neg:
                window = "\n".join(lines[max(0, line_no - 2):line_no + 2])
                if neg.search(window):
                    continue
            tainted = False
            reason = ""
            trust = ""
            if rule.taint_sensitive:
                lo = max(0, line_no - 4)
                hi = min(len(lines), line_no + 2)
                window = "\n".join(lines[lo:hi])
                mm = REMOTE_INPUT_MARKERS.search(window) or LOCAL_INPUT_MARKERS.search(window)
                if mm:
                    tainted = True
                    trust = ("remote" if REMOTE_INPUT_MARKERS.search(window) else "local")
                    reason = (f"appears alongside {trust} input ({mm.group(0).strip()}) "
                              "within a few lines")
            findings.append(Finding(
                rule_id=rule.id,
                rule_name=rule.name,
                vuln_class=rule.vuln_class,
                path=rel, line=line_no,
                column=m.start() - (code.rfind("\n", 0, m.start()) + 1),
                snippet=line_text.strip()[:200],
                message=rule.message,
                confidence=rule.confidence,
                language=language,
                tainted=tainted,
                taint_reason=reason,
                taint_trust=trust,
                in_test_code=is_test,
                fix_hint=rule.fix_hint or "",
            ))

    # 3. Secrets ------------------------------------------------------------
    if include_secrets:
        for f in scan_secrets(text, rel, language):
            f.in_test_code = is_test
            findings.append(f)

    # 4. Suppression + dedupe ----------------------------------------------
    deduped: Dict[Tuple[str, int, str], Finding] = {}
    for f in findings:
        sup = suppressions.get(f.line)
        if sup and ("*" in sup or f.rule_id.upper() in sup):
            continue
        key = (f.rule_id, f.line, f.vuln_class)
        if key not in deduped:
            deduped[key] = score(f)

    result.findings = sorted(
        deduped.values(),
        key=lambda f: (-SEVERITY_ORDER[f.severity], -f.risk_score, f.line),
    )
    return result


# ---------------------------------------------------------------------------
# Whole-scan orchestration
# ---------------------------------------------------------------------------

@dataclass
class ScanReport:
    root: str
    findings: List[Finding]
    files_scanned: int
    lines_scanned: int
    errors: List[Tuple[str, str]]
    duration_s: float = 0.0
    languages: Dict[str, int] = field(default_factory=dict)

    def by_severity(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {s: [] for s in
                                         ("critical", "high", "medium", "low", "info")}
        for f in self.findings:
            out[f.severity].append(f)
        return out

    def by_class(self) -> Dict[str, List[Finding]]:
        out: Dict[str, List[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.vuln_class, []).append(f)
        return dict(sorted(out.items(), key=lambda kv: -max(x.risk_score for x in kv[1])))

    def counts(self) -> Dict[str, int]:
        c = Counter(f.severity for f in self.findings)
        return {s: c.get(s, 0) for s in ("critical", "high", "medium", "low", "info")}


def scan(roots: Sequence[Path], excludes: Sequence[str] = (),
         use_gitignore: bool = True, include_secrets: bool = True,
         include_tests: bool = True, max_bytes: int = 2_000_000,
         test_heuristic: bool = True, progress=None) -> ScanReport:
    import time
    start = time.time()
    files = discover(roots, excludes, use_gitignore, max_bytes)
    root = Path(roots[0]).resolve()
    if root.is_file():
        root = root.parent

    findings: List[Finding] = []
    errors: List[Tuple[str, str]] = []
    lines_total = 0
    langs: Counter = Counter()

    for idx, (path, lang) in enumerate(files):
        if progress:
            progress(idx + 1, len(files), path)
        res = scan_file(path, lang, root, include_secrets=include_secrets,
                        test_heuristic=test_heuristic)
        lines_total += res.lines
        langs[lang] += 1
        if res.error:
            errors.append((res.path, res.error))
        for f in res.findings:
            if not include_tests and f.in_test_code:
                continue
            findings.append(f)

    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], -f.risk_score,
                                 -CONFIDENCE_ORDER[f.confidence], f.path, f.line))
    return ScanReport(
        root=str(root),
        findings=findings,
        files_scanned=len(files),
        lines_scanned=lines_total,
        errors=errors,
        duration_s=round(time.time() - start, 2),
        languages=dict(langs.most_common()),
    )
