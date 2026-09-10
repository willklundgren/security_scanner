"""Python AST analysis with lightweight taint tracking.

Regex rules see text; this pass sees structure.  It is used for two things:

1.  Precision.  `subprocess.run(cmd, shell=True)` where `cmd` is a literal is
    much less interesting than the same call where `cmd` came from
    `request.args`.  The AST pass can tell the difference; a regex cannot.

2.  Reachability.  We track which local names derive from an untrusted source
    (request objects, CLI arguments, stdin, environment, file contents, network
    responses) and mark findings as `tainted` when such a name flows into a
    sink.  Tainted findings get a confidence and exploitability boost, and the
    report says *why* they are reachable.

The taint analysis is intentionally flow-insensitive and intraprocedural: it
over-approximates within a function and does not follow calls.  That is the
right trade-off for a linting-speed tool - it produces useful signal without
pretending to be sound.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# Roots that indicate attacker-controlled data when an attribute is read off
# them (req.query, request.form, ...).
TAINT_ROOTS = {
    "request", "req", "flask_request", "self.request",
}
# Roots trustworthy enough to taint on their own, with no attribute access.
# 'req' is deliberately absent: it is just as often a local urllib Request or
# a requirements object, and treating every one of them as untrusted produced
# a false SSRF report inside this scanner's own source.
BARE_TAINT_ROOTS = {"request", "flask_request"}
TAINT_CALLS = {
    "input", "raw_input", "getenv", "environ", "argv", "read", "readline",
    "readlines", "recv", "get_json", "loads", "unquote", "urlopen",
}

# Trust levels. "remote" means a stranger supplies the value over the network.
# "local" means the value comes from whoever started the process - command-line
# arguments, environment variables, an interactive prompt. Both are untrusted
# input, but they are not the same risk: someone who can choose your argv
# already has your privileges, so `open(sys.argv[1])` is a CLI doing its job,
# not a path-traversal vulnerability. It becomes one only when the program runs
# with privileges the caller lacks (setuid, a service invoked by another user).
REMOTE = "remote"
LOCAL = "local"


@dataclass(frozen=True)
class Taint:
    reason: str
    trust: str = REMOTE
TAINT_ATTRS = {
    "args", "form", "json", "data", "files", "cookies", "headers", "values",
    "query_params", "GET", "POST", "body", "params", "path_params",
}

WEB_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch", "app", "api",
    "require_http_methods", "api_view", "endpoint", "websocket",
}


# Regex rules whose job the AST pass does better. When a Python file parses,
# these are skipped in favour of the structural check (see scanner.scan_file).
# Every id here must appear in some `supersedes` tuple below, and vice versa -
# tests/test_secscan.py enforces both directions.
# Every structural check this module can emit. Kept as a declared set so the
# CLI can report an accurate count and tests can catch a check added without
# being registered here.
AST_CHECKS = frozenset({
    "AST-PY-SQL", "AST-PY-SHELL", "AST-PY-OSSYSTEM", "AST-PY-EVAL",
    "AST-PY-SSTI", "AST-PY-PICKLE", "AST-PY-YAML", "AST-PY-WEAKHASH",
    "AST-PY-RANDOM", "AST-PY-TLS", "AST-PY-JWT", "AST-PY-XXE",
    "AST-PY-PATH", "AST-PY-SSRF", "AST-PY-TMP", "AST-PY-DEBUG",
    "AST-PY-DJDEBUG", "AST-PY-DJHOSTS",
})

AST_COVERED_RULES = frozenset({
    "PY-SQL-001", "PY-SQL-002", "PY-SQL-003",
    "PY-CMD-001", "PY-CMD-002",
    "PY-EVAL-001", "PY-SSTI-001",
    "PY-DESER-001", "PY-DESER-002",
    "PY-CRYPTO-001", "PY-RAND-001",
    "PY-TLS-001", "PY-XXE-001", "PY-PATH-001", "PY-SSRF-001",
    "PY-TMP-001", "PY-DEBUG-001",
    "GEN-JWT-001", "GEN-JWT-002",
})


@dataclass
class AstFinding:
    rule_id: str
    vuln_class: str
    line: int
    col: int
    message: str
    confidence: str
    tainted: bool = False
    taint_reason: str = ""
    taint_trust: str = ""
    fix_hint: str = ""
    # Rule ids whose regex findings on this line should be suppressed in favour
    # of this (more precise) finding.
    supersedes: Tuple[str, ...] = ()


def _name_of(node: ast.AST) -> str:
    """Dotted name for Name/Attribute nodes; '' for anything else."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name_of(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name_of(node.func)
    return ""


def _is_literal(node: Optional[ast.AST]) -> bool:
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.JoinedStr):  # f-string: literal only if no fields
        return all(isinstance(v, ast.Constant) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _has_dynamic_parts(node: Optional[ast.AST]) -> bool:
    """True if the expression mixes literal text with runtime values."""
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, (ast.Add, ast.Mod)):
            return not _is_literal(node)
    if isinstance(node, ast.Call):
        fn = _name_of(node.func)
        return fn.endswith(".format") or fn.endswith(".join")
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript)):
        return True
    return False


def _kwarg(call: ast.Call, name: str) -> Optional[ast.AST]:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _is_true(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_false(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


class TaintTracker:
    """Collects names that (transitively) hold untrusted data."""

    def __init__(self) -> None:
        self.tainted: Dict[str, Taint] = {}

    def source_of(self, node: ast.AST) -> Optional[Taint]:
        """Return a Taint if this expression carries untrusted data."""
        best: Optional[Taint] = None
        for sub in ast.walk(node):
            found: Optional[Taint] = None
            if isinstance(sub, ast.Attribute):
                dotted = _name_of(sub)
                head = dotted.split(".")[0]
                if head in TAINT_ROOTS and sub.attr in TAINT_ATTRS:
                    found = Taint(f"derives from {dotted}", REMOTE)
                elif sub.attr in ("argv", "environ") and head in ("sys", "os"):
                    found = Taint(f"derives from {dotted}", LOCAL)
            elif isinstance(sub, ast.Call):
                fn = _name_of(sub.func)
                short = fn.split(".")[-1]
                head = fn.split(".")[0]
                if short in ("input", "raw_input"):
                    found = Taint("derives from input()", LOCAL)
                elif head in TAINT_ROOTS and short in ("get_json", "get_data", "json"):
                    found = Taint(f"derives from {fn}()", REMOTE)
                elif short == "getenv" and head == "os":
                    found = Taint("derives from os.getenv()", LOCAL)
            elif isinstance(sub, ast.Name):
                if sub.id in self.tainted:
                    found = self.tainted[sub.id]
                elif sub.id in BARE_TAINT_ROOTS:
                    found = Taint(f"derives from {sub.id}", REMOTE)
            if found is not None:
                # Remote beats local: if any part of the expression is
                # attacker-controlled, the whole expression is.
                if found.trust == REMOTE:
                    return found
                best = best or found
        return best

    def learn(self, node: ast.AST) -> None:
        """Record assignments of untrusted expressions to local names."""
        if isinstance(node, ast.Assign):
            taint = self.source_of(node.value)
            if taint:
                for tgt in node.targets:
                    name = _name_of(tgt)
                    if name:
                        self.tainted[name.split(".")[0]] = taint
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            taint = self.source_of(node.value)
            if taint:
                name = _name_of(node.target)
                if name:
                    self.tainted[name.split(".")[0]] = taint
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Parameters of a route handler are request-controlled.
            if _is_web_handler(node):
                for arg in list(node.args.args) + list(node.args.kwonlyargs):
                    if arg.arg not in ("self", "cls"):
                        self.tainted[arg.arg] = Taint(
                            "is a parameter of an HTTP route handler", REMOTE)


def _is_web_handler(node: ast.AST) -> bool:
    decorators = getattr(node, "decorator_list", [])
    for dec in decorators:
        name = _name_of(dec)
        parts = {p.lower() for p in name.split(".")}
        if parts & WEB_DECORATORS:
            return True
    return False


SQL_KEYWORDS = ("select ", "insert into", "update ", "delete from", "drop ",
                "create table", "alter table", " where ", " from ")


def _looks_like_sql(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            low = sub.value.lower()
            if any(k in low for k in SQL_KEYWORDS):
                return True
    return False


class PythonAnalyzer(ast.NodeVisitor):
    def __init__(self) -> None:
        self.findings: List[AstFinding] = []
        self.taint = TaintTracker()
        self.imports: Set[str] = set()

    # -- helpers ----------------------------------------------------------
    def _add(self, node: ast.AST, rule_id: str, vuln_class: str, message: str,
             confidence: str = "high", tainted_expr: Optional[ast.AST] = None,
             fix_hint: str = "", supersedes: Tuple[str, ...] = ()) -> None:
        taint = self.taint.source_of(tainted_expr) if tainted_expr is not None else None
        self.findings.append(AstFinding(
            rule_id=rule_id,
            vuln_class=vuln_class,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            message=message,
            confidence=confidence,
            tainted=taint is not None,
            taint_reason=taint.reason if taint else "",
            taint_trust=taint.trust if taint else "",
            fix_hint=fix_hint,
            supersedes=supersedes,
        ))

    # -- traversal --------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.imports.add(a.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.taint.learn(node)
        self._check_django_debug(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.taint.learn(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.taint.learn(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.taint.learn(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        fn = _name_of(node.func)
        short = fn.split(".")[-1]
        args = node.args

        # --- SQL execution ------------------------------------------------
        if short in ("execute", "executemany", "executescript", "raw", "text") and args:
            q = args[0]
            if _looks_like_sql(q) and _has_dynamic_parts(q):
                self._add(node, "AST-PY-SQL", "sql-injection",
                          "SQL string is built from runtime values and then executed; "
                          "the interpolated value becomes part of the query grammar.",
                          tainted_expr=q,
                          fix_hint="Pass values as bound parameters: cursor.execute(sql, (a, b)).",
                          supersedes=("PY-SQL-001", "PY-SQL-002", "PY-SQL-003"))

        # --- command execution --------------------------------------------
        if fn.startswith("subprocess.") or short in ("Popen", "call", "check_output", "check_call", "run"):
            shell = _kwarg(node, "shell")
            if _is_true(shell):
                cmd = args[0] if args else None
                dynamic = _has_dynamic_parts(cmd)
                conf = "high" if dynamic else "medium"
                msg = ("A shell command is executed with shell=True and a dynamically built "
                       "command string, so shell metacharacters in the interpolated value run as commands."
                       if dynamic else
                       "shell=True runs the command through /bin/sh; any future interpolation here becomes injectable.")
                self._add(node, "AST-PY-SHELL", "command-injection", msg,
                          confidence=conf, tainted_expr=cmd,
                          fix_hint="Drop shell=True and pass an argument list.",
                          supersedes=("PY-CMD-001",))

        if fn in ("os.system", "os.popen"):
            cmd = args[0] if args else None
            self._add(node, "AST-PY-OSSYSTEM", "command-injection",
                      f"{fn}() executes its argument through a shell.",
                      confidence="high" if _has_dynamic_parts(cmd) else "medium",
                      tainted_expr=cmd,
                      fix_hint="Use subprocess.run([...], shell=False).",
                      supersedes=("PY-CMD-002",))

        # --- dynamic code -------------------------------------------------
        if short in ("eval", "exec") and not fn.count(".") and args:
            if not _is_literal(args[0]):
                self._add(node, "AST-PY-EVAL", "code-injection",
                          f"{short}() executes a runtime-constructed string as Python code.",
                          tainted_expr=args[0],
                          fix_hint="Use ast.literal_eval() for data or a dispatch dict for behaviour.",
                          supersedes=("PY-EVAL-001",))

        if short == "render_template_string" and args:
            self._add(node, "AST-PY-SSTI", "template-injection",
                      "A Jinja template is compiled from a runtime string; template syntax in "
                      "that string is evaluated with access to the application object graph.",
                      confidence="high" if _has_dynamic_parts(args[0]) else "medium",
                      tainted_expr=args[0],
                      fix_hint="render_template('file.html', **context) with user data as context only.",
                      supersedes=("PY-SSTI-001",))

        # --- deserialization ----------------------------------------------
        if fn in ("pickle.loads", "pickle.load", "cPickle.loads", "dill.loads",
                  "marshal.loads", "yaml.unsafe_load", "yaml.full_load"):
            self._add(node, "AST-PY-PICKLE", "deserialization",
                      f"{fn}() reconstructs arbitrary Python objects from the input bytes, "
                      "executing constructor callables chosen by the data.",
                      tainted_expr=args[0] if args else None,
                      fix_hint="Use JSON, or HMAC-sign and verify the payload before loading.",
                      supersedes=("PY-DESER-001",))

        if fn == "yaml.load":
            loader = _kwarg(node, "Loader") or (args[1] if len(args) > 1 else None)
            loader_name = _name_of(loader) if loader is not None else ""
            if "Safe" not in loader_name and "Base" not in loader_name:
                self._add(node, "AST-PY-YAML", "deserialization",
                          "yaml.load() without a safe loader can instantiate arbitrary Python "
                          "objects through !!python/object tags.",
                          tainted_expr=args[0] if args else None,
                          fix_hint="Use yaml.safe_load(stream).",
                          supersedes=("PY-DESER-002",))

        # --- crypto --------------------------------------------------------
        if fn in ("hashlib.md5", "hashlib.sha1"):
            if not _is_false(_kwarg(node, "usedforsecurity")):
                algo = fn.split(".")[-1].upper()
                self._add(node, "AST-PY-WEAKHASH", "weak-crypto",
                          f"{algo} is collision-broken and must not be used for signatures, "
                          "integrity checks or password storage.",
                          fix_hint="hashlib.sha256(...), or usedforsecurity=False if this is a non-security hash.",
                          supersedes=("PY-CRYPTO-001",))

        if fn.startswith("random.") and short in (
                "random", "randint", "choice", "choices", "sample", "randrange", "getrandbits", "shuffle"):
            self._flag_random_in_security_context(node, fn)

        # --- TLS -----------------------------------------------------------
        if _is_false(_kwarg(node, "verify")) and (
                fn.startswith("requests.") or fn.startswith("httpx.") or short in ("get", "post", "put", "delete", "request")):
            self._add(node, "AST-PY-TLS", "tls-verification-disabled",
                      "TLS certificate verification is disabled for this request, so the "
                      "connection can be intercepted and modified by anyone on the path.",
                      fix_hint="verify='/path/to/internal-ca.pem' instead of verify=False.",
                      supersedes=("PY-TLS-001",))

        # --- JWT -----------------------------------------------------------
        if fn.endswith("jwt.decode") or short == "decode" and "jwt" in fn:
            opts = _kwarg(node, "options")
            unverified = False
            if isinstance(opts, ast.Dict):
                for k, v in zip(opts.keys, opts.values):
                    if isinstance(k, ast.Constant) and k.value in ("verify_signature", "verify") and _is_false(v):
                        unverified = True
            if _is_false(_kwarg(node, "verify")):
                unverified = True
            if unverified or (len(args) == 1 and not node.keywords):
                self._add(node, "AST-PY-JWT", "jwt-verification",
                          "The JWT is decoded without verifying its signature, so its claims "
                          "(user id, roles) are entirely attacker-controlled.",
                          confidence="high" if unverified else "medium",
                          fix_hint="jwt.decode(token, key, algorithms=['RS256'], audience=...).",
                          supersedes=("GEN-JWT-001", "GEN-JWT-002"))

        # --- XXE -----------------------------------------------------------
        if short in ("parse", "fromstring", "parseString", "XMLParser") and (
                fn.startswith("etree.") or fn.startswith("ET.") or fn.startswith("xml.")
                or fn.startswith("lxml.") or fn.startswith("minidom.")):
            if not any(m.startswith("defusedxml") for m in self.imports):
                self._add(node, "AST-PY-XXE", "xxe",
                          "XML is parsed with a parser that may resolve external entities, "
                          "allowing local file reads and internal network requests.",
                          confidence="medium",
                          tainted_expr=args[0] if args else None,
                          fix_hint="from defusedxml.ElementTree import parse, fromstring.",
                          supersedes=("PY-XXE-001",))

        # --- file access ----------------------------------------------------
        if short in ("open", "send_file", "send_from_directory") and args:
            if self.taint.source_of(args[0]) and _has_dynamic_parts(args[0]):
                self._add(node, "AST-PY-PATH", "path-traversal",
                          "A filesystem path is built from untrusted input; '../' sequences "
                          "escape the intended directory.",
                          tainted_expr=args[0],
                          fix_hint="realpath the result and verify it is inside the base directory.",
                          supersedes=("PY-PATH-001",))

        # --- SSRF ------------------------------------------------------------
        if short in ("get", "post", "put", "delete", "head", "request", "urlopen") and args:
            if fn.split(".")[0] in ("requests", "httpx", "urllib", "aiohttp", "session") or short == "urlopen":
                if self.taint.source_of(args[0]):
                    self._add(node, "AST-PY-SSRF", "ssrf",
                              "The outbound request URL is attacker-controlled, so the server "
                              "can be made to call internal addresses (including cloud metadata).",
                              tainted_expr=args[0],
                              fix_hint="Allowlist hosts; resolve DNS and reject private/link-local IPs.",
                              supersedes=("PY-SSRF-001",))

        # --- temp files -------------------------------------------------------
        if fn == "tempfile.mktemp":
            self._add(node, "AST-PY-TMP", "insecure-temp-file",
                      "tempfile.mktemp() only generates a name; the gap before you open it is a race window.",
                      fix_hint="tempfile.NamedTemporaryFile() or tempfile.mkstemp().",
                      supersedes=("PY-TMP-001",))

        # --- Flask run --------------------------------------------------------
        if short == "run" and (_is_true(_kwarg(node, "debug"))):
            self._add(node, "AST-PY-DEBUG", "debug-exposure",
                      "The development server runs with debug=True: the Werkzeug debugger "
                      "exposes an interactive console that executes Python on the server.",
                      fix_hint="debug=os.environ.get('FLASK_DEBUG') == '1', and never in production.",
                      supersedes=("PY-DEBUG-001",))

        self.generic_visit(node)

    def _flag_random_in_security_context(self, node: ast.Call, fn: str) -> None:
        """random.* matters only when the value is security-relevant."""
        parent_names = getattr(node, "_secscan_target", "")
        if not parent_names:
            return
        low = parent_names.lower()
        if any(w in low for w in ("token", "secret", "key", "nonce", "salt", "otp",
                                  "password", "session", "csrf", "reset", "code", "seed")):
            self._add(node, "AST-PY-RANDOM", "weak-random",
                      f"{fn}() is a Mersenne Twister PRNG - not cryptographically secure - and "
                      f"its output is used for '{parent_names}'.",
                      fix_hint="Use the secrets module: secrets.token_urlsafe(32).",
                      supersedes=("PY-RAND-001",))

    def _check_django_debug(self, node: ast.Assign) -> None:
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id in ("DEBUG", "ALLOWED_HOSTS", "SECRET_KEY"):
                if tgt.id == "DEBUG" and _is_true(node.value):
                    self._add(node, "AST-PY-DJDEBUG", "debug-exposure",
                              "DEBUG = True in settings exposes stack traces, settings and SQL "
                              "to anyone who can trigger an error.",
                              confidence="medium",
                              fix_hint="DEBUG = os.environ.get('DJANGO_DEBUG') == '1'.",
                              supersedes=("PY-DEBUG-001",))
                if tgt.id == "ALLOWED_HOSTS" and isinstance(node.value, ast.List):
                    if any(isinstance(e, ast.Constant) and e.value == "*" for e in node.value.elts):
                        self._add(node, "AST-PY-DJHOSTS", "debug-exposure",
                                  "ALLOWED_HOSTS = ['*'] disables Django's Host header validation, "
                                  "enabling host-header poisoning of password-reset links and caches.",
                                  confidence="medium",
                                  fix_hint="List your real hostnames explicitly.")


def _annotate_assignment_targets(tree: ast.AST) -> None:
    """Tag call nodes with the name they are assigned to (for RNG context)."""
    for node in ast.walk(tree):
        target_name = ""
        if isinstance(node, ast.Assign):
            target_name = ", ".join(filter(None, (_name_of(t) for t in node.targets)))
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            target_name = _name_of(node.target)
            value = node.value
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            target_name = node.name
            value = None
        else:
            continue
        if not target_name:
            continue
        if value is not None:
            for sub in ast.walk(value):
                if isinstance(sub, ast.Call):
                    setattr(sub, "_secscan_target", target_name)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and not getattr(sub, "_secscan_target", ""):
                    setattr(sub, "_secscan_target", target_name)


def analyze(source: str) -> Tuple[List[AstFinding], Optional[str]]:
    """Return (findings, syntax_error_message)."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # Python 2 file, template, or genuinely broken
        return [], f"could not parse: {exc.msg} (line {exc.lineno})"
    _annotate_assignment_targets(tree)
    analyzer = PythonAnalyzer()
    analyzer.visit(tree)
    return analyzer.findings, None
