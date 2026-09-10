"""Pattern rules.

These are regular-expression rules applied to source text after comments have
been stripped.  They are deliberately biased toward *recall*: a pattern that
looks dangerous is reported with a confidence level, and the Python AST pass
(pyast.py) upgrades or suppresses Python findings where it can reason properly.

Each rule names a vulnerability class from knowledge.py, which supplies the
impact / exploitability / prevalence / news material for the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# Confidence describes how sure we are that the *pattern* means what it looks
# like - not how severe it is.
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    vuln_class: str
    languages: Tuple[str, ...]
    pattern: str
    message: str
    confidence: str = "medium"
    # A second regex that, if it also matches the line, suppresses the finding.
    negate: Optional[str] = None
    ignore_case: bool = False
    # Rule-specific note appended to the class remediation.
    fix_hint: Optional[str] = None
    # Whether nearby user-input markers should raise the exploitability score.
    taint_sensitive: bool = True

    def compiled(self) -> "re.Pattern[str]":
        flags = re.IGNORECASE if self.ignore_case else 0
        return re.compile(self.pattern, flags)

    def compiled_negate(self) -> Optional["re.Pattern[str]"]:
        if not self.negate:
            return None
        flags = re.IGNORECASE if self.ignore_case else 0
        return re.compile(self.negate, flags)


PY_LANGS = ("python",)
JS_LANGS = ("javascript", "typescript")
C_LANGS = ("c", "cpp")
WEB = ("javascript", "typescript", "html", "vue", "svelte")
ANY = ("*",)


RULES: List[Rule] = [
    # ---------------------------------------------------------------- SQL
    Rule(
        id="PY-SQL-001",
        name="SQL query built with f-string",
        vuln_class="sql-injection",
        languages=PY_LANGS,
        pattern=r"""(?i)\b(execute|executemany|executescript|raw|text)\s*\(\s*f["']\s*(select|insert|update|delete|drop|alter|create|merge|with)\b""",
        message="An f-string is interpolated directly into a SQL statement, so any value it embeds becomes query syntax.",
        confidence="high",
        fix_hint="Replace with cursor.execute('... WHERE id = %s', (user_id,)) and let the driver bind the value.",
    ),
    Rule(
        id="PY-SQL-002",
        name="SQL query built with string concatenation or %-formatting",
        vuln_class="sql-injection",
        languages=PY_LANGS,
        pattern=r"""(?i)\b(execute|executemany|executescript|raw|text)\s*\(\s*["'][^"']*\b(select|insert|update|delete|drop|alter)\b[^"']*["']\s*(\+|%\s*[^s\)])""",
        message="A SQL string is concatenated or %-formatted with runtime values before execution.",
        confidence="high",
        fix_hint="Use driver parameter binding ('%s' / '?' placeholders with a parameter tuple) rather than building the string.",
    ),
    Rule(
        id="PY-SQL-003",
        name="SQL string assembled with .format()",
        vuln_class="sql-injection",
        languages=PY_LANGS,
        pattern=r"""(?i)["'][^"']*\b(select|insert into|update|delete from)\b[^"']*\{\}?[^"']*["']\s*\.\s*format\s*\(""",
        message="A SQL statement is assembled with str.format(), which offers no escaping of any kind.",
        confidence="medium",
    ),
    Rule(
        id="JS-SQL-001",
        name="SQL query built with a template literal",
        vuln_class="sql-injection",
        languages=JS_LANGS,
        pattern=r"""(?i)\.(query|execute|raw)\s*\(\s*`[^`]*\b(select|insert|update|delete|drop)\b[^`]*\$\{""",
        message="A template literal interpolates a value straight into SQL passed to the database driver.",
        confidence="high",
        fix_hint="Use placeholders: connection.query('SELECT * FROM t WHERE id = ?', [id]).",
    ),
    Rule(
        id="JS-SQL-002",
        name="SQL query built with string concatenation",
        vuln_class="sql-injection",
        languages=JS_LANGS,
        pattern=r"""(?i)\.(query|execute)\s*\(\s*["'][^"']*\b(select|insert|update|delete)\b[^"']*["']\s*\+""",
        message="A SQL string is concatenated with runtime values before being sent to the database.",
        confidence="high",
    ),
    Rule(
        id="GEN-SQL-001",
        name="SQL statement interpolated in Java/Go/PHP/Ruby",
        vuln_class="sql-injection",
        languages=("java", "go", "php", "ruby", "csharp", "kotlin", "scala"),
        pattern=r"""(?i)(executeQuery|executeUpdate|prepareStatement|db\.Query|db\.Exec|mysqli_query|pg_query|\.where)\s*\(\s*["'`][^"'`]*\b(select|insert|update|delete)\b[^"'`]*["'`]\s*(\+|\.|%|,\s*fmt\.Sprintf)""",
        message="A SQL statement is built by string assembly instead of parameter binding.",
        confidence="medium",
    ),

    # ------------------------------------------------------- command injection
    Rule(
        id="PY-CMD-001",
        name="subprocess called with shell=True",
        vuln_class="command-injection",
        languages=PY_LANGS,
        pattern=r"\b(subprocess\s*\.\s*(run|call|check_call|check_output|Popen)|Popen)\s*\([^)]*shell\s*=\s*True",
        message="shell=True re-parses the command string through /bin/sh, so metacharacters in any interpolated value become commands.",
        confidence="high",
        fix_hint="Pass a list of arguments and drop shell=True: subprocess.run(['git', 'clone', url]).",
    ),
    Rule(
        id="PY-CMD-002",
        name="os.system / os.popen invocation",
        vuln_class="command-injection",
        languages=PY_LANGS,
        pattern=r"\bos\s*\.\s*(system|popen)\s*\(",
        message="os.system/os.popen always execute through a shell; any interpolated value can inject commands.",
        confidence="medium",
        fix_hint="Use subprocess.run([...]) with an argument list.",
    ),
    Rule(
        id="JS-CMD-001",
        name="child_process exec with interpolated command",
        vuln_class="command-injection",
        languages=JS_LANGS,
        pattern=r"\b(exec|execSync)\s*\(\s*[`\"'][^`\"']*(\$\{|\"\s*\+|'\s*\+)",
        message="child_process.exec runs its argument through a shell, and this command embeds a runtime value.",
        confidence="high",
        fix_hint="Use execFile/spawn with an argument array: execFile('convert', [input, output]).",
    ),
    Rule(
        id="GEN-CMD-001",
        name="Shell execution helper with interpolated input",
        vuln_class="command-injection",
        languages=("php", "ruby", "perl", "java", "go", "shell"),
        pattern=r"""(?i)\b(system|shell_exec|passthru|proc_open|popen|exec\.Command\s*\(\s*"(?:sh|bash)"|Runtime\.getRuntime\(\)\.exec)\s*\(?\s*["'`][^"'`]*(\$\{|\$\(|\#\{|\+|%s)""",
        message="A shell command is assembled from runtime values before execution.",
        confidence="medium",
    ),
    Rule(
        id="RB-CMD-001",
        name="Ruby backtick or %x shell execution with interpolation",
        vuln_class="command-injection",
        languages=("ruby",),
        pattern=r"(`[^`\n]*#\{|%x\([^)\n]*#\{)",
        message="Ruby backticks and %x() execute through a shell; #{} interpolation puts user data into that command line.",
        confidence="high",
    ),

    # ------------------------------------------------------------ code injection
    Rule(
        id="PY-EVAL-001",
        name="eval/exec on a runtime value",
        vuln_class="code-injection",
        languages=PY_LANGS,
        pattern=r"\b(eval|exec)\s*\(\s*(?!['\"][^'\"]*['\"]\s*\))",
        message="eval/exec compiles and runs its argument as Python; if any part is attacker-influenced this is remote code execution.",
        confidence="medium",
        fix_hint="Use ast.literal_eval for data, or dispatch through an explicit {name: function} mapping.",
    ),
    Rule(
        id="JS-EVAL-001",
        name="eval / Function constructor / setTimeout on a string",
        vuln_class="code-injection",
        languages=JS_LANGS,
        pattern=r"(\beval\s*\(|new\s+Function\s*\(|\bsetTimeout\s*\(\s*[\"'`][^\"'`]*\$\{)",
        message="A string is compiled and executed as JavaScript.",
        confidence="medium",
        fix_hint="Parse data with JSON.parse and pass functions - not strings - to setTimeout/setInterval.",
    ),
    Rule(
        id="PY-SSTI-001",
        name="Template rendered from a runtime string",
        vuln_class="template-injection",
        languages=PY_LANGS,
        pattern=r"\b(render_template_string|Template\s*\(\s*(f[\"']|[a-zA-Z_][\w.]*\s*[\)+%]))",
        message="A template is compiled from a runtime string; Jinja expressions in that string execute with full object access.",
        confidence="medium",
        negate=r"^\s*(from|import)\s",
        fix_hint="Render a fixed template file and pass user data as context: render_template('page.html', name=name).",
    ),

    # ----------------------------------------------------------- deserialization
    Rule(
        id="PY-DESER-001",
        name="pickle / marshal / shelve load of external data",
        vuln_class="deserialization",
        languages=PY_LANGS,
        pattern=r"\b(pickle|cPickle|dill|marshal|shelve)\s*\.\s*(loads?|Unpickler)\s*\(",
        message="Unpickling executes constructor callables chosen by the data itself - untrusted input here is code execution.",
        confidence="high",
        fix_hint="Use JSON for interchange; if pickle is unavoidable, HMAC-sign the blob and verify before loading.",
    ),
    Rule(
        id="PY-DESER-002",
        name="yaml.load without a safe loader",
        vuln_class="deserialization",
        languages=PY_LANGS,
        pattern=r"\byaml\s*\.\s*load\s*\(",
        message="yaml.load with the default loader can instantiate arbitrary Python objects via !!python tags.",
        confidence="high",
        negate=r"Loader\s*=\s*(yaml\.)?(Safe|Base|C?Safe)Loader",
        fix_hint="Use yaml.safe_load(...) (or Loader=yaml.SafeLoader).",
    ),
    Rule(
        id="JAVA-DESER-001",
        name="Java native deserialization of a stream",
        vuln_class="deserialization",
        languages=("java", "kotlin", "scala"),
        pattern=r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)",
        message="Java native deserialization instantiates attacker-chosen classes; public gadget chains turn this into RCE.",
        confidence="medium",
        fix_hint="Switch to JSON with a strict schema, or install a class allowlist via ObjectInputFilter.",
    ),
    Rule(
        id="PHP-DESER-001",
        name="PHP unserialize() on request data",
        vuln_class="deserialization",
        languages=("php",),
        pattern=r"\bunserialize\s*\(\s*\$(_GET|_POST|_REQUEST|_COOKIE|data|input)",
        message="unserialize() on request data triggers magic methods on attacker-chosen classes (POP chain).",
        confidence="high",
    ),

    # ------------------------------------------------------------------- XSS
    Rule(
        id="JS-XSS-001",
        name="innerHTML / outerHTML assigned a dynamic value",
        vuln_class="xss",
        languages=WEB,
        pattern=r"\.(innerHTML|outerHTML)\s*=\s*(?!['\"`][^'\"`]*['\"`]\s*;?\s*$)",
        message="Assigning to innerHTML parses the value as HTML, so any script-bearing markup in it runs.",
        confidence="medium",
        fix_hint="Use textContent for text, or sanitise with DOMPurify.sanitize() when markup is genuinely required.",
    ),
    Rule(
        id="JS-XSS-002",
        name="document.write with a dynamic value",
        vuln_class="xss",
        languages=WEB,
        pattern=r"document\s*\.\s*(write|writeln)\s*\(",
        message="document.write injects raw markup into the parser.",
        confidence="medium",
    ),
    Rule(
        id="JS-XSS-003",
        name="React dangerouslySetInnerHTML",
        vuln_class="xss",
        languages=JS_LANGS,
        pattern=r"dangerouslySetInnerHTML\s*=\s*\{\{",
        message="dangerouslySetInnerHTML bypasses React's escaping; the value must already be sanitised HTML.",
        confidence="medium",
        fix_hint="Render text as a child instead, or sanitise with DOMPurify before passing it in.",
    ),
    Rule(
        id="JS-XSS-004",
        name="Vue v-html directive",
        vuln_class="xss",
        languages=("vue", "html", "javascript", "typescript"),
        pattern=r"v-html\s*=",
        message="v-html renders raw HTML and bypasses Vue's escaping.",
        confidence="medium",
    ),
    Rule(
        id="PY-XSS-001",
        name="Escaping bypassed with mark_safe / |safe",
        vuln_class="xss",
        languages=("python", "html", "jinja", "django"),
        pattern=r"\b(mark_safe\s*\(|\|\s*safe\b|\{\%\s*autoescape\s+(off|false)\s*\%\})",
        message="Template auto-escaping is explicitly bypassed for this value.",
        confidence="medium",
        fix_hint="Remove the bypass, or sanitise with bleach.clean() before marking content safe.",
    ),
    Rule(
        id="PHP-XSS-001",
        name="Request data echoed without escaping",
        vuln_class="xss",
        languages=("php",),
        pattern=r"\b(echo|print)\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)\b",
        message="Request data is echoed straight into the response body.",
        confidence="high",
        fix_hint="Wrap in htmlspecialchars($v, ENT_QUOTES, 'UTF-8').",
    ),

    # -------------------------------------------------------------- traversal
    Rule(
        id="PY-PATH-001",
        name="File path built from a runtime value",
        vuln_class="path-traversal",
        languages=PY_LANGS,
        pattern=r"\b(open|send_file|send_from_directory|FileResponse)\s*\(\s*(f[\"']|os\.path\.join\s*\([^)]*(request|params|args|argv|input|user)|[\w.]*\s*\+\s*)",
        message="A filesystem path is assembled from a runtime value; '../' sequences in it escape the intended directory.",
        confidence="low",
        fix_hint="Resolve with os.path.realpath and assert the result starts with your base directory before opening.",
    ),
    Rule(
        id="JS-PATH-001",
        name="File path built from request data",
        vuln_class="path-traversal",
        languages=JS_LANGS,
        pattern=r"(readFile|readFileSync|createReadStream|sendFile|unlink|writeFile)\s*\(\s*[^)]*(req\.(query|params|body)|\$\{)",
        message="A filesystem path incorporates request data without normalisation.",
        confidence="medium",
        fix_hint="path.resolve the candidate and verify it stays within the base directory.",
    ),
    Rule(
        id="GEN-ZIP-001",
        name="Archive extracted without path validation",
        vuln_class="path-traversal",
        languages=ANY,
        pattern=r"\b(extractall\s*\(|\.extract\s*\(|tar\s+-?x[a-z]*f)",
        message="Archive entries can contain '../' paths ('zip slip') and overwrite files outside the target directory.",
        confidence="low",
        fix_hint="Validate each member's resolved destination before writing; Python 3.12+ offers filter='data'.",
    ),

    # ------------------------------------------------------------------ SSRF
    Rule(
        id="PY-SSRF-001",
        name="Outbound request to a runtime URL",
        vuln_class="ssrf",
        languages=PY_LANGS,
        pattern=r"\b(requests\s*\.\s*(get|post|put|delete|head|request)|urlopen|httpx\s*\.\s*(get|post)|aiohttp[\w.]*\.(get|post))\s*\(\s*(f[\"']|[a-z_][\w.]*\s*[,)]|[\w.]*\s*\+)",
        message="The destination URL comes from a runtime value, letting a caller point the request at internal hosts or cloud metadata.",
        confidence="low",
        fix_hint="Allowlist the host, resolve DNS and reject private/link-local addresses, and disable redirects.",
    ),
    Rule(
        id="JS-SSRF-001",
        name="Outbound fetch to a request-controlled URL",
        vuln_class="ssrf",
        languages=JS_LANGS,
        pattern=r"\b(fetch|axios(\.\w+)?|got|request)\s*\(\s*(`[^`]*\$\{|req\.(query|params|body))",
        message="The outbound request URL is built from request data.",
        confidence="medium",
    ),

    # ------------------------------------------------------------------- XXE
    Rule(
        id="PY-XXE-001",
        name="XML parsed with an entity-resolving parser",
        vuln_class="xxe",
        languages=PY_LANGS,
        pattern=r"\b(xml\.(etree|dom|sax)[\w.]*\.(parse|fromstring|parseString)|lxml\.etree\.(parse|fromstring)|etree\.(parse|fromstring))\s*\(",
        message="Standard-library and lxml XML parsers may resolve external entities, exposing local files and internal URLs.",
        confidence="low",
        negate=r"defusedxml|resolve_entities\s*=\s*False",
        fix_hint="Use defusedxml (from defusedxml.ElementTree import parse) or an lxml parser with resolve_entities=False.",
    ),
    Rule(
        id="JAVA-XXE-001",
        name="XML factory without secure processing",
        vuln_class="xxe",
        languages=("java", "kotlin", "scala"),
        pattern=r"(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*newInstance\s*\(",
        message="Default JAXP factories resolve DTDs and external entities unless explicitly restricted.",
        confidence="low",
        negate=r"(FEATURE_SECURE_PROCESSING|disallow-doctype-decl|setExpandEntityReferences\s*\(\s*false)",
        fix_hint="factory.setFeature('http://apache.org/xml/features/disallow-doctype-decl', true).",
    ),

    # ---------------------------------------------------------------- crypto
    Rule(
        id="PY-CRYPTO-001",
        name="MD5 or SHA-1 used",
        vuln_class="weak-crypto",
        languages=PY_LANGS,
        pattern=r"\bhashlib\s*\.\s*(md5|sha1)\s*\(|\bhashlib\.new\s*\(\s*[\"'](md5|sha1)[\"']",
        message="MD5 and SHA-1 are collision-broken and unsuitable for signatures, integrity checks or password storage.",
        confidence="high",
        negate=r"usedforsecurity\s*=\s*False",
        fix_hint="Use hashlib.sha256; for a deliberately non-security hash pass usedforsecurity=False to document the intent.",
    ),
    Rule(
        id="GEN-CRYPTO-001",
        name="Weak hash algorithm referenced",
        vuln_class="weak-crypto",
        languages=("java", "javascript", "typescript", "go", "csharp", "php", "ruby", "kotlin"),
        pattern=r"""(?i)(MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)|createHash\s*\(\s*["'](md5|sha1)|md5\.New\s*\(|sha1\.New\s*\(|hash\s*\(\s*["'](md5|sha1))""",
        message="A collision-broken hash algorithm (MD5/SHA-1) is selected here.",
        confidence="high",
    ),
    Rule(
        id="GEN-CRYPTO-002",
        name="Weak cipher or ECB mode",
        vuln_class="weak-crypto",
        languages=ANY,
        pattern=r"""(?i)["'](DES|DESede|3DES|RC4|RC2|Blowfish)(/[\w/]*)?["']|AES\s*[/.-]\s*ECB|MODE_ECB|["']aes-\d+-ecb["']""",
        message="A broken cipher (DES/RC4) or ECB mode is selected; ECB leaks plaintext structure across identical blocks.",
        confidence="high",
        fix_hint="Use AES-256-GCM (authenticated) or ChaCha20-Poly1305 with a unique nonce per message.",
    ),
    Rule(
        id="GEN-HASH-001",
        name="Password hashed with a fast general-purpose hash",
        vuln_class="weak-password-hash",
        languages=ANY,
        pattern=r"""(?i)(md5|sha1|sha256|sha512)\s*\(\s*[^)]*\b(password|passwd|pwd|pw|passphrase|secret)\b""",
        message="Passwords hashed with a fast hash are recoverable in bulk on GPUs after any database leak.",
        confidence="high",
        fix_hint="Use argon2id (argon2-cffi), scrypt, or bcrypt, which are memory-hard and tunable.",
    ),
    Rule(
        id="PY-RAND-001",
        name="Non-cryptographic RNG used for a security value",
        vuln_class="weak-random",
        languages=PY_LANGS,
        pattern=r"""(?i)\b(token|secret|key|nonce|salt|otp|password|session|csrf|reset|api_?key)\w*\s*=\s*[^=\n]*\brandom\s*\.\s*(random|randint|choice|choices|sample|shuffle|randrange|getrandbits)\b""",
        message="random is a Mersenne Twister PRNG: observing a few outputs reveals its state and all future values.",
        confidence="high",
        fix_hint="Use secrets.token_urlsafe(32) / secrets.choice() for anything security-relevant.",
    ),
    Rule(
        id="JS-RAND-001",
        name="Math.random used for a security value",
        vuln_class="weak-random",
        languages=JS_LANGS,
        pattern=r"""(?i)\b(token|secret|key|nonce|salt|otp|password|session|csrf|reset|apikey)\w*\s*[:=][^;\n]*Math\s*\.\s*random\s*\(""",
        message="Math.random is not cryptographically secure and its output is predictable.",
        confidence="high",
        fix_hint="Use crypto.randomBytes(32).toString('hex') (Node) or crypto.getRandomValues (browser).",
    ),

    # ------------------------------------------------------------------- TLS
    Rule(
        id="PY-TLS-001",
        name="TLS certificate verification disabled",
        vuln_class="tls-verification-disabled",
        languages=PY_LANGS,
        pattern=r"\bverify\s*=\s*False\b|_create_unverified_context\s*\(|ssl\.CERT_NONE\b|check_hostname\s*=\s*False",
        message="Certificate verification is switched off, so any machine on the network path can impersonate the server.",
        confidence="high",
        fix_hint="Pass the internal CA bundle instead: requests.get(url, verify='/etc/ssl/internal-ca.pem').",
        taint_sensitive=False,
    ),
    Rule(
        id="JS-TLS-001",
        name="Node TLS verification disabled",
        vuln_class="tls-verification-disabled",
        languages=JS_LANGS,
        pattern=r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0",
        message="Node is told to accept any certificate, defeating TLS authentication for these connections.",
        confidence="high",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-TLS-001",
        name="Certificate validation bypassed",
        vuln_class="tls-verification-disabled",
        languages=("java", "go", "csharp", "php", "ruby", "kotlin"),
        pattern=r"(InsecureSkipVerify\s*:\s*true|VERIFY_PEER\s*,?\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|ServerCertificateValidationCallback\s*(\+)?=|TrustAllCerts|X509TrustManager\s*\(\s*\)\s*\{)",
        message="Certificate validation is bypassed for these connections.",
        confidence="high",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-HTTP-001",
        name="Sensitive endpoint addressed over plain HTTP",
        vuln_class="insecure-transport",
        languages=ANY,
        pattern=r"""(?i)["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|schemas?\.|www\.w3\.org|xmlns)[\w.-]+[^"']*["']""",
        message="A remote endpoint is addressed over unencrypted HTTP.",
        confidence="low",
        # XML feature switches, namespaces and DTD identifiers are spelled as
        # http:// URIs but are never fetched - they are just names.
        negate=r"(xml/features|/sax/(properties|features)|xmlns|namespace|schemaLocation|DOCTYPE|\bDTD\b)",
        taint_sensitive=False,
    ),

    # --------------------------------------------------------------- JWT/auth
    Rule(
        id="GEN-JWT-001",
        name="JWT signature verification disabled",
        vuln_class="jwt-verification",
        languages=ANY,
        pattern=r"""(?i)(verify\s*=\s*False|verify_signature["']?\s*[:=]\s*(False|false)|["']none["']\s*(,|\])\s*#?\s*alg|algorithms\s*=\s*\[\s*["']none["'])""",
        message="The JWT signature is not verified, so any token payload can be forged.",
        confidence="medium",
        negate=r"requests\.|httpx\.|session\.|urllib3|ssl_",
        fix_hint="jwt.decode(token, key, algorithms=['RS256']) - pin the algorithm and verify exp/iss/aud.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-JWT-002",
        name="JWT decoded without verification",
        vuln_class="jwt-verification",
        languages=ANY,
        pattern=r"(jwt\.decode\s*\([^)]*options\s*=\s*\{[^}]*verify_signature[\"']?\s*:\s*False|jwt_decode\s*\(\s*[^,)]+\s*\)|decodeJwt\s*\(|jwt\.decode\s*\(\s*[^,)]+\s*\)\s*$)",
        message="The token is decoded without a key, which reads claims an attacker fully controls.",
        confidence="medium",
        taint_sensitive=False,
    ),

    # ------------------------------------------------------------- misconfig
    Rule(
        id="PY-DEBUG-001",
        name="Debug mode enabled",
        vuln_class="debug-exposure",
        languages=PY_LANGS,
        pattern=r"\b(debug\s*=\s*True|DEBUG\s*=\s*True)\b",
        message="Debug mode exposes stack traces, settings and - in Flask/Werkzeug - an interactive console that executes code.",
        confidence="medium",
        negate=r"os\.(environ|getenv)|settings\.|config\(|if\s+",
        fix_hint="DEBUG = os.environ.get('DEBUG', '') == '1' and assert it is False in the production entrypoint.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-BIND-001",
        name="Service bound to all interfaces",
        vuln_class="ssl-hostname",
        languages=ANY,
        pattern=r"""(?i)(host\s*=\s*["']0\.0\.0\.0["']|["']0\.0\.0\.0["']\s*,\s*\d{2,5}|--host[= ]0\.0\.0\.0|bind\s*\(\s*\(\s*["']0\.0\.0\.0["'])""",
        message="Binding to 0.0.0.0 exposes this listener on every network interface the host has.",
        confidence="low",
        fix_hint="Bind to 127.0.0.1 and expose deliberately at the container/port-mapping layer.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-CORS-001",
        name="Wildcard CORS origin",
        vuln_class="permissive-cors",
        languages=ANY,
        pattern=r"""(?i)(Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|origins?\s*=\s*\[?\s*["']\*["']|cors\s*\(\s*\{\s*origin\s*:\s*(true|["']\*["']))""",
        message="Any origin may read responses from this endpoint.",
        confidence="medium",
        fix_hint="Allowlist exact origins from configuration; never pair a wildcard with credentials.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-CORS-002",
        name="CORS origin reflected with credentials",
        vuln_class="permissive-cors",
        languages=ANY,
        pattern=r"""(?i)Access-Control-Allow-Origin["']?\s*[:,]\s*[^"'\n]*\b(origin|req\.headers|request\.headers|HTTP_ORIGIN)\b""",
        message="The request's Origin header is reflected back, which - with credentials allowed - lets any site read authenticated responses.",
        confidence="medium",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-CSRF-001",
        name="CSRF protection disabled",
        vuln_class="csrf",
        languages=ANY,
        pattern=r"""(?i)(csrf_exempt|@csrf\.exempt|csrf\s*[:=]\s*(False|false|off)|WTF_CSRF_ENABLED\s*=\s*False|protect_from_forgery\s+with:\s*:null_session|\[\s*ValidateAntiForgeryToken\s*\]\s*//\s*disabled)""",
        message="CSRF protection is switched off for this handler, so a third-party page can trigger it using the victim's session.",
        confidence="medium",
        fix_hint="For webhooks, verify an HMAC signature instead of exempting the route.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-COOKIE-001",
        name="Session cookie missing Secure/HttpOnly",
        vuln_class="insecure-cookie",
        languages=ANY,
        pattern=r"""(?i)(httponly\s*[:=]\s*(False|false|0)|secure\s*[:=]\s*(False|false|0)|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|samesite\s*[:=]\s*["']?none["']?)""",
        message="A cookie security attribute is explicitly disabled or weakened.",
        confidence="medium",
        fix_hint="Set Secure, HttpOnly and SameSite=Lax on session cookies.",
        taint_sensitive=False,
    ),
    Rule(
        id="GEN-REDIR-001",
        name="Redirect target taken from request data",
        vuln_class="open-redirect",
        languages=ANY,
        pattern=r"""(?i)\b(redirect|sendRedirect|Redirect)\s*\(\s*[^)]*\b(request\.(args|GET|POST|query|params|values)|req\.(query|params|body)|\$_(GET|POST|REQUEST)|params\[)""",
        message="The redirect destination comes from the request, so the URL can point anywhere.",
        confidence="medium",
        fix_hint="Allow only relative paths, or map a token to a server-side list of permitted destinations.",
    ),
    Rule(
        id="PY-TMP-001",
        name="Insecure temporary file",
        vuln_class="insecure-temp-file",
        languages=PY_LANGS,
        pattern=r"\btempfile\s*\.\s*mktemp\s*\(|[\"']/tmp/[\w.\-{}$]+[\"']",
        message="A predictable temporary path lets a local attacker pre-create or symlink the file before you open it.",
        confidence="low",
        fix_hint="Use tempfile.NamedTemporaryFile() or mkstemp(), which create atomically with 0600 permissions.",
        taint_sensitive=False,
    ),

    # -------------------------------------------------------------- JS extras
    Rule(
        id="JS-PROTO-001",
        name="Unsafe deep merge / dynamic property assignment",
        vuln_class="prototype-pollution",
        languages=JS_LANGS,
        pattern=r"(\bmerge\s*\(\s*\{?\s*\}?\s*,\s*(req\.|JSON\.parse|body)|_\.(merge|defaultsDeep|set)\s*\(|\[\s*(key|prop|path|name)\s*\]\s*=\s*)",
        message="Deep-merging or path-assigning attacker-controlled keys can reach Object.prototype via __proto__.",
        confidence="low",
        fix_hint="Reject __proto__/constructor/prototype keys, or key user data with a Map.",
    ),

    # ------------------------------------------------------------- native code
    Rule(
        id="C-BUF-001",
        name="Unbounded string/memory function",
        vuln_class="buffer-overflow",
        languages=C_LANGS,
        pattern=r"\b(strcpy|strcat|sprintf|vsprintf|gets|scanf\s*\(\s*\"%s)\s*\(",
        message="These functions write without a destination bound; a longer-than-expected input corrupts adjacent memory.",
        confidence="high",
        fix_hint="Use snprintf/strlcpy/fgets with an explicit size, and check return values.",
    ),
    Rule(
        id="C-FMT-001",
        name="Non-literal format string",
        vuln_class="format-string",
        languages=C_LANGS,
        pattern=r"\b(printf|fprintf|sprintf|snprintf|syslog|vprintf)\s*\(\s*(?![\"stdout,\s]*\")[A-Za-z_]\w*\s*\)",
        message="A variable is passed where a format string is expected; format specifiers inside it are interpreted.",
        confidence="high",
        fix_hint="printf(\"%s\", value) - keep the format string a literal.",
    ),
    Rule(
        id="C-BUF-002",
        name="Length-limited copy with a suspicious bound",
        vuln_class="buffer-overflow",
        languages=C_LANGS,
        pattern=r"\b(strncpy|memcpy|strncat)\s*\([^,]+,\s*[^,]+,\s*(strlen\s*\(|sizeof\s*\(\s*\*)",
        message="The length argument is derived from the source rather than the destination, which does not bound the write.",
        confidence="medium",
        fix_hint="Bound by sizeof(destination) - 1 and terminate explicitly.",
    ),
]


# ---------------------------------------------------------------------------
# Secret detection patterns (handled separately: entropy + provider formats)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecretPattern:
    id: str
    name: str
    pattern: str
    confidence: str = "high"
    # Minimum Shannon entropy (bits/char) required for generic patterns.
    min_entropy: float = 0.0


SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern("SEC-AWS-AKID", "AWS access key ID", r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    SecretPattern("SEC-AWS-SECRET", "AWS secret access key",
                  r"""(?i)aws_?(?:secret_?)?access_?key(?:_?id)?["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']"""),
    SecretPattern("SEC-GH-PAT", "GitHub token", r"\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,})\b"),
    SecretPattern("SEC-SLACK", "Slack token", r"\b(xox[abposr]-[A-Za-z0-9-]{10,})\b"),
    SecretPattern("SEC-GOOGLE", "Google API key", r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
    SecretPattern("SEC-STRIPE", "Stripe secret key", r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b"),
    SecretPattern("SEC-SENDGRID", "SendGrid API key", r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b"),
    SecretPattern("SEC-OPENAI", "OpenAI-style API key", r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{32,})\b"),
    SecretPattern("SEC-ANTHROPIC", "Anthropic API key", r"\b(sk-ant-[A-Za-z0-9_\-]{24,})\b"),
    SecretPattern("SEC-PRIVKEY", "Private key block",
                  r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"),
    SecretPattern("SEC-JWT", "Hardcoded JWT",
                  r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b",
                  confidence="medium"),
    SecretPattern("SEC-SLACK-HOOK", "Slack webhook URL",
                  r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})"),
    SecretPattern("SEC-DBURL", "Database URL with inline password",
                  r"""((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s"':/]+:[^\s"'@/]{4,}@[^\s"'/]+)"""),
    SecretPattern("SEC-GENERIC", "Hardcoded credential in assignment",
                  r"""(?i)\b(?:api_?key|secret_?key|access_?token|auth_?token|client_?secret|private_?key|passwd|password|pwd|db_?pass|encryption_?key)\w*["']?\s*[:=]\s*["']([^"'\n]{8,})["']""",
                  confidence="medium", min_entropy=2.6),
]


def rules_for_language(lang: str) -> List[Rule]:
    return [r for r in RULES if "*" in r.languages or lang in r.languages]


def rule_by_id(rule_id: str) -> Optional[Rule]:
    for r in RULES:
        if r.id == rule_id:
            return r
    return None
