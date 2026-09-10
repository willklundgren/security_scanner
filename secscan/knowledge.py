"""Knowledge base: what each vulnerability class *means*.

Every finding the scanner emits is an instance of one of the classes below.
The class supplies the four judgement axes the report is built around:

    impact          - consequences if it were exploited
    exploitability  - how easily it could be exploited
    prevalence      - how common the flaw is in real codebases
    news            - notable real-world incidents of this vulnerability type

Scores are 1-5 integers.  They are deliberately hand-set rather than derived
from CVSS: CVSS scores a *specific* CVE in a *specific* product, whereas these
describe the vulnerability class as it typically appears in application code.

Prevalence anchors cite the 2024 CWE Top 25 Most Dangerous Software Weaknesses
and the OWASP Top 10 (2021).  Both lists are periodically republished - refresh
`cwe_top25_rank` and `owasp` when a newer list lands.

The `news` entries are a curated, offline snapshot (see CURATED_AS_OF).  They
are intentionally limited to well-documented, widely-reported incidents.  For
genuinely current data the scanner enriches this at runtime from CISA's Known
Exploited Vulnerabilities catalog and the NVD API - see `secscan/news.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

CURATED_AS_OF = "2026-05"


@dataclass(frozen=True)
class NewsItem:
    """A real-world incident or advisory involving this vulnerability type."""

    date: str  # YYYY-MM
    headline: str
    summary: str
    source: str
    url: str

    def render(self) -> str:
        return f"{self.date}  {self.headline} ({self.source})"


@dataclass(frozen=True)
class VulnClass:
    key: str
    title: str
    cwe: str
    owasp: str

    impact: int
    impact_note: str

    exploitability: int
    exploitability_note: str

    prevalence: int
    prevalence_note: str

    remediation: str

    cwe_top25_rank: Optional[int] = None
    # True when the flaw exists *because* an attacker-controlled value reaches a
    # sink - injection, traversal, SSRF. For these, who controls the value is
    # the whole question, so a value that only the local caller controls is a
    # much weaker finding. False for flaws that are unsafe by construction
    # regardless of the data's origin: an unbounded strcpy, MD5, a disabled TLS
    # check, a committed credential. Those are not discounted for local input.
    taint_driven: bool = False
    news: Tuple[NewsItem, ...] = ()
    references: Tuple[str, ...] = ()
    # Keywords used to match live CISA KEV / NVD records to this class.
    feed_keywords: Tuple[str, ...] = ()

    @property
    def cwe_id(self) -> str:
        """'CWE-89' -> '89'-bearing id usable against the NVD API."""
        return self.cwe.split(":")[0].strip()


def _n(date: str, headline: str, summary: str, source: str, url: str) -> NewsItem:
    return NewsItem(date=date, headline=headline, summary=summary, source=source, url=url)


VULN_CLASSES: Dict[str, VulnClass] = {}


def _add(vc: VulnClass) -> VulnClass:
    VULN_CLASSES[vc.key] = vc
    return vc


# --------------------------------------------------------------------------
# Injection
# --------------------------------------------------------------------------

_add(VulnClass(
    key="sql-injection",
    taint_driven=True,
    title="SQL injection",
    cwe="CWE-89",
    owasp="A03:2021 - Injection",
    cwe_top25_rank=3,
    impact=5,
    impact_note=(
        "Full read/write access to the database behind the query: credential and PII "
        "theft, silent data tampering, authentication bypass. On many engines it "
        "escalates to file read/write or OS command execution on the database host, "
        "which turns a single query into a foothold on internal infrastructure."
    ),
    exploitability=5,
    exploitability_note=(
        "Remotely reachable with no authentication in the common case. Fully "
        "automated by commodity tooling (sqlmap) and by scanners that mass-scan the "
        "internet, so discovery-to-exploitation is minutes, not days. Blind and "
        "time-based variants need no error output."
    ),
    prevalence=5,
    prevalence_note=(
        "#3 on the 2024 CWE Top 25 and part of OWASP's Injection category. Endemic "
        "anywhere strings are concatenated into queries - most often in reporting, "
        "search, and admin endpoints that skipped the ORM."
    ),
    remediation=(
        "Use parameterised queries/prepared statements exclusively; pass user data as "
        "bound parameters, never as string fragments. If an identifier (table/column) "
        "must vary, map user input through an allowlist. ORMs help only when you avoid "
        "their raw-SQL escape hatches."
    ),
    news=(
        _n("2023-06", "MOVEit Transfer SQL injection drives mass extortion campaign",
           "CVE-2023-34362, a SQL injection in Progress MOVEit Transfer, was exploited "
           "as a zero-day by the Cl0p ransomware group; thousands of organisations and "
           "tens of millions of individuals were affected in one of the largest data-theft "
           "campaigns on record.",
           "CISA/FBI joint advisory AA23-158A",
           "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a"),
        _n("2023-05", "MOVEit flaw added to CISA's Known Exploited Vulnerabilities catalog",
           "CISA ordered federal agencies to patch the MOVEit SQL injection under BOD 22-01, "
           "confirming active exploitation in the wild.",
           "CISA KEV",
           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        "https://cwe.mitre.org/data/definitions/89.html",
    ),
    feed_keywords=("sql injection", "sqli"),
))

_add(VulnClass(
    key="command-injection",
    taint_driven=True,
    title="OS command injection",
    cwe="CWE-78",
    owasp="A03:2021 - Injection",
    cwe_top25_rank=6,
    impact=5,
    impact_note=(
        "Arbitrary command execution as the service account - the attacker inherits "
        "every privilege and credential the process holds. Typically the end of the "
        "engagement: shell, persistence, lateral movement, and access to cloud instance "
        "metadata and any mounted secrets."
    ),
    exploitability=5,
    exploitability_note=(
        "Trivial once a shell metacharacter reaches the command line: a single ';', "
        "'|', '$()' or backtick in a request parameter. No exploit development, no "
        "memory-layout knowledge, and it is reliable across versions and platforms."
    ),
    prevalence=4,
    prevalence_note=(
        "#6 on the 2024 CWE Top 25. Concentrated in glue code - image/PDF conversion, "
        "archive handling, network diagnostics, backup and deploy scripts - and in "
        "appliance and router firmware, where it is close to a default finding."
    ),
    remediation=(
        "Avoid the shell: pass an argument list (e.g. subprocess.run([...], shell=False)) "
        "so the OS never re-parses your string. Prefer a library call over shelling out. "
        "If a shell is unavoidable, allowlist the input against a strict pattern - "
        "escaping/quoting by hand is a losing game."
    ),
    news=(
        _n("2024-04", "Palo Alto GlobalProtect command injection exploited as a zero-day",
           "CVE-2024-3400, an unauthenticated command injection in PAN-OS GlobalProtect, "
           "was exploited in the wild to plant backdoors on internet-facing firewalls; "
           "CISA added it to the KEV catalog within a day of disclosure.",
           "CISA KEV / Palo Alto Networks advisory",
           "https://security.paloaltonetworks.com/CVE-2024-3400"),
        _n("2024-01", "Ivanti Connect Secure command injection chained for unauthenticated RCE",
           "CVE-2024-21887 (command injection) chained with CVE-2023-46805 (auth bypass) "
           "gave unauthenticated remote code execution on Ivanti VPN appliances and was "
           "mass-exploited; CISA issued an emergency directive to disconnect them.",
           "CISA Emergency Directive 24-01",
           "https://www.cisa.gov/news-events/directives/ed-24-01-mitigate-ivanti-connect-secure-and-ivanti-policy-secure-vulnerabilities"),
    ),
    references=(
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    ),
    feed_keywords=("command injection", "os command", "shell injection"),
))

_add(VulnClass(
    key="code-injection",
    taint_driven=True,
    title="Code injection / dynamic evaluation",
    cwe="CWE-94",
    owasp="A03:2021 - Injection",
    cwe_top25_rank=9,
    impact=5,
    impact_note=(
        "Attacker-supplied code runs inside your process with your interpreter's full "
        "power - equivalent to remote code execution, plus direct access to in-memory "
        "secrets, database handles and session state."
    ),
    exploitability=4,
    exploitability_note=(
        "Easy when input reaches eval/exec unfiltered. Sandboxes and 'safe' evaluators "
        "are routinely escaped (attribute traversal in Python, constructor chains in JS), "
        "so partial filtering buys little. Requires slightly more craft than SQL injection."
    ),
    prevalence=3,
    prevalence_note=(
        "#9 on the 2024 CWE Top 25. Less common than SQLi in mainstream web code, but "
        "persistent in plugin systems, rules/formula engines, template rendering, "
        "notebook tooling and admin consoles."
    ),
    remediation=(
        "Delete the dynamic evaluation. Parse structured data with a real parser "
        "(json.loads, ast.literal_eval); dispatch behaviour through an explicit "
        "dict/registry keyed by validated input rather than by building code strings."
    ),
    news=(
        _n("2022-03", "Spring4Shell turns data binding into remote code execution",
           "CVE-2022-22965 let attackers reach class-loader properties through Spring's "
           "request-parameter binding and write a JSP web shell; exploitation began within "
           "days of public disclosure and it was added to CISA's KEV catalog.",
           "CISA KEV / VMware advisory",
           "https://nvd.nist.gov/vuln/detail/CVE-2022-22965"),
        _n("2021-12", "Log4Shell: expression injection in a logging call",
           "CVE-2021-44228 turned any logged attacker-controlled string into remote code "
           "execution via JNDI lookups. CISA called it one of the most serious flaws it had "
           "seen; exploitation was global within 24 hours and continued for years.",
           "CISA advisory AA21-356A",
           "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a"),
    ),
    references=("https://cwe.mitre.org/data/definitions/94.html",),
    feed_keywords=("code injection", "remote code execution", "expression language"),
))

_add(VulnClass(
    key="template-injection",
    taint_driven=True,
    title="Server-side template injection (SSTI)",
    cwe="CWE-1336",
    owasp="A03:2021 - Injection",
    impact=5,
    impact_note=(
        "Template engines expose Python/Java/Ruby object graphs, so SSTI usually "
        "escalates to full remote code execution rather than mere information "
        "disclosure - and it runs with the web application's privileges."
    ),
    exploitability=4,
    exploitability_note=(
        "Detected with a one-character probe ('{{7*7}}' returning 49) and escalated with "
        "published, engine-specific payload chains. Widely covered in tooling and training."
    ),
    prevalence=2,
    prevalence_note=(
        "Uncommon overall but concentrated in a recognisable pattern: user-editable "
        "email/report/notification templates, CMS themes and low-code builders."
    ),
    remediation=(
        "Never build a template from user input - pass user data as *context variables* "
        "to a static template. If users must supply templates, use a logic-less engine "
        "(Mustache) or a sandboxed engine in a separate, unprivileged process."
    ),
    news=(
        _n("2025-04", "Craft CMS template-related RCE exploited in the wild",
           "Chained zero-days against Craft CMS (including CVE-2025-32432) were used to "
           "compromise servers; CISA added the flaw to its Known Exploited Vulnerabilities "
           "catalog, illustrating that template-layer RCE is actively hunted.",
           "CISA KEV",
           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ),
    references=("https://portswigger.net/web-security/server-side-template-injection",),
    feed_keywords=("template injection", "ssti"),
))

_add(VulnClass(
    key="deserialization",
    taint_driven=True,
    title="Insecure deserialization",
    cwe="CWE-502",
    owasp="A08:2021 - Software and Data Integrity Failures",
    impact=5,
    impact_note=(
        "Deserialising untrusted data instantiates attacker-chosen objects and invokes "
        "their lifecycle hooks - reliably remote code execution with public gadget chains "
        "(ysoserial for Java/.NET, pickle's __reduce__ in Python)."
    ),
    exploitability=4,
    exploitability_note=(
        "No custom research needed when a known gadget is on the classpath: generate a "
        "payload, send it in a cookie, cache entry or message body. The hard part is "
        "finding the entry point, not writing the exploit."
    ),
    prevalence=3,
    prevalence_note=(
        "OWASP A08 category. Common in Java enterprise stacks, .NET, and any Python "
        "service that pickles cache entries, job queues or session data."
    ),
    remediation=(
        "Exchange data in a data-only format (JSON) with a schema. Never unpickle or "
        "Java-deserialise untrusted bytes. If you must, sign the payload with an HMAC you "
        "verify before parsing, and restrict allowed classes explicitly."
    ),
    news=(
        _n("2023-02", "Fortra GoAnywhere deserialization flaw fuels ransomware extortion",
           "CVE-2023-0669, a deserialization bug in GoAnywhere MFT's admin console, was "
           "exploited as a zero-day by the Cl0p group against 100+ organisations before "
           "patches were widely deployed.",
           "CISA KEV / Fortra advisory",
           "https://nvd.nist.gov/vuln/detail/CVE-2023-0669"),
    ),
    references=(
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    ),
    feed_keywords=("deserialization", "deserialisation", "unsafe object"),
))

_add(VulnClass(
    key="xss",
    taint_driven=True,
    title="Cross-site scripting (XSS)",
    cwe="CWE-79",
    owasp="A03:2021 - Injection",
    cwe_top25_rank=1,
    impact=4,
    impact_note=(
        "Runs attacker JavaScript in a victim's session: session/token theft, silent "
        "action-on-behalf-of-user, credential harvesting via injected forms, and "
        "full defacement. Stored XSS in an admin view escalates to account takeover of "
        "the whole tenant; impact stops short of server compromise."
    ),
    exploitability=4,
    exploitability_note=(
        "Reflected variants need a victim to open a link (phishing/social step); stored "
        "variants need only that someone views the page. Payloads and filter bypasses are "
        "commodity knowledge and browser-agnostic."
    ),
    prevalence=5,
    prevalence_note=(
        "#1 on the 2024 CWE Top 25 - the single most reported weakness class. Ubiquitous "
        "wherever templates are bypassed with raw/unsafe helpers or the DOM is built with "
        "innerHTML."
    ),
    remediation=(
        "Let the template engine auto-escape and stop overriding it (no mark_safe, |safe, "
        "dangerouslySetInnerHTML, innerHTML). Encode per context (HTML body, attribute, JS, "
        "URL). Sanitise rich text with a vetted library (DOMPurify, bleach) and deploy a "
        "strict Content-Security-Policy as a second layer."
    ),
    news=(
        _n("2024-11", "XSS ranks #1 in the 2024 CWE Top 25",
           "MITRE and CISA's 2024 Top 25 Most Dangerous Software Weaknesses placed "
           "cross-site scripting first by combined frequency and severity across CVEs "
           "analysed, ahead of out-of-bounds write and SQL injection.",
           "MITRE / CISA",
           "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html"),
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    ),
    feed_keywords=("cross-site scripting", "xss"),
))

_add(VulnClass(
    key="path-traversal",
    taint_driven=True,
    title="Path traversal",
    cwe="CWE-22",
    owasp="A01:2021 - Broken Access Control",
    cwe_top25_rank=5,
    impact=4,
    impact_note=(
        "Reads any file the process can read - /etc/passwd, .env files, cloud credentials, "
        "SSH keys, source code. Where the path feeds a write, it becomes arbitrary file "
        "write, which usually converts to code execution by dropping a web shell or "
        "overwriting a cron/startup file."
    ),
    exploitability=5,
    exploitability_note=(
        "'../../' in a parameter. Encoding tricks (%2e%2e%2f, double encoding, UNC paths) "
        "defeat naive filters, and every scanner tests for it automatically."
    ),
    prevalence=4,
    prevalence_note=(
        "#5 on the 2024 CWE Top 25. Very common in file download/upload endpoints, static "
        "asset servers, template loaders, and archive extraction ('zip-slip')."
    ),
    remediation=(
        "Never build a path from user input directly. Resolve the candidate path "
        "(os.path.realpath) and verify it is inside the intended base directory before "
        "opening it; better, index files by opaque ID and look the real path up server-side."
    ),
    news=(
        _n("2024-02", "ConnectWise ScreenConnect path traversal exploited within days",
           "CVE-2024-1708 (path traversal), chained with an authentication bypass, was used "
           "to deploy ransomware and remote-access tooling on managed-service-provider "
           "servers shortly after disclosure.",
           "CISA KEV / ConnectWise advisory",
           "https://nvd.nist.gov/vuln/detail/CVE-2024-1708"),
        _n("2021-10", "Apache HTTP Server path traversal exploited hours after patch",
           "CVE-2021-41773 allowed reading files outside the document root and, with CGI "
           "enabled, remote code execution; mass scanning began almost immediately.",
           "Apache / CISA KEV",
           "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"),
    ),
    references=("https://cwe.mitre.org/data/definitions/22.html",),
    feed_keywords=("path traversal", "directory traversal", "relative path"),
))

_add(VulnClass(
    key="ssrf",
    taint_driven=True,
    title="Server-side request forgery (SSRF)",
    cwe="CWE-918",
    owasp="A10:2021 - Server-Side Request Forgery",
    impact=4,
    impact_note=(
        "Turns your server into a proxy into the internal network: cloud instance-metadata "
        "credentials, internal admin panels, databases and Kubernetes APIs that trust "
        "network position instead of authentication. Frequently the first hop of a full "
        "cloud-account compromise."
    ),
    exploitability=4,
    exploitability_note=(
        "Supply a URL and observe. Blind SSRF is exploitable via out-of-band callbacks; "
        "DNS-rebinding and redirect chains defeat naive allowlists. Well-known payload sets "
        "exist for every major cloud's metadata endpoint."
    ),
    prevalence=3,
    prevalence_note=(
        "Its own OWASP Top 10 category (A10:2021) after community survey ranking. Common in "
        "webhooks, link previews/unfurlers, PDF and image renderers, and file-import features."
    ),
    remediation=(
        "Allowlist destination hosts and schemes; resolve DNS first and reject private, "
        "link-local (169.254.0.0/16) and loopback ranges - re-checking after every redirect. "
        "Disable redirect following. Enforce IMDSv2 / metadata-service hardening so a "
        "successful SSRF still yields nothing."
    ),
    news=(
        _n("2019-07", "Capital One breach: SSRF to cloud metadata credentials",
           "An SSRF against a misconfigured WAF let an attacker retrieve EC2 instance-metadata "
           "credentials and exfiltrate data on ~100 million customers; the bank was fined "
           "$80M by the OCC. The case remains the reference example for SSRF impact.",
           "US Dept. of Justice / OCC",
           "https://www.justice.gov/usao-wdwa/pr/seattle-tech-worker-arrested-data-theft-involving-large-financial-services"),
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    feed_keywords=("server-side request forgery", "ssrf"),
))

_add(VulnClass(
    key="xxe",
    taint_driven=True,
    title="XML external entity injection (XXE)",
    cwe="CWE-611",
    owasp="A05:2021 - Security Misconfiguration",
    impact=4,
    impact_note=(
        "Reads local files and internal URLs through the XML parser (a specialised SSRF), "
        "and the 'billion laughs' variant exhausts memory for denial of service. Some "
        "parsers/expect handlers escalate to command execution."
    ),
    exploitability=3,
    exploitability_note=(
        "Requires an XML entry point (SOAP, SAML, DOCX/SVG upload, RSS import) and often "
        "out-of-band exfiltration for blind cases. Payloads are standard, but modern parser "
        "defaults increasingly disable external entities."
    ),
    prevalence=2,
    prevalence_note=(
        "Declining as parsers ship secure defaults, but still routine in SAML/SSO endpoints, "
        "legacy SOAP services and document-processing pipelines."
    ),
    remediation=(
        "Disable DTD processing and external entity resolution on every parser instance; in "
        "Python use defusedxml. Prefer JSON where you control the format."
    ),
    news=(
        _n("2018-01", "XXE enters the OWASP Top 10 as its own category",
           "OWASP added XXE (A4:2017) after tooling made it easy to find at scale; it was "
           "later folded into Security Misconfiguration in the 2021 list as parser defaults "
           "improved.",
           "OWASP",
           "https://owasp.org/www-project-top-ten/"),
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html",
    ),
    feed_keywords=("xml external entity", "xxe"),
))

# --------------------------------------------------------------------------
# Secrets, crypto, identity
# --------------------------------------------------------------------------

_add(VulnClass(
    key="hardcoded-secret",
    title="Hardcoded credential or API key",
    cwe="CWE-798",
    owasp="A07:2021 - Identification and Authentication Failures",
    impact=5,
    impact_note=(
        "A committed credential is valid everywhere the service is reachable and survives "
        "in git history after deletion. Cloud keys mean data-store access and resource "
        "abuse; signing keys mean forged tokens. Rotation is often organisation-wide and "
        "expensive."
    ),
    exploitability=5,
    exploitability_note=(
        "No exploitation skill at all - copy and use. Bots scan public GitHub pushes "
        "continuously and abuse leaked cloud keys within minutes; internal repos, CI logs "
        "and container images leak them just as readily."
    ),
    prevalence=5,
    prevalence_note=(
        "Among the most frequently reported issues in code-scanning corpora; GitHub's "
        "secret-scanning programme reports millions of leaked credentials detected per year "
        "across public repositories."
    ),
    remediation=(
        "Move the value to a secret manager or environment variable injected at deploy time. "
        "Assume any committed secret is burned: rotate it, then purge history "
        "(git filter-repo) and enable push protection / pre-commit secret scanning."
    ),
    news=(
        _n("2024-01", "Mercedes-Benz internal source code exposed by a leaked GitHub token",
           "A GitHub token committed in a public repository gave access to internal "
           "repositories containing source code, cloud keys and design documents - a plain "
           "hardcoded-credential failure at enterprise scale.",
           "RedHunt Labs / TechCrunch",
           "https://techcrunch.com/2024/01/29/mercedes-benz-source-code-github-token/"),
        _n("2023-09", "Microsoft AI researchers leak 38TB via an over-permissive SAS token",
           "A token committed to a public repo for sharing training data also granted access "
           "to internal backups, secrets and Teams messages - a credential-scope failure "
           "rather than a code bug.",
           "Wiz Research",
           "https://www.wiz.io/blog/38-terabytes-of-private-data-accidentally-exposed-by-microsoft-ai-researchers"),
        _n("2022-10", "Toyota exposes customer data key in a public repository",
           "An access key committed to GitHub sat public for roughly five years, exposing "
           "email addresses and customer numbers for ~296,000 T-Connect users.",
           "Toyota / BleepingComputer",
           "https://www.bleepingcomputer.com/news/security/toyota-discloses-data-breach-after-source-code-exposed-on-github/"),
    ),
    references=("https://cwe.mitre.org/data/definitions/798.html",),
    feed_keywords=("hard-coded credential", "hardcoded password", "default credential"),
))

_add(VulnClass(
    key="weak-crypto",
    title="Broken or weak cryptography",
    cwe="CWE-327",
    owasp="A02:2021 - Cryptographic Failures",
    impact=3,
    impact_note=(
        "Depends on use. MD5/SHA-1 for signatures or integrity permits forgery via "
        "collisions; DES/RC4/ECB leaks plaintext structure and enables decryption or "
        "tampering. Rarely instant compromise on its own, but it undermines every control "
        "built on top of it."
    ),
    exploitability=2,
    exploitability_note=(
        "Needs cryptographic work or specific conditions - chosen-prefix collisions, large "
        "ciphertext corpora, or an oracle. Real but not point-and-click; the exception is "
        "ECB mode, where structure is visible by eye."
    ),
    prevalence=4,
    prevalence_note=(
        "OWASP A02 - moved up to #2 in 2021. Legacy MD5/SHA-1 lingers throughout codebases, "
        "often for non-security purposes but rarely labelled as such."
    ),
    remediation=(
        "Use SHA-256/SHA-3 for hashing, AES-GCM or ChaCha20-Poly1305 for encryption, and a "
        "high-level library (libsodium, cryptography's Fernet) over primitives. Where a hash "
        "is genuinely non-security (cache key, sharding), say so explicitly - Python's "
        "hashlib accepts usedforsecurity=False."
    ),
    news=(
        _n("2022-12", "NIST sets a 2030 deadline to retire SHA-1",
           "NIST announced SHA-1 must be phased out of federal use by 31 December 2030, "
           "citing practical collision attacks; SHA-1 and MD5 are unsuitable for any "
           "integrity or signature purpose.",
           "NIST",
           "https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm"),
        _n("2017-02", "SHAttered: first practical SHA-1 collision",
           "Google and CWI produced two different PDFs with the same SHA-1 hash, moving "
           "collision attacks from theory to demonstrated practice.",
           "Google / CWI Amsterdam",
           "https://shattered.io/"),
    ),
    references=("https://cwe.mitre.org/data/definitions/327.html",),
    feed_keywords=("weak cryptograph", "broken cryptograph", "md5", "sha-1"),
))

_add(VulnClass(
    key="weak-random",
    title="Insecure randomness for security values",
    cwe="CWE-338",
    owasp="A02:2021 - Cryptographic Failures",
    impact=4,
    impact_note=(
        "Predictable tokens defeat the control they protect: guessable password-reset links, "
        "forgeable session IDs, predictable API keys or wallet seeds. The result is account "
        "takeover without touching the authentication code."
    ),
    exploitability=3,
    exploitability_note=(
        "Requires collecting sample outputs and recovering PRNG state - well-documented for "
        "Mersenne Twister (Python/PHP/Java Random) with public tooling, but it is a deliberate "
        "attack rather than an accident."
    ),
    prevalence=3,
    prevalence_note=(
        "Common wherever a developer reached for the obvious random API. Frequently found in "
        "token/OTP/coupon/filename generation - the language default is almost never a CSPRNG."
    ),
    remediation=(
        "Use a cryptographically secure source: Python secrets, Node crypto.randomBytes, "
        "Java SecureRandom, Go crypto/rand. Reserve math/statistical RNGs for simulation and "
        "sampling."
    ),
    news=(
        _n("2023-08", "'Milk Sad': weak randomness drains cryptocurrency wallets",
           "CVE-2023-39910 - Libbitcoin Explorer seeded key generation from a 32-bit Mersenne "
           "Twister, letting researchers and thieves brute-force wallet keys; roughly $900,000 "
           "was stolen from affected wallets.",
           "Milk Sad research team / NVD",
           "https://milksad.info/"),
        _n("2022-04", "Trust Wallet browser extension generated predictable seed phrases",
           "A weak PRNG in mnemonic generation made wallets brute-forceable; funds were at "
           "risk for every wallet created during the affected window.",
           "Trust Wallet / Ledger Donjon",
           "https://community.trustwallet.com/t/wallet-extension-security-incident/523425"),
    ),
    references=("https://cwe.mitre.org/data/definitions/338.html",),
    feed_keywords=("insufficient entropy", "predictable", "random"),
))

_add(VulnClass(
    key="weak-password-hash",
    title="Weak password storage",
    cwe="CWE-916",
    owasp="A02:2021 - Cryptographic Failures",
    impact=4,
    impact_note=(
        "When the database leaks - and breach data circulates for years - fast or unsalted "
        "hashes are cracked in bulk on commodity GPUs. Users' credentials are then replayed "
        "against every other service they use."
    ),
    exploitability=2,
    exploitability_note=(
        "Only matters after another compromise gives up the hashes, but from that point "
        "cracking is mechanical: hashcat plus a wordlist recovers most real-world passwords "
        "from MD5/SHA-family hashes."
    ),
    prevalence=3,
    prevalence_note=(
        "Still routine in bespoke authentication code and legacy systems; frameworks with "
        "built-in auth have largely fixed it by default."
    ),
    remediation=(
        "Use a memory-hard, tunable KDF - Argon2id (preferred), scrypt, or bcrypt - via a "
        "maintained library, with per-user salts handled by that library. Follow current "
        "OWASP parameter guidance and re-hash on login when parameters change."
    ),
    news=(
        _n("2022-12", "LastPass vault theft puts hash iteration counts under scrutiny",
           "Attackers exfiltrated encrypted customer vaults; reporting focused on legacy "
           "accounts left at low PBKDF2 iteration counts, making offline cracking of weaker "
           "master passwords feasible.",
           "LastPass / Ars Technica",
           "https://blog.lastpass.com/posts/notice-of-recent-security-incident"),
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
    ),
    feed_keywords=("password hash", "weak hash", "unsalted"),
))

_add(VulnClass(
    key="tls-verification-disabled",
    title="Certificate/TLS verification disabled",
    cwe="CWE-295",
    owasp="A02:2021 - Cryptographic Failures",
    impact=4,
    impact_note=(
        "Removes the guarantee that you are talking to the right server. An attacker on the "
        "network path reads and rewrites traffic - stealing the credentials and tokens the "
        "call carries, and tampering with responses (including software updates)."
    ),
    exploitability=3,
    exploitability_note=(
        "Needs a network position: hostile Wi-Fi, a compromised hop, ARP/DNS spoofing on a "
        "shared LAN, or a malicious egress proxy. Once positioned, off-the-shelf tooling "
        "(mitmproxy) makes interception trivial."
    ),
    prevalence=4,
    prevalence_note=(
        "Very common - typically a debugging workaround for a self-signed certificate that "
        "was never reverted, then copied into production code and internal tooling."
    ),
    remediation=(
        "Keep verification on. For internal/self-signed certificates, add the CA to the trust "
        "store or pass its bundle explicitly (verify='/path/ca.pem') instead of verify=False. "
        "Gate any relaxation behind an explicit development-only configuration flag."
    ),
    news=(
        _n("2014-02", "Apple 'goto fail' broke TLS certificate validation",
           "A duplicated goto skipped signature verification in iOS and macOS, silently "
           "disabling certificate checks for all TLS connections - the canonical demonstration "
           "of how invisible this class of bug is.",
           "Apple / CVE-2014-1266",
           "https://nvd.nist.gov/vuln/detail/CVE-2014-1266"),
    ),
    references=("https://cwe.mitre.org/data/definitions/295.html",),
    feed_keywords=("certificate validation", "improper certificate", "man-in-the-middle"),
))

_add(VulnClass(
    key="jwt-verification",
    title="Unverified or weakly verified JWT",
    cwe="CWE-347",
    owasp="A07:2021 - Identification and Authentication Failures",
    impact=5,
    impact_note=(
        "Skipping signature verification means anyone can mint a token claiming any user or "
        "role - complete authentication and authorisation bypass, typically including "
        "administrator impersonation, with no audit trail distinguishing it from a real login."
    ),
    exploitability=5,
    exploitability_note=(
        "Edit the base64 payload and send it. The 'alg: none' and HS256/RS256 confusion "
        "tricks are in every web-security curriculum, and jwt_tool automates them."
    ),
    prevalence=3,
    prevalence_note=(
        "Frequent in hand-rolled auth middleware and in code that decodes a token twice - "
        "once unverified to read the issuer, once properly - and forgets the second step."
    ),
    remediation=(
        "Always verify: pin the expected algorithm(s), verify the signature against the "
        "correct key, and check exp/nbf/iss/aud. Use decode(..., algorithms=['RS256']) and "
        "never accept the algorithm from the token header."
    ),
    news=(
        _n("2022-12", "RCE in the 'jsonwebtoken' library via key handling",
           "CVE-2022-23529 in jsonwebtoken (<9.0.0, ~9M weekly downloads at the time) allowed "
           "code execution when verifying a token with an attacker-influenced key - a reminder "
           "that token verification code is itself an attack surface.",
           "Palo Alto Unit 42 / NVD",
           "https://nvd.nist.gov/vuln/detail/CVE-2022-23529"),
    ),
    references=("https://cwe.mitre.org/data/definitions/347.html",),
    feed_keywords=("jwt", "json web token", "signature verification"),
))

# --------------------------------------------------------------------------
# Configuration & web plumbing
# --------------------------------------------------------------------------

_add(VulnClass(
    key="debug-exposure",
    title="Debug mode / diagnostic endpoint exposed",
    cwe="CWE-489",
    owasp="A05:2021 - Security Misconfiguration",
    impact=4,
    impact_note=(
        "Debug pages leak stack traces, configuration, environment variables and secrets. "
        "Several frameworks go further: Flask's Werkzeug debugger and Django's technical 500 "
        "page can hand over an interactive console or the SECRET_KEY, which is code execution "
        "or session forgery."
    ),
    exploitability=4,
    exploitability_note=(
        "Just request the page and trigger an error. Shodan and mass scanners index exposed "
        "debug consoles continuously, so exposure is found without targeting you."
    ),
    prevalence=4,
    prevalence_note=(
        "OWASP A05 - one of the most common categories overall. Usually a staging setting "
        "promoted to production or a default left in place."
    ),
    remediation=(
        "Drive debug from environment configuration that defaults to off, and assert it is "
        "off in production startup checks. Bind admin/diagnostic listeners to localhost and "
        "put them behind authentication."
    ),
    news=(
        _n("2021-05", "OWASP Top 10 2021 elevates Security Misconfiguration to #5",
           "OWASP moved misconfiguration up the list, noting that 90% of applications tested "
           "showed some form of it - debug flags and default settings prominent among them.",
           "OWASP",
           "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    ),
    references=("https://cwe.mitre.org/data/definitions/489.html",),
    feed_keywords=("debug", "misconfiguration", "information disclosure"),
))

_add(VulnClass(
    key="permissive-cors",
    title="Overly permissive CORS policy",
    cwe="CWE-942",
    owasp="A05:2021 - Security Misconfiguration",
    impact=3,
    impact_note=(
        "Lets any origin read authenticated responses from your API. Combined with cookie "
        "credentials it becomes cross-origin data theft: an attacker's page reads a victim's "
        "data with the victim's session."
    ),
    exploitability=3,
    exploitability_note=(
        "Requires luring an authenticated user to a page you control, then a few lines of "
        "fetch(). Reflecting the Origin header with credentials:true is the dangerous form; "
        "wildcard alone is blocked by browsers for credentialed requests."
    ),
    prevalence=4,
    prevalence_note=(
        "Very common. '*' or a reflected Origin is the standard way developers make a CORS "
        "error message go away, and it rarely gets revisited."
    ),
    remediation=(
        "Allowlist exact origins from configuration; never reflect the Origin header "
        "unchecked, and never combine a wildcard with credentials. Prefer token auth in an "
        "Authorization header over cookies for cross-origin APIs."
    ),
    references=("https://cwe.mitre.org/data/definitions/942.html",),
    feed_keywords=("cors", "cross-origin"),
))

_add(VulnClass(
    key="csrf",
    title="Missing CSRF protection",
    cwe="CWE-352",
    owasp="A01:2021 - Broken Access Control",
    cwe_top25_rank=4,
    impact=3,
    impact_note=(
        "State-changing actions performed as the victim: email/password change leading to "
        "account takeover, funds transfer, privilege grants. The attacker acts blind (no "
        "response read) but the write still lands."
    ),
    exploitability=3,
    exploitability_note=(
        "An auto-submitting form on any page the victim visits. Modern SameSite=Lax cookie "
        "defaults blunt the classic attack, which is why this rates lower than it once did - "
        "but explicit SameSite=None or custom auth headers reopen it."
    ),
    prevalence=4,
    prevalence_note=(
        "#4 on the 2024 CWE Top 25. Usually appears as a deliberate exemption - a decorator "
        "disabling the framework's protection for a webhook or legacy client."
    ),
    remediation=(
        "Keep the framework's CSRF middleware on and use synchroniser tokens for cookie-"
        "authenticated state changes. Set SameSite=Lax or Strict. For webhooks, verify an "
        "HMAC signature instead of exempting the endpoint outright."
    ),
    references=(
        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    ),
    feed_keywords=("cross-site request forgery", "csrf"),
))

_add(VulnClass(
    key="insecure-cookie",
    title="Insecure cookie attributes",
    cwe="CWE-614",
    owasp="A05:2021 - Security Misconfiguration",
    impact=3,
    impact_note=(
        "A session cookie without Secure can be captured over plaintext HTTP; without "
        "HttpOnly it is readable by any XSS payload. Either way the outcome is session theft "
        "and impersonation."
    ),
    exploitability=2,
    exploitability_note=(
        "Not directly exploitable - it removes a mitigation. Needs a companion condition "
        "(network position, or an XSS elsewhere in the app) to convert into a real session "
        "compromise."
    ),
    prevalence=4,
    prevalence_note=(
        "Widespread, particularly in hand-written cookie code and older frameworks whose "
        "defaults predate current guidance."
    ),
    remediation=(
        "Set Secure, HttpOnly and SameSite on every session/auth cookie; enforce HTTPS "
        "everywhere with HSTS. Prefix with __Host- where applicable."
    ),
    references=("https://cwe.mitre.org/data/definitions/614.html",),
    feed_keywords=("cookie", "session hijack"),
))

_add(VulnClass(
    key="open-redirect",
    taint_driven=True,
    title="Open redirect",
    cwe="CWE-601",
    owasp="A01:2021 - Broken Access Control",
    impact=2,
    impact_note=(
        "Lends your domain's credibility to a phishing page and can leak tokens in the "
        "Referer or through an OAuth redirect_uri. Low impact alone; meaningful as a link in "
        "a chain, especially against OAuth flows."
    ),
    exploitability=4,
    exploitability_note=(
        "Change a URL parameter. The only barrier is getting a victim to click, and the link "
        "genuinely starts with your trusted domain - which is the whole point."
    ),
    prevalence=4,
    prevalence_note=(
        "Very common in login/logout 'next' and 'returnUrl' parameters; a staple of bug-"
        "bounty reports and of phishing kits."
    ),
    remediation=(
        "Redirect only to relative paths, or map a short token to a server-side allowlist of "
        "destinations. Validate with a URL parser, not a startswith() check - "
        "'https://evil.com/?x=https://yoursite.com' passes naive tests."
    ),
    news=(
        _n("2021-08", "Phishing campaigns abuse open redirects on trusted domains",
           "Microsoft detailed a widespread campaign using open redirectors on well-known "
           "domains to make phishing links look legitimate and evade URL reputation filters.",
           "Microsoft Security Blog",
           "https://www.microsoft.com/en-us/security/blog/2021/08/26/widespread-credential-phishing-campaign-abuses-open-redirector-links/"),
    ),
    references=("https://cwe.mitre.org/data/definitions/601.html",),
    feed_keywords=("open redirect", "url redirection"),
))

_add(VulnClass(
    key="insecure-transport",
    title="Cleartext transmission of sensitive data",
    cwe="CWE-319",
    owasp="A02:2021 - Cryptographic Failures",
    impact=3,
    impact_note=(
        "Credentials, tokens and personal data are readable by anyone on the path and can be "
        "modified in flight. Also downgrades any authentication that rides on the connection."
    ),
    exploitability=3,
    exploitability_note=(
        "Passive capture needs only network presence; active tampering needs a "
        "man-in-the-middle position. No application-level exploitation required."
    ),
    prevalence=3,
    prevalence_note=(
        "Persistent in internal service-to-service calls, legacy integrations and "
        "configuration defaults, where 'it's on the private network' substitutes for encryption."
    ),
    remediation=(
        "Use HTTPS/TLS for every hop including internal ones; redirect HTTP to HTTPS and set "
        "HSTS. Use TLS-enabled ports for databases, brokers and caches."
    ),
    references=("https://cwe.mitre.org/data/definitions/319.html",),
    feed_keywords=("cleartext transmission", "unencrypted"),
))

_add(VulnClass(
    key="insecure-temp-file",
    title="Insecure temporary file handling",
    cwe="CWE-377",
    owasp="A01:2021 - Broken Access Control",
    impact=2,
    impact_note=(
        "A local attacker can win the race between name generation and file creation to read "
        "the contents or replace the file with a symlink, causing the privileged process to "
        "write where it should not."
    ),
    exploitability=2,
    exploitability_note=(
        "Requires local access on the same host and winning a timing race - practical on "
        "shared or multi-tenant systems, irrelevant on a single-tenant container."
    ),
    prevalence=2,
    prevalence_note=(
        "Occasional; mostly legacy uses of mktemp and hand-built /tmp paths in scripts and "
        "build tooling."
    ),
    remediation=(
        "Use tempfile.NamedTemporaryFile / mkstemp (atomic create with O_EXCL and 0600 "
        "permissions). Never generate a name and open it in a second step."
    ),
    references=("https://cwe.mitre.org/data/definitions/377.html",),
    feed_keywords=("temporary file", "symlink"),
))

_add(VulnClass(
    key="buffer-overflow",
    title="Unsafe memory operation (C/C++)",
    cwe="CWE-787",
    owasp="n/a (native code)",
    cwe_top25_rank=2,
    impact=5,
    impact_note=(
        "Memory corruption leads to code execution in the process's context, or at minimum a "
        "reliable crash. In privileged daemons and kernel code it means full system compromise; "
        "these are the bugs that get chained into remote exploits."
    ),
    exploitability=3,
    exploitability_note=(
        "Real exploitation requires bypassing ASLR, stack canaries, NX and CFI - skilled work "
        "measured in days, not minutes. But denial of service is usually immediate, and "
        "weaponised exploits for popular targets circulate widely once written."
    ),
    prevalence=4,
    prevalence_note=(
        "#2 on the 2024 CWE Top 25 (out-of-bounds write). Confined to native code, where it "
        "dominates - hence the industry push toward memory-safe languages."
    ),
    remediation=(
        "Replace unbounded APIs (strcpy, strcat, sprintf, gets) with bounded equivalents "
        "(snprintf, strlcpy) and check every length. Build with ASan/UBSan in CI, fuzz parsers, "
        "and prefer a memory-safe language for new components handling untrusted input."
    ),
    news=(
        _n("2024-07", "'regreSSHion' remote code execution in OpenSSH",
           "CVE-2024-6387, a memory-safety bug (signal-handler race) in OpenSSH's server, "
           "allowed unauthenticated remote code execution as root on glibc Linux; millions of "
           "internet-facing servers were affected.",
           "Qualys Threat Research / NVD",
           "https://nvd.nist.gov/vuln/detail/CVE-2024-6387"),
        _n("2023-10", "'Looney Tunables' glibc buffer overflow gives local root",
           "CVE-2023-4911, a buffer overflow in glibc's dynamic loader, provided full root on "
           "major Linux distributions and was quickly folded into attacker toolkits.",
           "Qualys / NVD",
           "https://nvd.nist.gov/vuln/detail/CVE-2023-4911"),
    ),
    references=("https://cwe.mitre.org/data/definitions/787.html",),
    feed_keywords=("buffer overflow", "out-of-bounds", "memory corruption", "use after free"),
))

_add(VulnClass(
    key="format-string",
    title="Uncontrolled format string",
    cwe="CWE-134",
    owasp="n/a (native code)",
    impact=4,
    impact_note=(
        "Format specifiers supplied by an attacker read the stack (%x, %s leak memory and "
        "pointers, defeating ASLR) and, with %n, write to chosen addresses - which converts "
        "an information leak into memory corruption and code execution."
    ),
    exploitability=3,
    exploitability_note=(
        "Trivial to detect (send '%x%x%x' and watch the output); weaponising %n into a write "
        "primitive is a well-documented but skilled exercise. Modern compilers warn about it "
        "and some libc builds restrict %n."
    ),
    prevalence=2,
    prevalence_note=(
        "Uncommon in new code - -Wformat-security catches most cases - but persistent in "
        "legacy C, embedded firmware and logging wrappers that pass a variable as the format."
    ),
    remediation=(
        "Never pass a runtime value as the format string: use printf(\"%s\", value) and "
        "fprintf(stream, \"%s\", value). Build with -Wformat -Wformat-security -Werror."
    ),
    references=("https://cwe.mitre.org/data/definitions/134.html",),
    feed_keywords=("format string",),
))

_add(VulnClass(
    key="prototype-pollution",
    taint_driven=True,
    title="Prototype pollution (JavaScript)",
    cwe="CWE-1321",
    owasp="A08:2021 - Software and Data Integrity Failures",
    impact=4,
    impact_note=(
        "Modifying Object.prototype changes behaviour application-wide: authorisation checks "
        "that read a missing property suddenly see an attacker-chosen value, and in Node it "
        "frequently chains to remote code execution through polluted options objects."
    ),
    exploitability=3,
    exploitability_note=(
        "Send JSON containing __proto__ or constructor.prototype to a deep-merge or "
        "path-assignment helper. Simple to trigger; turning pollution into RCE needs a gadget "
        "in the app's dependencies, which researchers have catalogued extensively."
    ),
    prevalence=3,
    prevalence_note=(
        "Common in the Node ecosystem, particularly in utility merge/clone/set helpers and "
        "query-string parsers; many high-profile packages have shipped a variant."
    ),
    remediation=(
        "Reject __proto__, constructor and prototype keys during merge/assignment; use Map or "
        "Object.create(null) for user-keyed data, and Object.freeze(Object.prototype) at "
        "startup as defence in depth. Keep merge utilities patched."
    ),
    news=(
        _n("2019-07", "Prototype pollution in lodash affects millions of projects",
           "CVE-2019-10744 in lodash's defaultsDeep allowed Object.prototype modification; "
           "lodash's download volume made it one of the most widely inherited vulnerabilities "
           "in the npm ecosystem.",
           "Snyk / NVD",
           "https://nvd.nist.gov/vuln/detail/CVE-2019-10744"),
    ),
    references=("https://cwe.mitre.org/data/definitions/1321.html",),
    feed_keywords=("prototype pollution",),
))

_add(VulnClass(
    key="ssl-hostname",
    title="Unrestricted or unsafe network binding",
    cwe="CWE-1327",
    owasp="A05:2021 - Security Misconfiguration",
    impact=3,
    impact_note=(
        "Binding a service to 0.0.0.0 exposes it to every network the host can reach. "
        "Development servers, debug consoles and databases meant for localhost become "
        "reachable from the LAN or, behind a permissive security group, the internet."
    ),
    exploitability=3,
    exploitability_note=(
        "No exploitation technique needed - the service is simply reachable. Internet-wide "
        "scanners (Shodan, Censys) inventory exposed services continuously."
    ),
    prevalence=3,
    prevalence_note=(
        "Common in containerised deployments where 0.0.0.0 is required inside the container "
        "but the port mapping or security group is then left too open."
    ),
    remediation=(
        "Bind to 127.0.0.1 unless the service is deliberately public; when a container "
        "requires 0.0.0.0, restrict exposure at the port mapping, security group and network "
        "policy, and require authentication regardless."
    ),
    references=("https://cwe.mitre.org/data/definitions/1327.html",),
    feed_keywords=("exposed service", "unauthenticated access"),
))


def get(key: str) -> VulnClass:
    return VULN_CLASSES[key]


def all_classes() -> Tuple[VulnClass, ...]:
    return tuple(VULN_CLASSES.values())
