# secscan

A static security scanner that doesn't just list findings — it tells you, for each one:

| | |
|---|---|
| **What it costs you** | The concrete consequences if the flaw were exploited |
| **How easily it's exploited** | Attacker effort, tooling, and whether untrusted input actually reaches *this* instance |
| **How common it is** | Where the weakness sits in the 2024 CWE Top 25 and OWASP Top 10 |
| **What it's been doing lately** | Real incidents of this vulnerability type, including live data from CISA's Known Exploited Vulnerabilities catalog |

Zero runtime dependencies. Python 3.9+. Standard library only.

```bash
python3 -m secscan /path/to/codebase
```

---

## Why the four dimensions matter

A list of 200 findings sorted by "severity" is a list nobody reads. The useful question is
never "is this a SQL injection?" — it's "should I stop what I'm doing and fix this today?"
That answer depends on what breaks if someone exploits it, how hard exploiting it actually
is *here*, how routinely attackers look for it, and whether it is being exploited in the
wild right now. secscan reports all four, separately, with its reasoning visible.

```
  [5] CRITICAL SQL injection · CWE-89 · risk 10.0/10
      app/views.py:28  (rule AST-PY-SQL, confidence high, reachable from untrusted input)
      │ cur.execute(f"SELECT id, name FROM products WHERE name LIKE '%{term}%'")
      SQL string is built from runtime values and then executed; the interpolated
      value becomes part of the query grammar.

      IF EXPLOITED    █████ 5/5
                      Full read/write access to the database behind the query:
                      credential and PII theft, silent data tampering,
                      authentication bypass. On many engines it escalates to file
                      read/write or OS command execution on the database host…
      EASE OF ATTACK  █████ 5/5
                      Remotely reachable with no authentication in the common case.
                      Fully automated by commodity tooling (sqlmap)… Here, untrusted
                      data reaches the sink directly - the value derives from
                      request.args, so no additional conditions are needed.
      HOW COMMON      █████ 5/5
                      #3 on the 2024 CWE Top 25 and part of OWASP's Injection
                      category. Endemic anywhere strings are concatenated into queries…
      IN THE NEWS
                      32 CVE(s) of this type in CISA's known-exploited catalog,
                      8 added in the last 365 days; 132 new CWE-89 CVEs published
                      in NVD in the last 120 days.
                      2026-09  CVE-2026-9586: Sangoma Switchvox SQL Injection
                        …
```

## Install

```bash
git clone <this repo> && cd security_scanner
python3 -m secscan --help          # run in place, no install needed
```

Or install the `secscan` command:

```bash
pip install -e .
```

## Usage

```bash
secscan .                                   # scan the current directory
secscan src/ --min-severity high            # only what's worth interrupting someone for
secscan . --format html -o report.html      # shareable report
secscan . --format sarif -o out.sarif       # GitHub code scanning / CI
secscan . --only sql-injection,xss          # one class at a time
secscan --explain ssrf                      # read the briefing without scanning
secscan . --detail full                     # full four-axis workup on every finding
```

### CI gate

```bash
secscan . --format sarif -o results.sarif --fail-on high
```

Exit codes: `0` clean (relative to `--fail-on`), `1` findings at or above the threshold,
`2` usage or runtime error.

### Baselines — adopting the tool on an existing codebase

Turning a scanner on a mature repo produces a wall of findings that everyone learns to
ignore. Record today's findings as accepted, then gate only on new ones:

```bash
secscan . --write-baseline .secscan-baseline.json   # once
secscan . --baseline .secscan-baseline.json --fail-on medium   # in CI
```

Baseline entries are content fingerprints, not line numbers, so they survive reformatting
and code moving around. Delete an entry to make that finding visible again.

### Suppressing a finding in code

```python
subprocess.run(cmd, shell=True)  # nosec — cmd is a constant built at import time
subprocess.run(cmd, shell=True)  # secscan:ignore AST-PY-SHELL
```

A bare `# nosec` silences the line; naming rule ids silences only those.
`// nosec` and `/* nosec */` work in C-family languages.

## What it looks at

**Languages.** Python, JavaScript/TypeScript, Java, Kotlin, Scala, Go, Ruby, PHP, C/C++,
C#, Perl, shell, HTML/Vue/Svelte templates, and config formats (YAML, TOML, INI, `.env`,
Terraform, Dockerfiles).

**Vulnerability classes** (26): SQL injection, OS command injection, code injection, SSTI,
insecure deserialization, XSS, path traversal, SSRF, XXE, hardcoded secrets, weak
cryptography, weak randomness, weak password storage, disabled TLS verification, unverified
JWTs, debug exposure, permissive CORS, missing CSRF protection, insecure cookies, open
redirect, cleartext transport, insecure temp files, memory-unsafe operations, format
strings, prototype pollution, unsafe network binding.

Run `secscan --list-classes` for the scored list, or `--list-rules` for all 55 pattern
rules, 14 secret patterns and 18 Python AST checks.

## How it decides

**Three passes.** A Python AST pass with lightweight taint tracking; a regex pass over
comment-stripped source for every language; and entropy-plus-format secret detection.

**The AST pass wins where it applies.** When a Python file parses cleanly, structural
checks replace their text-pattern equivalents entirely. `subprocess.run(cmd, shell=True)`
where `cmd` is a literal is a different finding from the same call where `cmd` came from
`request.args` — a regex cannot tell those apart, and reporting them identically is how
scanners lose their audience.

**Taint tracking is intraprocedural and flow-insensitive** — deliberately. It tracks values
derived from request objects, route-handler parameters, `input()`, `sys.argv` and
`os.environ` into sinks, over-approximating within a function and not following calls.
That is the honest trade-off for a tool that runs in under a second: it is not sound, and
it doesn't claim to be. Findings it can prove reachable are marked *reachable from untrusted
input* and score a point higher on exploitability.

**Not all untrusted input is equally untrusted.** `request.args` comes from a stranger;
`sys.argv` comes from whoever ran the program, who already holds its privileges. So
`open(sys.argv[1])` in a CLI is that CLI doing its job, not a path-traversal vulnerability —
it becomes one only in a setuid binary or a service invoked with caller-influenced
arguments. secscan tracks that distinction: locally-sourced taint is reported, explained,
and capped at `low` rather than shouting `critical`. The cap applies only to classes where
*who controls the value* is the whole question (injection, traversal, SSRF). An unbounded
`strcpy` or a hardcoded key is unsafe by construction and gets no such discount.

That one distinction cut this scanner's `critical` count on numpy from 28 to 20 with no
loss of real signal.

**Scoring.**

```
risk = (0.5 × impact + 0.3 × exploitability + 0.2 × prevalence) × 2     → 0–10
```

Impact and prevalence are properties of the vulnerability class. Exploitability is
adjusted per finding: `+1` when untrusted input demonstrably reaches it, `−2` when it sits
in test or example code. Low-confidence findings never present as `critical`.

**Precision measures.** When a Python file parses, structural checks replace their regex
equivalents outright. Comments are blanked before matching (with string literals kept
intact, and Ruby's `#{}` interpolation correctly treated as code). Import lines are not
treated as uses. Vendor documentation credentials — AWS's `AKIAIOSFODNN7EXAMPLE`, Stripe's
sample keys — are detected, labelled, and capped at `low` rather than reported as leaks.
Placeholders (`CHANGEME`, `<your-key>`, `${API_KEY}`, `os.environ[...]`) are dropped, and
generic secret matches must clear an entropy threshold. Secret values are redacted in
output.

## Where the news comes from

Two sources, disclosed in every report:

1. **CISA Known Exploited Vulnerabilities catalog** — the authoritative public list of CVEs
   with confirmed in-the-wild exploitation, matched to each finding by CWE. This is the
   strongest available "this is being exploited right now" signal. Fetched over HTTPS,
   cached 24h under `~/.cache/secscan/`.
2. **NVD CVE API 2.0** (with `--nvd`) — how many CVEs of this weakness type were published
   in the last 120 days, as a volume signal.

Behind those sits a curated offline set of well-documented incidents (MOVEit, Log4Shell,
Capital One, regreSSHion, Milk Sad, the Mercedes-Benz token leak…) used when the network is
unavailable. `--offline` never touches the network at all.

**Only CWE identifiers are sent to those feeds — never your code, paths or findings.**
TLS verification is always on; if your Python has no usable root store, secscan locates the
OS CA bundle rather than disabling verification.

## Try it

A deliberately vulnerable sample app ships in `demo/vulnerable_shop`:

```bash
python3 -m secscan demo/vulnerable_shop --no-test-heuristic
```

It should turn up 38 findings across 21 vulnerability types, including SQL injection
reachable from `request.args`, command injection via `shell=True`, pickle and YAML
deserialization of request bodies, SSTI, path traversal, SSRF with TLS verification
disabled, a hardcoded Stripe key and database password, `DEBUG = True`, `ALLOWED_HOSTS =
['*']`, `strcpy`/`printf` misuse in C, and prototype pollution in JavaScript.

`--no-test-heuristic` is needed because the demo lives under a path that looks like sample
code, which secscan otherwise treats as non-production and downgrades. Use the same flag if
your production code genuinely lives in a directory named `examples/`.

## Tests

```bash
python3 -m unittest discover -s tests
```

66 tests covering rule/knowledge-base integrity, true positives across seven languages,
false-positive resistance (parameterised SQL, argument-list subprocess,
`usedforsecurity=False`, `yaml.safe_load`, vulnerabilities inside comments and strings),
taint tracking, secret placeholder handling, scoring, all five output formats, baselines and
CLI exit codes.

## Limits — read this part

This is static pattern and AST analysis. It does not know about:

- **Business logic and authorisation.** The largest category of real breaches — an endpoint
  that forgets to check whether *this* user owns *that* order — is invisible to it.
- **Runtime and deployment configuration.** Reverse proxies, WAFs, security groups, IAM
  policies, and secrets injected at deploy time are all outside the file tree.
- **Vulnerable dependencies.** No CVE matching against your lockfiles; use `pip-audit`,
  `npm audit`, `osv-scanner` or Dependabot alongside it.
- **Interprocedural data flow.** Taint that crosses a function boundary is not followed, so
  a genuine injection can be missed.

It will also produce false positives. That is the intended trade: for the classes it
covers, recall matters more than a quiet report, which is why every finding carries a
confidence level and the reasoning behind its score.

**A clean scan is not an audit.** Treat it as a fast first pass that removes the obvious
before a human looks — not as a sign-off.

### Scanning secscan with itself

```bash
python3 -m secscan secscan/ --exclude 'rules.py' --exclude 'knowledge.py'
```

Without those exclusions it reports three findings in its own rule definitions — a pattern
file necessarily contains the patterns it searches for. The remaining self-scan findings are
the vendor documentation keys in its own known-example table, correctly labelled and capped
at `low`.

## Keeping it current

- **News** refreshes itself: the KEV cache expires after 24 hours, `--refresh-news` forces it.
- **Prevalence rankings** are static. `cwe_top25_rank` and the OWASP category in
  `secscan/knowledge.py` reflect the 2024 CWE Top 25 and OWASP Top 10 2021; update them when
  new lists are published.
- **Curated incidents** in `knowledge.py` carry `CURATED_AS_OF`. Live KEV data supersedes
  them in the report ordering, so the curated set ages gracefully.

## Layout

```
secscan/
  knowledge.py   26 vulnerability classes: the four axes, remediation, curated incidents
  rules.py       55 regex rules + 14 secret patterns
  pyast.py       Python AST checks + taint tracking
  scanner.py     discovery, comment stripping, matching, scoring
  news.py        CISA KEV + NVD enrichment, caching, offline fallback
  report.py      terminal / JSON / Markdown / HTML / SARIF renderers
  cli.py         argument parsing, filtering, baselines, exit codes
demo/vulnerable_shop/   deliberately insecure sample app
tests/test_secscan.py   66 tests
```

## License

MIT.
