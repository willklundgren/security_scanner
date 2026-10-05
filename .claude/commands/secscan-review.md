---
description: Scan a path with secscan, verify the findings with parallel subagents, and report what is real
argument-hint: <path> [min-severity, default medium]
---

You are the lead in a review of secscan findings for: $ARGUMENTS

The first argument is the path to scan. An optional second argument is the minimum severity
(`critical`, `high`, `medium`, `low` or `info`). Default to `medium`.

1. **Scan.** Call `mcp__secscan__scan_path` with that path and minimum severity. If
   `next_offset` is set, call it again until you have every finding. If the path looks like
   production code that sits under a `demo/`, `examples/` or `tests/` directory, pass
   `test_heuristic: false`, and pass the same value to every verifier. Note the `root` it returns.

2. **Split the work.** Group findings by file, then cut the groups into batches of at most five
   findings. Keep a file's findings in the same batch where you can, since one verifier reading
   a file once is cheaper than two.

3. **Fan out.** For each batch, start a `secscan-verifier` subagent. Start up to six at once, in
   a single message, so they run in parallel. Each verifier sees none of this conversation, so
   its brief must stand alone. Include:
   - the scan root;
   - the `test_heuristic` value;
   - for each finding, its file path (the part of `location` before the colon), fingerprint,
     rule id and severity.
   Do not verify findings yourself while the verifiers run.

4. **Collect.** When all verifiers have reported, call `mcp__secscan__triage_summary` with the
   root. Every fingerprint you dispatched should have a verdict. Send any that are missing to
   one more verifier.

5. **Spot-check.** Pick the two highest-severity findings marked `false_positive`. Read the
   evidence each verifier cited and confirm it holds. If it does not, call
   `mcp__secscan__record_verdict` yourself to correct the verdict, and say so in the report.

6. **Report.** Write a short report in chat with these parts:
   - Counts per verdict, and how many findings were scanned versus verified.
   - Confirmed findings, most severe first: `file:line`, class, a one-line exploit path, and
     the fix.
   - Findings marked `needs_review`, each with the question a human has to answer.
   - False positives in one line each. These are candidates for the baseline or a
     `# secscan:ignore` comment, and examples worth turning into secscan tests.

Then offer to fix the confirmed critical and high findings. Do not edit any code until the user
says yes. If they do, you make the fixes yourself; verifiers are read-only.
