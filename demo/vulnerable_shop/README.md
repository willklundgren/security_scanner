# vulnerable_shop

A deliberately insecure sample application used to exercise `secscan`.
Every file here contains real vulnerability patterns. Nothing in this
directory should be copied into production code.

Scan it with:

    python3 -m secscan demo/vulnerable_shop --no-test-heuristic
