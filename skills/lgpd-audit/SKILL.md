---
name: lgpd-audit
description: >-
  Runs a comprehensive 7-axis LGPD (Lei 13.709/2018) compliance audit on the codebase.
  Outputs the Executive Summary, Scorecard (0 to 100), Vulnerability Matrix, and Remediation Plan.
  Trigger with /lgpd-audit or "audit lgpd".
---

# LGPD Full Compliance Audit (/lgpd-audit)

Run a complete compliance audit against Lei 13.709/2018 across all application layers (persistence, logs, forms, retention, trackers).

## Operational Rules

1. Strict Evidence-Based Grounding: Every reported gap must reference an existing file, exact line number, and a literal code snippet.
2. Defensive Verification: Search for hashing (bcrypt, argon2), log masking proxies, or opt-in controls before confirming any finding.
3. Closed Catalog: Only cite validated articles of Lei 13.709/2018.
4. Deterministic Score: Baseline 100 points, deducting 15 for Critical, 8 for High, 3 for Medium, 1 for Informative.
5. Strict Output Formatting:
   • Do not use emojis anywhere in the report.
   • Do not use hyphens as bullet points, dash punctuation, or line dividers. Use numbers, clean Unicode dots, or structured markdown tables.

## Execution

Execute the bundled Python scanner first:
```bash
python3 ~/.gemini/config/skills/lgpd-compliance-auditor/scripts/scanner.py --dir . || python3 scripts/scanner.py --dir .
```
If the script cannot run, inspect persistence, logs, forms, and trackers manually.

Generate the full report according to the specification with Executive Summary, ROPA table, Vulnerability Matrix, DPO Suppressions table (if any), and Chronological Remediation Plan.
