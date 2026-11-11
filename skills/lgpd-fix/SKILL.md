---
name: lgpd-fix
description: >-
  Applies surgical, zero-breaking remediations for LGPD compliance gaps identified in code.
  Masks unmasked logs, removes pre-checked consent checkboxes, adds defensive hashes, or creates anonymization jobs.
  Trigger with /lgpd-fix <target> or "fix lgpd".
---

# LGPD Surgical Remediation (/lgpd-fix)

Applies targeted code changes to resolve an identified compliance vulnerability with the shortest working diff.

## Remediation Guidelines

1. Log Leaks (Article 6 and Article 46):
   • Replace direct logging of request objects with masked properties.
   • Ensure passwords, CPF, and secrets are sanitized before output.
2. Consent Capture (Article 8):
   • Remove `defaultChecked={true}`, `checked="checked"`, or active states from checkboxes.
   • Require explicit voluntary action from the data subject.
3. Plaintext Credentials (Article 46):
   • Apply industry-standard password hashing (bcrypt, argon2) before persistence.
4. Soft Delete Retention (Article 16 and 18):
   • Implement or stub an anonymization procedure replacing PII with anonymized values.

Always ensure existing tests, fixtures, and callers remain unbroken after remediation.
Do not use emojis or hyphens in any output summary.
