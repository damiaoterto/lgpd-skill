---
name: lgpd-pii
description: >-
  Scans database models, migrations, schemas, and DTOs for personal identifiable information (PII).
  Generates a formal Personal Data Inventory (ROPA) under LGPD Articles 5, 7, and 11.
  Trigger with /lgpd-pii or "map pii".
---

# LGPD Personal Data Inventory (/lgpd-pii)

This skill focuses exclusively on identifying, cataloging, and classifying personal data processed by the application.

## Operational Rules

1. Scan all data structures: ORM models, SQL migrations, DTOs, interfaces, and entity classes.
2. Classify each identified field into:
   • Common PII (Artigo 5)
   • Sensitive PII (Artigo 11: health, biometrics, race, religion, political opinions)
   • Credentials or Secrets
3. Determine protection status (Plain text, Hashed, Encrypted).
4. Suggest the probable Legal Ground under Article 7 (Consent, Legal Obligation, Contract Execution, Legitimate Interest).
5. Output format must use structured tables with zero emojis and zero hyphens.

## Execution

Execute the scanner to extract persistence candidates:
```bash
python3 ~/.gemini/config/skills/lgpd-compliance-auditor/scripts/scanner.py --dir . || python3 scripts/scanner.py --dir .
```
Filter the output for common_pii, sensitive_pii, and soft_delete_retention.

## Output Format

```markdown
Inventário de Dados Pessoais (ROPA - Lei 13.709/2018)

| Entidade ou Tabela | Campo Identificado | Classificação Legal | Estado de Proteção | Base Legal Recomendada (Artigo 7) | Risco Apurado |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [estrutura] | [campo] | [Comum / Sensível / Credencial] | [Texto Puro / Cifrado / Hash] | [Inciso do Artigo 7] | [Baixo / Médio / Alto / Crítico] |
```
