---
name: lgpd-compliance-auditor
description: Technology-agnostic LGPD (Brazilian General Data Protection Law 13.709/2018) compliance auditor for source code. Scans codebases for personal data mapping, unmasked log leaks, pre-checked consent controls, data subject rights (DSR) workflows, retention policies, and security gaps with strict evidence-based grounding.
---

# LGPD Compliance Auditor Skill

This skill performs a rigorous, technology-agnostic compliance audit against the Brazilian General Data Protection Law (Lei 13.709/2018 - LGPD) across any codebase.

## Triggers and Commands

The skill reacts to natural language requests as well as three standardized commands:

1. `/lgpd-audit`: Runs a complete 7-axis audit across the codebase and outputs the Executive Summary, Compliance Scorecard (0 to 100), Vulnerability Matrix, and Remediation Plan.
2. `/lgpd-pii`: Focuses exclusively on data persistence and contracts (SQL schemas, ORM models, migrations, DTOs, interfaces) to output the formal Personal Data Inventory (ROPA mapping) with sensitivity classifications and recommended legal grounds under Article 7.
3. `/lgpd-fix <target>`: Applies minimal, zero-breaking surgical remediations to a specific finding (e.g. sanitizing unmasked logs, setting checkboxes to opt-in, or drafting an anonymization procedure).

## Core Operational Rules

1. Strict Evidence-Based Grounding: Every reported gap must reference an existing file, an exact line number, and a literal code snippet of at most three lines. Never infer, speculate, or report theoretical vulnerabilities without direct code evidence.
2. Defensive Verification: Before confirming any vulnerability, actively search for defensive layers such as password hashing algorithms (bcrypt, argon2, PBKDF2), log masking/sanitization middlewares, or application-level encryption. If protections exist, downgrade or eliminate the finding.
3. Closed Legal Catalog: Only cite validated articles of Lei 13.709/2018 defined in the rule catalog. Never invent articles or legal interpretations.
4. Deterministic Scoring: Start from a baseline score of 100 points and deduct points based on confirmed findings:
   • Critical severity: deduct 15 points
   • High severity: deduct 8 points
   • Medium severity: deduct 3 points
   • Informative: deduct 1 point
   The minimum allowed score is 0.
5. Strict Output Formatting:
   • Do not use emojis anywhere in the report.
   • Do not use hyphens as bullet points, dash punctuation, or line dividers anywhere in the output. Use numbers, clean Unicode dots, or structured markdown tables.

## Execution Workflow (Hybrid Model)

### Primary Flow: Executing the Helper Script
Always attempt to execute the bundled Python helper script first:

```bash
python3 scripts/scanner.py --dir .
```

If a `.lgpdrc` or `.lgpdrc.json` configuration file exists in the repository, the script automatically applies:
• Official DPO contact details (fulfilling Article 41)
• Custom business PII terms added to detection patterns
• Ignored paths (mocks, test fixtures, discarded migrations)
• Suppressed findings approved by the DPO with documented justification

Read the generated JSON output containing categorized findings across the following buckets:
• common_pii
• sensitive_pii
• log_leaks
• prechecked_consent
• third_party_trackers
• soft_delete_retention
• dpo_contacts
• suppressed_findings
• governance (dpo_configured)

### Autonomous Fallback Flow
If the environment does not permit running shell scripts, if Python 3 is unavailable, or if script execution fails, operate autonomously using standard codebase search tools:

1. Identify Data Persistence: Inspect SQL migrations, ORM schemas, interfaces, DTOs, and model definitions for common and sensitive PII field names in Portuguese and English.
2. Trace Logging Statements: Search for logging calls (`logger.*`, `console.*`, `print`, `fmt.Print*`, `Log::*`) passing unmasked request bodies or credentials.
3. Inspect Frontend Forms: Check form templates (HTML, JSX, TSX, Vue, Blade) for pre-checked consent controls (`defaultChecked={true}`, `checked="checked"`).
4. Review Soft Delete Implementations: Verify whether soft delete mechanisms (`deleted_at`, `is_deleted`) contain associated automated purge or anonymization jobs.
5. Review DSR Endpoints: Check for endpoints dedicated to user data export (Article 18, portability) and complete profile deletion.
6. Verify Trackers and DPO Disclosures: Inspect scripts for external analytics tools and public privacy contact references.

## Closed Regulatory Catalog (Lei 13.709/2018)

| Rule Identifier | Legal Basis | Inspection Condition | Confirmation Standard |
| :--- | :--- | :--- | :--- |
| RULE PII 01 | Articles 5 and 11 | Personal or sensitive data declared in models or database schemas | Data stored as plain text without masking, application encryption, or clear category tagging |
| RULE LOG 02 | Articles 6 (VII) and 46 | Personal data or credentials passed directly to log streams | Logger receiving whole request payloads, unmasked passwords, CPF, or tokens |
| RULE OPT 03 | Article 8 (Paragraph 4) | Consent capture mechanisms in registration or marketing forms | Checkbox controls set to active or checked by default violating voluntary consent |
| RULE DSR 04 | Article 18 | Exercising data subject rights for access, portability, and erasure | Total absence of mechanisms or endpoints for account deletion or machine-readable export |
| RULE RET 05 | Article 16 | Storage limitation, termination of processing, and anonymization | Using logical deletion alone without scheduled jobs to wipe or anonymize historical PII |
| RULE CRY 06 | Article 46 | Security standards for data at rest and data in transit | Storing credentials, access keys, or sensitive health data in plain text |
| RULE DPO 07 | Article 41 | Public disclosure of the Data Protection Officer (Encarregado) | Absence of designated DPO contact email or privacy channel in public facing resources |

## Output Report Specification

The final audit report must be presented in Portuguese according to Brazilian legal terminology, formatted exclusively with structured tables and numbered sections.

```markdown
Relatório de Conformidade LGPD
Auditoria Técnica de Software | Lei 13.709/2018

Sumário Executivo de Conformidade

| Indicador | Avaliação | Status |
| :--- | :--- | :--- |
| Pontuação Geral de Conformidade | [Calculado] de 100 pontos | [Adequado / Moderado / Crítico] |
| Total de Entidades com Dados Pessoais | [Quantidade] estruturas mapeadas | [Avaliação contextual] |
| Dados Pessoais Sensíveis (Artigo 11) | [Quantidade] campos identificados | [Avaliação contextual] |
| Falhas Críticas de Segurança | [Quantidade] ocorrências | [Avaliação contextual] |
| Falhas de Média e Alta Severidade | [Quantidade] ocorrências | [Avaliação contextual] |

1. Inventário de Dados Pessoais e Mapeamento de Risco (ROPA)

| Entidade ou Tabela | Campo Mapeado | Classificação Legal | Estado de Proteção | Risco Apurado |
| :--- | :--- | :--- | :--- | :--- |
| [nome da estrutura] | [nome do campo] | [Comum / Sensível / Credencial] | [Cifrado / Texto Puro / Hash] | [Baixo / Médio / Alto / Crítico] |

2. Matriz de Vulnerabilidades e Gaps Detectados

| Severidade | Artigo da Lei | Localização no Código | Diagnóstico Técnico | Ação de Remediação |
| :--- | :--- | :--- | :--- | :--- |
| [CRÍTICO / ALTO / MÉDIO] | [Artigo Oficial] | [arquivo e linha exata] | [Diagnóstico objetivo com citação] | [Recomendação técnica direta] |

3. Justificativas e Supressões Homologadas pelo DPO (.lgpdrc)
(Apresentar esta seção apenas quando houver supressões homologadas ativas)

| Arquivo e Linha | Achado Original | Justificativa Registrada | Aprovador | Impacto no Score |
| :--- | :--- | :--- | :--- | :--- |
| [arquivo e linha] | [tipo de achado] | [motivo documentado] | [nome ou email do DPO] | Risco Mitigado (Sem Dedução) |

4. Plano Cronológico de Remediação

| Fase | Prazo Sugerido | Escopo de Atuação | Objetivo Central |
| :--- | :--- | :--- | :--- |
| Fase 1 | Imediato (até 48 horas) | Camada de Logging e Telemetria | Eliminar vazamentos ativos de credenciais e PII |
| Fase 2 | Curto Prazo (Sprint Atual) | Camada de Frontend e Formulários | Ajustar caixas de consentimento para modelo livre |
| Fase 3 | Médio Prazo (Próxima Sprint) | Camada de Persistência e Banco | Implementar anonimização de dados expirados |
| Fase 4 | Longo Prazo (Trimestral) | Camada de Governança e APIs | Construir endpoints de atendimento ao Artigo 18 |
```
