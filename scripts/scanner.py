#!/usr/bin/env python3
"""
LGPD Compliance Code Scanner (Brazilian General Data Protection Law 13709/2018)
Technology-agnostic scanner using Python standard library only.
"""

import os
import sys
import re
import json
import argparse
from pathlib import Path

IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "vendor",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    "target",
    "out",
    ".next",
    ".nuxt",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".turbo",
    ".gradle",
    "bin",
    "obj",
    ".idea",
    ".vscode",
    "scripts",
}

IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi",
    ".pyc", ".pyo", ".class",
    ".lock", "-lock.json", ".min.js", ".min.css", ".map"
}

# Patterns for common personal identifiable information in Portuguese and English
PATTERNS_COMMON_PII = [
    r"\b(cpf|cnpj|rg|ssn|tax[_\s]?id)\b",
    r"\b(email|e_mail|electronic[_\s]?mail)\b",
    r"\b(telefone|celular|phone|cellphone|mobile|whatsapp)\b",
    r"\b(endereco|address|rua|street|cep|zipcode|postal[_\s]?code)\b",
    r"\b(ip[_\s]?address|client[_\s]?ip|remote[_\s]?ip)\b",
    r"\b(geolocalizacao|geolocation|latitude|longitude|lat[_\s]?long)\b",
    r"\b(data[_\s]?nascimento|birth[_\s]?date|birthday|dt[_\s]?nasc)\b",
    r"\b(nome[_\s]?completo|full[_\s]?name|sobrenome|last[_\s]?name)\b"
]

# Patterns for sensitive personal data according to Article 11 of LGPD
PATTERNS_SENSITIVE_PII = [
    r"\b(origem[_\s]?racial|raca|etnia|race|ethnicity)\b",
    r"\b(religiao|crenca[_\s]?religiosa|religion|religious[_\s]?belief)\b",
    r"\b(opiniao[_\s]?politica|filiacao[_\s]?partidaria|political[_\s]?opinion)\b",
    r"\b(filiacao[_\s]?sindical|sindicato|union[_\s]?membership)\b",
    r"\b(dado[_\s]?saude|historico[_\s]?medico|prontuario|diagnostico|health|medical|disease)\b",
    r"\b(tipo[_\s]?sanguineo|blood[_\s]?type)\b",
    r"\b(dado[_\s]?genetico|biometria|biometric|dna|fingerprint|facial[_\s]?recognition)\b",
    r"\b(vida[_\s]?sexual|orientacao[_\s]?sexual|sexual[_\s]?orientation)\b"
]

# Patterns for potential PII leaks into log streams or unmasked prints
PATTERNS_LOG_LEAKS = [
    r"(logger\.(info|debug|warn|error|trace|fatal)|console\.(log|info|warn|error)|print|fmt\.Print|Log::(info|debug|error|warning))\s*\([^)]*(req\.body|request\.body|request->all|\$request|params|payload|data|body)[^)]*\)",
    r"(logger\.(info|debug|warn|error|trace|fatal)|console\.(log|info|warn|error)|print|fmt\.Print|Log::(info|debug|error|warning))\s*\([^)]*(password|senha|secret|cpf|token|cartao|credit_card)[^)]*\)"
]

# Patterns for pre-checked consent checkboxes violating freely given consent
PATTERNS_PRECHECKED_CONSENT = [
    r"(defaultChecked\s*=\s*\{\s*true\s*\}|checked\s*=\s*[\"']checked[\"']|checked\s*=\s*\{\s*true\s*\}|<input[^>]+checked)",
]

KEYWORDS_TERMS_AND_PRIVACY = [
    r"(termos|privacidade|lgpd|consentimento|politica|marketing|newsletter|comunicacao|privacy|terms|consent)"
]

# Patterns for third-party trackers loaded in application frontends
PATTERNS_THIRD_PARTY_TRACKERS = [
    r"(googletagmanager\.com|google-analytics\.com|connect\.facebook\.net|clarity\.ms|hotjar\.com|pixel|segment\.com|mixpanel\.com)"
]

# Patterns for soft delete without data anonymization
PATTERNS_SOFT_DELETE = [
    r"\b(deleted_at|is_deleted|soft_delete|removido_em|is_active)\b"
]

# Patterns for Data Protection Officer (DPO / Encarregado) contact disclosures
PATTERNS_DPO = [
    r"\b(encarregado|dpo|privacidade@|dpo@|dataprotection)\b"
]


class LGPDScanner:
    """Agnostic scanner analyzing source code for LGPD compliance gaps."""

    def __init__(self, root_path="."):
        self.root_path = Path(root_path).resolve()
        self.results = {
            "stats": {
                "scanned_files": 0,
                "total_findings": 0
            },
            "common_pii": [],
            "sensitive_pii": [],
            "log_leaks": [],
            "prechecked_consent": [],
            "third_party_trackers": [],
            "soft_delete_retention": [],
            "dpo_contacts": []
        }

    def is_text_file(self, file_path):
        """Check if file should be analyzed based on extension."""
        suffix = file_path.suffix.lower()
        if suffix in IGNORED_EXTENSIONS:
            return False
        for ignored_suffix in IGNORED_EXTENSIONS:
            if file_path.name.lower().endswith(ignored_suffix):
                return False
        return True

    def read_lines(self, file_path):
        """Safely read lines from file with fallback encoding."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as stream:
                return stream.readlines()
        except Exception:
            return []

    def scan_line(self, relative_path, line_number, raw_line):
        """Scan a single line of code against compliance patterns."""
        clean_line = raw_line.strip()
        if not clean_line or len(clean_line) > 1000:
            return

        # Check for sensitive personal data
        for pattern in PATTERNS_SENSITIVE_PII:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                self.results["sensitive_pii"].append({
                    "file": relative_path,
                    "line": line_number,
                    "matched_term": match.group(0),
                    "evidence": clean_line[:160]
                })
                break

        # Check for common personal identifiable information
        for pattern in PATTERNS_COMMON_PII:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                self.results["common_pii"].append({
                    "file": relative_path,
                    "line": line_number,
                    "matched_term": match.group(0),
                    "evidence": clean_line[:160]
                })
                break

        # Check for unmasked log leak risks
        for pattern in PATTERNS_LOG_LEAKS:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                self.results["log_leaks"].append({
                    "file": relative_path,
                    "line": line_number,
                    "evidence": clean_line[:160]
                })
                break

        # Check for pre-checked consent forms
        for pattern in PATTERNS_PRECHECKED_CONSENT:
            if re.search(pattern, clean_line, re.IGNORECASE):
                for term in KEYWORDS_TERMS_AND_PRIVACY:
                    if re.search(term, clean_line, re.IGNORECASE):
                        self.results["prechecked_consent"].append({
                            "file": relative_path,
                            "line": line_number,
                            "evidence": clean_line[:160]
                        })
                        break

        # Check for third-party trackers
        for pattern in PATTERNS_THIRD_PARTY_TRACKERS:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                self.results["third_party_trackers"].append({
                    "file": relative_path,
                    "line": line_number,
                    "provider": match.group(0),
                    "evidence": clean_line[:160]
                })
                break

        # Check for soft delete retention patterns in schema and models
        for pattern in PATTERNS_SOFT_DELETE:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                if re.search(r"(class|interface|type|struct|table|create|schema|column)", clean_line, re.IGNORECASE):
                    self.results["soft_delete_retention"].append({
                        "file": relative_path,
                        "line": line_number,
                        "evidence": clean_line[:160]
                    })
                    break

        # Check for DPO contact mentions
        for pattern in PATTERNS_DPO:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                self.results["dpo_contacts"].append({
                    "file": relative_path,
                    "line": line_number,
                    "evidence": clean_line[:160]
                })
                break

    def run(self):
        """Traverse directory tree and execute scans."""
        for root_dir, dirs, files in os.walk(self.root_path):
            dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES and not d.startswith(".")]

            for filename in files:
                target_file = Path(root_dir) / filename
                if not self.is_text_file(target_file):
                    continue

                try:
                    rel_path = str(target_file.relative_to(self.root_path))
                except ValueError:
                    rel_path = str(target_file)

                self.results["stats"]["scanned_files"] += 1
                lines = self.read_lines(target_file)
                for index, line in enumerate(lines, start=1):
                    self.scan_line(rel_path, index, line)

        total_count = (
            len(self.results["common_pii"]) +
            len(self.results["sensitive_pii"]) +
            len(self.results["log_leaks"]) +
            len(self.results["prechecked_consent"]) +
            len(self.results["third_party_trackers"]) +
            len(self.results["soft_delete_retention"]) +
            len(self.results["dpo_contacts"])
        )
        self.results["stats"]["total_findings"] = total_count
        return self.results


def main():
    """CLI entry point for scanner execution."""
    parser = argparse.ArgumentParser(description="Technology-agnostic LGPD compliance code scanner")
    parser.add_argument("--dir", default=".", help="Root directory to scan")
    parser.add_argument("--output", help="Target JSON file path")
    args = parser.parse_args()

    scanner = LGPDScanner(root_path=args.dir)
    data = scanner.run()

    json_output = json.dumps(data, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as out_stream:
            out_stream.write(json_output)
        print(f"Scan finished. Results saved to {args.output}")
    else:
        print(json_output)


if __name__ == "__main__":
    main()
