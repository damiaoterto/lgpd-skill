#!/usr/bin/env python3
"""
LGPD Compliance Code Scanner (Brazilian General Data Protection Law 13709/2018)
Technology-agnostic scanner using Python standard library only.
Supports repository configuration via .lgpdrc / .lgpdrc.json files.
"""

import os
import sys
import re
import json
import fnmatch
import argparse
from pathlib import Path

DEFAULT_IGNORED_DIRECTORIES = {
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

DEFAULT_IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi",
    ".pyc", ".pyo", ".class",
    ".lock", "-lock.json", ".min.js", ".min.css", ".map"
}

BASE_PATTERNS_COMMON_PII = [
    r"\b(cpf|cnpj|rg|ssn|tax[_\s]?id)\b",
    r"\b(email|e_mail|electronic[_\s]?mail)\b",
    r"\b(telefone|celular|phone|cellphone|mobile|whatsapp)\b",
    r"\b(endereco|address|rua|street|cep|zipcode|postal[_\s]?code)\b",
    r"\b(ip[_\s]?address|client[_\s]?ip|remote[_\s]?ip)\b",
    r"\b(geolocalizacao|geolocation|latitude|longitude|lat[_\s]?long)\b",
    r"\b(data[_\s]?nascimento|birth[_\s]?date|birthday|dt[_\s]?nasc)\b",
    r"\b(nome[_\s]?completo|full[_\s]?name|sobrenome|last[_\s]?name)\b"
]

BASE_PATTERNS_SENSITIVE_PII = [
    r"\b(origem[_\s]?racial|raca|etnia|race|ethnicity)\b",
    r"\b(religiao|crenca[_\s]?religiosa|religion|religious[_\s]?belief)\b",
    r"\b(opiniao[_\s]?politica|filiacao[_\s]?partidaria|political[_\s]?opinion)\b",
    r"\b(filiacao[_\s]?sindical|sindicato|union[_\s]?membership)\b",
    r"\b(dado[_\s]?saude|historico[_\s]?medico|prontuario|diagnostico|health|medical|disease)\b",
    r"\b(tipo[_\s]?sanguineo|blood[_\s]?type)\b",
    r"\b(dado[_\s]?genetico|biometria|biometric|dna|fingerprint|facial[_\s]?recognition)\b",
    r"\b(vida[_\s]?sexual|orientacao[_\s]?sexual|sexual[_\s]?orientation)\b"
]

PATTERNS_LOG_LEAKS = [
    r"(logger\.(info|debug|warn|error|trace|fatal)|console\.(log|info|warn|error)|print|fmt\.Print|Log::(info|debug|error|warning))\s*\([^)]*(req\.body|request\.body|request->all|\$request|params|payload|data|body)[^)]*\)",
    r"(logger\.(info|debug|warn|error|trace|fatal)|console\.(log|info|warn|error)|print|fmt\.Print|Log::(info|debug|error|warning))\s*\([^)]*(password|senha|secret|cpf|token|cartao|credit_card)[^)]*\)"
]

PATTERNS_PRECHECKED_CONSENT = [
    r"(defaultChecked\s*=\s*\{\s*true\s*\}|checked\s*=\s*[\"']checked[\"']|checked\s*=\s*\{\s*true\s*\}|<input[^>]+checked)",
]

PATTERNS_THIRD_PARTY_TRACKERS = [
    r"(googletagmanager\.com|google-analytics\.com|connect\.facebook\.net|clarity\.ms|hotjar\.com|pixel|segment\.com|mixpanel\.com)"
]

PATTERNS_SOFT_DELETE = [
    r"\b(deleted_at|is_deleted|soft_delete|removido_em|is_active)\b"
]

PATTERNS_DPO = [
    r"\b(encarregado|dpo|privacidade@|dpo@|dataprotection)\b"
]


class LGPDScanner:
    """Agnostic scanner analyzing source code with optional .lgpdrc governance file."""

    def __init__(self, root_path=".", config_file=None):
        self.root_path = Path(root_path).resolve()
        self.config = self.load_config(config_file)
        self.common_pii_patterns = list(BASE_PATTERNS_COMMON_PII)
        self.sensitive_pii_patterns = list(BASE_PATTERNS_SENSITIVE_PII)
        self.apply_custom_patterns()

        self.results = {
            "stats": {
                "scanned_files": 0,
                "total_findings": 0,
                "suppressed_findings": 0
            },
            "governance": {
                "config_loaded": bool(self.config),
                "dpo_configured": self.config.get("dpo", None)
            },
            "common_pii": [],
            "sensitive_pii": [],
            "log_leaks": [],
            "prechecked_consent": [],
            "third_party_trackers": [],
            "soft_delete_retention": [],
            "dpo_contacts": [],
            "suppressed_findings": []
        }

    def load_config(self, explicit_path):
        """Locate and read .lgpdrc or .lgpdrc.json configuration file."""
        candidates = []
        if explicit_path:
            candidates.append(Path(explicit_path))
        else:
            candidates.append(self.root_path / ".lgpdrc")
            candidates.append(self.root_path / ".lgpdrc.json")

        for candidate in candidates:
            if candidate.is_file():
                try:
                    with open(candidate, "r", encoding="utf-8") as stream:
                        return json.load(stream)
                except Exception:
                    pass
        return {}

    def apply_custom_patterns(self):
        """Append user defined terms from configuration."""
        for term in self.config.get("custom_pii", []):
            safe = re.escape(term.strip())
            self.common_pii_patterns.append(rf"\b({safe})\b")

        for term in self.config.get("custom_sensitive", []):
            safe = re.escape(term.strip())
            self.sensitive_pii_patterns.append(rf"\b({safe})\b")

    def is_ignored_by_config(self, relative_path):
        """Check if relative path matches any ignore pattern from config."""
        ignore_rules = self.config.get("ignore_paths", [])
        for rule in ignore_rules:
            if fnmatch.fnmatch(relative_path, rule) or fnmatch.fnmatch(relative_path, f"*/{rule}"):
                return True
        return False

    def check_suppression(self, relative_path, line_number, finding_type, evidence):
        """Check if finding has an approved suppression from DPO in config."""
        suppressions = self.config.get("suppressions", [])
        for item in suppressions:
            conf_file = item.get("file", "")
            if conf_file == relative_path or conf_file.endswith(relative_path) or relative_path.endswith(conf_file):
                target_line = item.get("line")
                if target_line is None or target_line == line_number:
                    self.results["suppressed_findings"].append({
                        "file": relative_path,
                        "line": line_number,
                        "finding_type": finding_type,
                        "evidence": evidence,
                        "reason": item.get("reason", "Approved suppression"),
                        "approved_by": item.get("approved_by", "DPO")
                    })
                    self.results["stats"]["suppressed_findings"] += 1
                    return True
        return False

    def is_text_file(self, file_path):
        """Check if file should be analyzed based on extension."""
        suffix = file_path.suffix.lower()
        if suffix in DEFAULT_IGNORED_EXTENSIONS:
            return False
        for ignored_suffix in DEFAULT_IGNORED_EXTENSIONS:
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
        for pattern in self.sensitive_pii_patterns:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                evidence = clean_line[:160]
                if not self.check_suppression(relative_path, line_number, "sensitive_pii", evidence):
                    self.results["sensitive_pii"].append({
                        "file": relative_path,
                        "line": line_number,
                        "matched_term": match.group(0),
                        "evidence": evidence
                    })
                break

        # Check for common personal identifiable information
        for pattern in self.common_pii_patterns:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                evidence = clean_line[:160]
                if not self.check_suppression(relative_path, line_number, "common_pii", evidence):
                    self.results["common_pii"].append({
                        "file": relative_path,
                        "line": line_number,
                        "matched_term": match.group(0),
                        "evidence": evidence
                    })
                break

        # Check for unmasked log leaks
        for pattern in PATTERNS_LOG_LEAKS:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                evidence = clean_line[:160]
                if not self.check_suppression(relative_path, line_number, "log_leak", evidence):
                    self.results["log_leaks"].append({
                        "file": relative_path,
                        "line": line_number,
                        "evidence": evidence
                    })
                break

        # Check for pre-checked consent forms
        for pattern in PATTERNS_PRECHECKED_CONSENT:
            if re.search(pattern, clean_line, re.IGNORECASE):
                evidence = clean_line[:160]
                if not self.check_suppression(relative_path, line_number, "prechecked_consent", evidence):
                    self.results["prechecked_consent"].append({
                        "file": relative_path,
                        "line": line_number,
                        "evidence": evidence
                    })
                break

        # Check for third-party trackers
        for pattern in PATTERNS_THIRD_PARTY_TRACKERS:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                evidence = clean_line[:160]
                if not self.check_suppression(relative_path, line_number, "third_party_tracker", evidence):
                    self.results["third_party_trackers"].append({
                        "file": relative_path,
                        "line": line_number,
                        "provider": match.group(0),
                        "evidence": evidence
                    })
                break

        # Check for soft delete patterns in schemas or models
        for pattern in PATTERNS_SOFT_DELETE:
            match = re.search(pattern, clean_line, re.IGNORECASE)
            if match:
                if re.search(r"(self\.|this\.|column|field|type|schema|class|interface|struct|=|\:)", clean_line, re.IGNORECASE):
                    evidence = clean_line[:160]
                    if not self.check_suppression(relative_path, line_number, "soft_delete_retention", evidence):
                        self.results["soft_delete_retention"].append({
                            "file": relative_path,
                            "line": line_number,
                            "evidence": evidence
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
            dirs[:] = [d for d in dirs if d not in DEFAULT_IGNORED_DIRECTORIES and not d.startswith(".")]

            for filename in files:
                target_file = Path(root_dir) / filename
                if not self.is_text_file(target_file):
                    continue

                try:
                    rel_path = str(target_file.relative_to(self.root_path))
                except ValueError:
                    rel_path = str(target_file)

                if self.is_ignored_by_config(rel_path):
                    continue

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
    parser.add_argument("--config", help="Explicit path to .lgpdrc configuration file")
    parser.add_argument("--output", help="Target JSON file path")
    args = parser.parse_args()

    scanner = LGPDScanner(root_path=args.dir, config_file=args.config)
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
