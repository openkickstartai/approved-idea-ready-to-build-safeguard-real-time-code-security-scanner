"""SafeGuard core scanner — regex-based security rule engine."""
import re
import os
from dataclasses import dataclass


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    message: str
    snippet: str


RULES = [
    {"id": "SG001", "name": "hardcoded-secret", "severity": "HIGH",
     "pattern": r'(?i)(password|secret|api_key|apikey|token|private_key)\s*=\s*["\'][^"\']{4,}["\']',
     "message": "Hardcoded secret detected"},
    {"id": "SG002", "name": "sql-injection", "severity": "CRITICAL",
     "pattern": r'(?i)(\.execute\s*\(\s*f["\']|f["\'].*\b(?:SELECT|INSERT|UPDATE|DELETE)\b|\bexecute\s*\(.*%)',
     "message": "Potential SQL injection vulnerability"},
    {"id": "SG003", "name": "dangerous-function", "severity": "HIGH",
     "pattern": r'\b(eval|exec)\s*\(',
     "message": "Use of dangerous function (eval/exec)"},
    {"id": "SG004", "name": "shell-injection", "severity": "CRITICAL",
     "pattern": r'os\.system\s*\(|subprocess\.\w+\s*\(.*shell\s*=\s*True',
     "message": "Potential shell injection vulnerability"},
    {"id": "SG005", "name": "debug-enabled", "severity": "MEDIUM",
     "pattern": r'(?<!\w)debug\s*=\s*True',
     "message": "Debug mode enabled — disable in production"},
    {"id": "SG006", "name": "insecure-deserialization", "severity": "HIGH",
     "pattern": r'pickle\.loads?\s*\(|yaml\.load\s*\(',
     "message": "Insecure deserialization detected"},
]

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
DEFAULT_EXTS = {".py", ".js", ".ts", ".go", ".rb", ".java", ".php"}


def scan_line(text, line_num, filepath, rules=None):
    findings = []
    for rule in (rules or RULES):
        if re.search(rule["pattern"], text):
            findings.append(Finding(
                file=filepath, line=line_num, rule=f'{rule["id"]}: {rule["name"]}',
                severity=rule["severity"], message=rule["message"],
                snippet=text.strip(),
            ))
    return findings


def scan_file(filepath, rules=None):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for num, line in enumerate(f, 1):
                findings.extend(scan_line(line, num, filepath, rules))
    except (OSError, IOError):
        return findings
    return findings


def scan_directory(dirpath, extensions=None, rules=None):
    exts = extensions or DEFAULT_EXTS
    findings = []
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            if os.path.splitext(fname)[1] in exts:
                findings.extend(scan_file(os.path.join(root, fname), rules))
    return findings


def format_report(findings):
    if not findings:
        return "✅ No security issues found!"
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}
    lines = [f"🛡️  SafeGuard found {len(findings)} issue(s):\n"]
    for f in findings:
        lines.append(f"{icons.get(f.severity, '⚪')} [{f.severity}] {f.file}:{f.line}")
        lines.append(f"   Rule: {f.rule}")
        lines.append(f"   {f.message}")
        lines.append(f"   > {f.snippet}\n")
    stats = {}
    for f in findings:
        stats[f.severity] = stats.get(f.severity, 0) + 1
    lines.append("Summary: " + ", ".join(f"{v} {k}" for k, v in sorted(stats.items())))
    return "\n".join(lines)
