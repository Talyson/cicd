"""Portão de segurança: consolida relatórios SAST/SCA e aplica a política por branch.

Política:
- main   (modo "threshold"): bloqueia se a soma de achados CRITICAL (SAST + SCA)
           for >= --critical-threshold (padrão 3). Demais achados geram apenas aviso.
- outras (modo "strict"):    bloqueia em qualquer achado HIGH/CRITICAL ou vulnerabilidade
           conhecida reportada pelo pip-audit.

Mapeamento de severidade:
- Bandit:    issue_severity HIGH (confiança >= MEDIUM)  -> CRITICAL
- Semgrep:   severity ERROR                             -> CRITICAL
- Trivy:     Severity CRITICAL / HIGH (vulns e secrets)  -> mesma severidade
- pip-audit: sem severidade                             -> UNKNOWN

Códigos de saída: 0 aprovado, 1 bloqueado, 2 erro (relatório ausente/inválido).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

PROTECTED_BRANCHES = {"main"}
REQUIRED_REPORTS = {
    "bandit": "bandit.json",
    "semgrep": "semgrep.json",
    "pip-audit": "pip-audit.json",
    "trivy-fs": "trivy-fs.json",
    "trivy-image": "trivy-image.json",
}
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "UNKNOWN": 2}


class ReportError(Exception):
    """Relatório ausente ou em formato inesperado."""


@dataclass(frozen=True, order=True)
class Finding:
    tool: str
    category: str  # SAST | SCA
    severity: str  # CRITICAL | HIGH | UNKNOWN
    rule: str
    location: str


# ---------------------------------------------------------------- parsers


def parse_bandit(data: dict) -> Iterator[Finding]:
    for item in data["results"]:
        if item["issue_severity"] == "HIGH" and item["issue_confidence"] in ("MEDIUM", "HIGH"):
            yield Finding(
                "bandit",
                "SAST",
                "CRITICAL",
                item["test_id"],
                f"{item['filename']}:{item['line_number']}",
            )


def parse_semgrep(data: dict) -> Iterator[Finding]:
    for item in data["results"]:
        if item["extra"]["severity"] == "ERROR":
            yield Finding(
                "semgrep",
                "SAST",
                "CRITICAL",
                item["check_id"],
                f"{item['path']}:{item['start']['line']}",
            )


def parse_trivy(data: dict) -> Iterator[Finding]:
    # tool="trivy" para fs e image: a mesma CVE no mesmo pacote é contada uma vez só.
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            if vuln["Severity"] in ("CRITICAL", "HIGH"):
                yield Finding(
                    "trivy",
                    "SCA",
                    vuln["Severity"],
                    vuln["VulnerabilityID"],
                    f"{vuln['PkgName']}@{vuln['InstalledVersion']}",
                )
        for secret in result.get("Secrets") or []:
            if secret["Severity"] in ("CRITICAL", "HIGH"):
                yield Finding(
                    "trivy",
                    "SCA",
                    secret["Severity"],
                    f"secret:{secret['RuleID']}",
                    f"{result['Target']}:{secret.get('StartLine', '?')}",
                )


def parse_pip_audit(data: dict) -> Iterator[Finding]:
    for dep in data["dependencies"]:
        for vuln in dep.get("vulns") or []:
            yield Finding(
                "pip-audit",
                "SCA",
                "UNKNOWN",
                vuln["id"],
                f"{dep['name']}@{dep['version']}",
            )


PARSERS = {
    "bandit": parse_bandit,
    "semgrep": parse_semgrep,
    "pip-audit": parse_pip_audit,
    "trivy-fs": parse_trivy,
    "trivy-image": parse_trivy,
}


def load_findings(reports_dir: Path) -> set[Finding]:
    findings: set[Finding] = set()
    for name, filename in REQUIRED_REPORTS.items():
        path = reports_dir / filename
        if not path.is_file():
            raise ReportError(f"Relatório obrigatório ausente: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            findings.update(PARSERS[name](data))
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ReportError(f"Relatório inválido ({name}): {path}: {exc!r}") from exc
    return findings


# ----------------------------------------------------------------- política


@dataclass
class Decision:
    mode: str
    blocked: bool
    reason: str
    blocking: list[Finding]
    warnings: list[Finding]


def evaluate(findings: Iterable[Finding], target_branch: str, critical_threshold: int) -> Decision:
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f))

    if target_branch in PROTECTED_BRANCHES:
        criticals = [f for f in ordered if f.severity == "CRITICAL"]
        others = [f for f in ordered if f.severity != "CRITICAL"]
        blocked = len(criticals) >= critical_threshold
        reason = (
            f"{len(criticals)} achado(s) CRITICAL (SAST + SCA); "
            f"limite de bloqueio: {critical_threshold}."
        )
        if blocked:
            return Decision("threshold", True, reason, criticals, others)
        return Decision("threshold", False, reason, [], ordered)

    reason = f"{len(ordered)} achado(s) HIGH/CRITICAL/pip-audit; modo estrito bloqueia em qualquer."
    return Decision("strict", bool(ordered), reason, ordered, [])


# ------------------------------------------------------------------- saída


def _table(findings: list[Finding], limit: int = 50) -> list[str]:
    lines = [
        "| Severidade | Categoria | Ferramenta | Regra/CVE | Local |",
        "|---|---|---|---|---|",
    ]
    for f in findings[:limit]:
        lines.append(f"| {f.severity} | {f.category} | {f.tool} | `{f.rule}` | `{f.location}` |")
    if len(findings) > limit:
        lines.append(f"| … | | | +{len(findings) - limit} achado(s) | |")
    return lines


def render_summary(decision: Decision, findings: set[Finding], target_branch: str) -> str:
    counts = Counter((f.category, f.severity) for f in findings)
    status = "❌ BLOQUEADO" if decision.blocked else "✅ APROVADO"
    lines = [
        "## Security Gate",
        "",
        f"**Branch de destino:** `{target_branch}` — **modo:** `{decision.mode}` — **{status}**",
        "",
        decision.reason,
        "",
        "| Categoria | CRITICAL | HIGH | UNKNOWN (pip-audit) |",
        "|---|---|---|---|",
    ]
    for category in ("SAST", "SCA"):
        lines.append(
            f"| {category} | {counts[(category, 'CRITICAL')]} | {counts[(category, 'HIGH')]} "
            f"| {counts[(category, 'UNKNOWN')]} |"
        )
    if decision.blocking:
        lines += ["", "### Achados que bloqueiam", "", *_table(decision.blocking)]
    if decision.warnings:
        lines += ["", "### Avisos (não bloqueiam)", "", *_table(decision.warnings)]
    return "\n".join(lines) + "\n"


def emit_annotations(decision: Decision) -> None:
    for f in decision.blocking:
        print(f"::error title=Security Gate ({f.tool})::{f.severity} {f.rule} em {f.location}")
    for f in decision.warnings:
        print(f"::warning title=Security Gate ({f.tool})::{f.severity} {f.rule} em {f.location}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--reports-dir", type=Path, required=True)
    parser.add_argument("--target-branch", required=True)
    parser.add_argument("--critical-threshold", type=int, default=3)
    args = parser.parse_args(argv)

    if args.critical_threshold < 1:
        parser.error("--critical-threshold deve ser >= 1")

    try:
        findings = load_findings(args.reports_dir)
    except ReportError as exc:
        print(f"::error title=Security Gate::{exc}")
        return 2

    decision = evaluate(findings, args.target_branch, args.critical_threshold)
    summary = render_summary(decision, findings, args.target_branch)
    print(summary)
    emit_annotations(decision)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as fh:
            fh.write(summary)

    return 1 if decision.blocked else 0


if __name__ == "__main__":
    sys.exit(main())
