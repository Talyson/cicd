import json

import pytest

from scripts.security_gate import Finding, evaluate, load_findings, main


def _trivy(*vulns):
    return {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": cve,
                        "PkgName": pkg,
                        "InstalledVersion": "1.0",
                        "Severity": sev,
                    }
                    for cve, pkg, sev in vulns
                ],
            }
        ]
    }


def _write_reports(tmp_path, *, bandit=None, semgrep=None, pip_audit=None, fs=None, image=None):
    reports = {
        "bandit.json": bandit or {"results": []},
        "semgrep.json": semgrep or {"results": []},
        "pip-audit.json": pip_audit or {"dependencies": []},
        "trivy-fs.json": fs or {"Results": None},
        "trivy-image.json": image or {"Results": []},
    }
    for name, content in reports.items():
        (tmp_path / name).write_text(json.dumps(content))
    return tmp_path


BANDIT_HIGH = {
    "results": [
        {
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "test_id": "B602",
            "filename": "app/x.py",
            "line_number": 3,
        },
        {  # severidade média: ignorado
            "issue_severity": "MEDIUM",
            "issue_confidence": "HIGH",
            "test_id": "B105",
            "filename": "app/x.py",
            "line_number": 4,
        },
        {  # confiança baixa: ignorado
            "issue_severity": "HIGH",
            "issue_confidence": "LOW",
            "test_id": "B602",
            "filename": "app/x.py",
            "line_number": 5,
        },
    ]
}

SEMGREP_ERROR = {
    "results": [
        {
            "check_id": "flask.rce",
            "path": "app/y.py",
            "start": {"line": 7},
            "extra": {"severity": "ERROR"},
        },
        {
            "check_id": "py.warn",
            "path": "app/y.py",
            "start": {"line": 8},
            "extra": {"severity": "WARNING"},
        },
    ]
}


def test_parsing_and_severity_mapping(tmp_path):
    _write_reports(
        tmp_path,
        bandit=BANDIT_HIGH,
        semgrep=SEMGREP_ERROR,
        pip_audit={
            "dependencies": [{"name": "flask", "version": "1.0", "vulns": [{"id": "PYSEC-1"}]}]
        },
        fs=_trivy(("CVE-1", "jinja2", "CRITICAL"), ("CVE-2", "werkzeug", "HIGH")),
        image=_trivy(("CVE-1", "jinja2", "CRITICAL"), ("CVE-3", "openssl", "LOW")),
    )
    findings = load_findings(tmp_path)
    by_tool = {(f.tool, f.severity, f.rule) for f in findings}
    assert by_tool == {
        ("bandit", "CRITICAL", "B602"),
        ("semgrep", "CRITICAL", "flask.rce"),
        ("pip-audit", "UNKNOWN", "PYSEC-1"),
        ("trivy", "CRITICAL", "CVE-1"),  # duplicada em fs e image: contada uma vez
        ("trivy", "HIGH", "CVE-2"),
    }


def test_trivy_secrets(tmp_path):
    fs = {
        "Results": [
            {
                "Target": "config.py",
                "Secrets": [
                    {"RuleID": "aws-access-key-id", "Severity": "CRITICAL", "StartLine": 2}
                ],
            }
        ]
    }
    _write_reports(tmp_path, fs=fs)
    (finding,) = load_findings(tmp_path)
    assert finding.severity == "CRITICAL"
    assert finding.rule == "secret:aws-access-key-id"


def _crit(n):
    return {Finding("trivy", "SCA", "CRITICAL", f"CVE-{i}", "pkg@1") for i in range(n)}


HIGH = Finding("trivy", "SCA", "HIGH", "CVE-H", "pkg@1")


@pytest.mark.parametrize(("criticals", "blocked"), [(0, False), (2, False), (3, True), (5, True)])
def test_main_threshold(criticals, blocked):
    decision = evaluate(_crit(criticals) | {HIGH}, "main", 3)
    assert decision.mode == "threshold"
    assert decision.blocked is blocked
    if blocked:
        assert len(decision.blocking) == criticals
        assert decision.warnings == [HIGH]
    else:
        assert decision.blocking == []
        assert HIGH in decision.warnings


def test_main_counts_sast_and_sca_together():
    sast = {
        Finding("bandit", "SAST", "CRITICAL", "B602", "a:1"),
        Finding("semgrep", "SAST", "CRITICAL", "r", "a:2"),
    }
    assert evaluate(sast | _crit(1), "main", 3).blocked
    assert not evaluate(sast, "main", 3).blocked


@pytest.mark.parametrize("branch", ["test", "feature/x"])
def test_strict_mode_blocks_on_any_finding(branch):
    assert evaluate({HIGH}, branch, 3).blocked
    assert evaluate({Finding("pip-audit", "SCA", "UNKNOWN", "X", "p@1")}, branch, 3).blocked
    decision = evaluate(set(), branch, 3)
    assert decision.mode == "strict"
    assert not decision.blocked


def test_main_cli_exit_codes(tmp_path, monkeypatch, capsys):
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    reports = tmp_path / "r"
    reports.mkdir()
    fs = _trivy(*[(f"CVE-{i}", "pkg", "CRITICAL") for i in range(3)])
    _write_reports(reports, fs=fs)

    assert main(["--reports-dir", str(reports), "--target-branch", "main"]) == 1
    assert (
        main(
            ["--reports-dir", str(reports), "--target-branch", "main", "--critical-threshold", "4"]
        )
        == 0
    )
    assert "Security Gate" in summary.read_text()
    assert "::error" in capsys.readouterr().out


def test_missing_report_fails_closed(tmp_path):
    _write_reports(tmp_path)
    (tmp_path / "trivy-image.json").unlink()
    assert main(["--reports-dir", str(tmp_path), "--target-branch", "main"]) == 2


def test_invalid_report_fails_closed(tmp_path):
    _write_reports(tmp_path)
    (tmp_path / "bandit.json").write_text(json.dumps({"unexpected": True}))
    assert main(["--reports-dir", str(tmp_path), "--target-branch", "test"]) == 2


def test_invalid_threshold(tmp_path):
    with pytest.raises(SystemExit):
        main(
            ["--reports-dir", str(tmp_path), "--target-branch", "main", "--critical-threshold", "0"]
        )


def test_summary_file(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    reports = tmp_path / "r"
    reports.mkdir()
    _write_reports(reports)
    out = tmp_path / "security-gate.md"
    args = ["--reports-dir", str(reports), "--target-branch", "main", "--summary-file", str(out)]
    assert main(args) == 0
    assert "APROVADO" in out.read_text()
