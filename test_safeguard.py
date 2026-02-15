"""Tests for SafeGuard security scanner."""
import os
import tempfile
from safeguard import scan_line, scan_file, scan_directory, format_report, Finding


def test_detects_hardcoded_secret():
    findings = scan_line('password = "super_secret_123"', 1, "test.py")
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert "SG001" in findings[0].rule


def test_detects_sql_injection():
    line = 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'
    findings = scan_line(line, 5, "app.py")
    assert len(findings) >= 1
    assert any(f.severity == "CRITICAL" for f in findings)
    assert any("SG002" in f.rule for f in findings)


def test_detects_eval():
    findings = scan_line("result = eval(user_input)", 10, "app.py")
    assert len(findings) == 1
    assert "SG003" in findings[0].rule


def test_detects_os_system():
    findings = scan_line('os.system("rm -rf /")', 3, "danger.py")
    assert len(findings) == 1
    assert findings[0].severity == "CRITICAL"
    assert "SG004" in findings[0].rule


def test_detects_debug_mode():
    findings = scan_line("app.run(debug=True)", 42, "server.py")
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_clean_code_no_findings():
    findings = scan_line("x = 1 + 2", 1, "clean.py")
    assert len(findings) == 0


def test_scan_file_integration():
    code = 'api_key = "AKIAIOSFODNN7EXAMPLE"\nname = "alice"\neval(data)\n'
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(code)
        path = f.name
    try:
        findings = scan_file(path)
        assert len(findings) == 2
        rules = {f.rule for f in findings}
        assert any("SG001" in r for r in rules)
        assert any("SG003" in r for r in rules)
    finally:
        os.unlink(path)


def test_scan_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = os.path.join(tmpdir, "vuln.py")
        with open(filepath, "w") as f:
            f.write('password = "hunter2_pass"\n')
        findings = scan_directory(tmpdir)
        assert len(findings) == 1
        assert findings[0].line == 1


def test_format_report_clean():
    report = format_report([])
    assert "No security issues" in report


def test_format_report_with_findings():
    findings = [
        Finding("t.py", 1, "SG001: hardcoded-secret", "HIGH", "Secret", 'pw="x"'),
    ]
    report = format_report(findings)
    assert "1 issue" in report
    assert "HIGH" in report
    assert "Summary" in report
