# 🛡️ SafeGuard — Real-Time Code Security Scanner

A lightweight, zero-dependency CLI tool that scans your source code for common security vulnerabilities — hardcoded secrets, SQL injection, shell injection, dangerous functions, and more.

## Installation

```bash
git clone https://github.com/openks/safeguard.git
cd safeguard
pip install -r requirements.txt
```

## Usage

### Scan a single file
```bash
python main.py app.py
```

### Scan an entire directory
```bash
python main.py ./src
```

### CI mode (exit code 1 on findings)
```bash
python main.py ./src --exit-code
```

### Filter by file extension
```bash
python main.py ./src --ext .py .js
```

## Detection Rules

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SG001 | hardcoded-secret | HIGH | Passwords, API keys, tokens in source |
| SG002 | sql-injection | CRITICAL | String interpolation in SQL queries |
| SG003 | dangerous-function | HIGH | Use of `eval()` or `exec()` |
| SG004 | shell-injection | CRITICAL | `os.system()` or `shell=True` |
| SG005 | debug-enabled | MEDIUM | Debug mode left enabled |
| SG006 | insecure-deserialization | HIGH | Unsafe `pickle.load` / `yaml.load` |

## Running Tests

```bash
pytest test_safeguard.py -v
```

## Contributing

Contributions welcome! Please open an issue first to discuss new rules or features.

## License

MIT
