#!/usr/bin/env python3
"""SafeGuard CLI — scan files or directories for security issues."""
import argparse
import sys
import os
from safeguard import scan_file, scan_directory, format_report


def main():
    parser = argparse.ArgumentParser(
        prog="safeguard",
        description="🛡️  SafeGuard — Real-Time Code Security Scanner",
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--ext", nargs="*", help="File extensions to include (e.g. .py .js)")
    parser.add_argument(
        "--exit-code", action="store_true",
        help="Exit with code 1 if any issues are found (useful for CI)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"Error: '{args.target}' not found")
        sys.exit(2)

    extensions = set(args.ext) if args.ext else None

    if os.path.isfile(args.target):
        findings = scan_file(args.target)
    else:
        findings = scan_directory(args.target, extensions=extensions)

    print(format_report(findings))

    if args.exit_code and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
